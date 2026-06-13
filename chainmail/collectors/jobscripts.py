"""Analyse root-run job scripts for hijackable includes.

Many privesc paths are not "write the watched file" but "the root-run command
is a script that pulls in another file you control". The classic case is HTB
"Connected": a root incron helper (``/usr/sbin/sysadmin_ha``) does
``require_once($i)`` on a PHP path that does not exist, under a directory the
``asterisk`` user can write -- so you create the missing include with a
malicious class and fire the trigger.

This collector reads the script behind each root-run scheduled/incron job and
finds includes/requires/sources whose target is either already writable or
*missing with a writable ancestor directory* (i.e. creatable). It also extracts
the ``new Class()->method()`` invocation so the builder can emit a precise PoC.

Read-only: it only ``cat``s scripts and ``test``s paths.
"""
from __future__ import annotations

import re
import shlex

from chainmail.collectors.base import Collector
from chainmail.ssh import SSHTarget
from chainmail.facts import Facts, HijackableInclude

MAX_SCRIPT_BYTES = 65536


# -- standalone parsers (unit-testable, no SSH) ----------------------------
def detect_language(script_path: str, content: str) -> str | None:
    head = content[:200]
    if re.search(r"^#!.*\bphp\b", head) or "<?php" in content or script_path.endswith(".php"):
        return "php"
    if re.search(r"^#!.*\b(bash|sh|dash|ksh)\b", head) or script_path.endswith((".sh",)):
        return "shell"
    if re.search(r"^#!.*\bperl\b", head) or script_path.endswith((".pl", ".pm")):
        return "perl"
    return None


def extract_includes(content: str, language: str) -> list[str]:
    """Return absolute include/require/source targets we can resolve."""
    paths: list[str] = []
    if language == "php":
        # direct: include/require[_once] ( "..." )
        for m in re.finditer(
            r"(?:include|require)(?:_once)?\s*\(?\s*[\"']([^\"']+)[\"']", content):
            paths.append(m.group(1))
        # variable: $i = "..."; ... require_once($i);
        assigns = dict(re.findall(r"\$(\w+)\s*=\s*[\"']([^\"']+)[\"']", content))
        for m in re.finditer(
            r"(?:include|require)(?:_once)?\s*\(?\s*\$(\w+)", content):
            if m.group(1) in assigns:
                paths.append(assigns[m.group(1)])
    elif language == "shell":
        for m in re.finditer(r"(?m)^\s*(?:\.|source)\s+([^\s;]+)", content):
            paths.append(m.group(1))
    elif language == "perl":
        for m in re.finditer(r"(?:require|do)\s+[\"']([^\"']+)[\"']", content):
            paths.append(m.group(1))
    # only absolute, deduplicated; drop obvious dynamic fragments
    seen, out = set(), []
    for p in paths:
        if p.startswith("/") and "$" not in p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def extract_invoke_hint(content: str, language: str) -> str:
    """Best-effort 'Class::method' the script calls, for PoC stub generation."""
    if language != "php":
        return ""
    cls = re.search(r"new\s+(\w+)", content)
    meth = re.search(r"->\s*(\w+)\s*\(", content)
    if cls and meth:
        return f"{cls.group(1)}::{meth.group(1)}"
    if cls:
        return cls.group(1)
    return ""


# -- collector -------------------------------------------------------------
class JobScriptsCollector(Collector):
    name = "jobscripts"

    def collect(self, target: SSHTarget, facts: Facts) -> None:
        me = facts.current_user
        # script_path -> list of jobs that run it (to attach trigger metadata)
        for job in facts.scheduled_jobs:
            owner = job.owner if job.owner not in ("", "ALL") else "root"
            if owner == me:
                continue                      # only scripts run as someone else
            script = self._script_path(job.command)
            if not script:
                continue
            content = self._read(target, script)
            if not content:
                continue
            lang = detect_language(script, content)
            if not lang:
                continue
            includes = extract_includes(content, lang)
            if not includes:
                continue
            hint = extract_invoke_hint(content, lang)
            states = self._classify(target, includes)
            for inc, (state, anchor, owner_g) in states.items():
                via = self._writable_via(facts, owner_g)
                facts.hijackable_includes.append(HijackableInclude(
                    script_path=script, include_path=inc, language=lang,
                    state=state, writable_via=via, anchor=anchor, owner=owner,
                    job_kind=job.kind, job_source=job.source,
                    trigger_path=job.trigger_path, invoke_hint=hint,
                ))
        self.log(f"{len(facts.hijackable_includes)} hijackable include(s)")

    @staticmethod
    def _script_path(command: str) -> str:
        if not command.strip():
            return ""
        m = re.match(r"^\S*/?(?:sh|bash|dash)\s+-c\s+['\"]?(\S+)", command)
        tok = m.group(1) if m else command.strip().split()[0]
        return tok if tok.startswith("/") else ""

    def _read(self, target: SSHTarget, path: str) -> str:
        res = target.run(f"head -c {MAX_SCRIPT_BYTES} {shlex.quote(path)} 2>/dev/null")
        return res.stdout if res.ok else ""

    def _classify(self, target: SSHTarget, paths: list[str]) -> dict:
        """Map include path -> (state, anchor, 'owner|group'). Skips inert ones."""
        lines = []
        for p in paths:
            qp = shlex.quote(p)
            lines.append(
                f'if [ -e {qp} ]; then [ -w {qp} ] && echo "W|{p}|{p}|$(stat -c \'%U|%G\' {qp})"; '
                f'else a={qp}; while [ ! -e "$a" ] && [ "$a" != "/" ]; do a=$(dirname "$a"); done; '
                f'if [ -d "$a" ] && [ -w "$a" ]; then echo "M|{p}|$a|$(stat -c \'%U|%G\' "$a")"; fi; fi'
            )
        res = target.run("\n".join(lines), timeout=30)
        out: dict = {}
        for line in res.stdout.splitlines():
            parts = line.split("|")
            if len(parts) < 5:
                continue
            kind, path, anchor, owner, group = parts[0], parts[1], parts[2], parts[3], parts[4]
            state = "writable" if kind == "W" else "missing-writable-parent"
            out[path] = (state, anchor, f"{owner}|{group}")
        return out

    @staticmethod
    def _writable_via(facts: Facts, owner_group: str) -> str:
        owner, _, group = owner_group.partition("|")
        if owner and owner == facts.current_user:
            return "user"
        if group and group in facts.current_groups:
            return f"group:{group}"
        return "world"

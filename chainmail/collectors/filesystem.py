"""Filesystem writability collection, focused on paths that matter.

Rather than a blanket ``find / -writable`` (slow and noisy), this collector
tests writability only for paths that are *interesting*: $PATH directories,
the binaries/scripts referenced by scheduled jobs, and a curated set of
sensitive system files. The join "writable AND used by root" is what turns a
benign permission into an escalation edge in the graph.
"""
from __future__ import annotations

import re
import shlex

from chainmail.collectors.base import Collector
from chainmail.ssh import SSHTarget
from chainmail.facts import Facts, WritableTarget


SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/crontab",
]
SENSITIVE_DIRS = [
    "/etc/sudoers.d",
    "/etc/cron.d",
    "/etc/ld.so.conf.d",
]


class FilesystemCollector(Collector):
    name = "filesystem"

    def collect(self, target: SSHTarget, facts: Facts) -> None:
        self._path_dirs(target, facts)
        candidates = self._candidate_paths(facts)
        self._test_writable(target, facts, candidates)

    def _path_dirs(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run("echo \"$PATH\"")
        facts.path_dirs = [d for d in res.stdout.strip().split(":") if d]
        for d in facts.path_dirs:
            chk = target.run(f"[ -d {shlex.quote(d)} ] && [ -w {shlex.quote(d)} ] && echo W")
            if chk.stdout.strip() == "W":
                facts.writable_path_dirs.append(d)
        self.log(f"$PATH has {len(facts.path_dirs)} dirs, "
                 f"{len(facts.writable_path_dirs)} writable")

    def _candidate_paths(self, facts: Facts) -> dict[str, str]:
        """Map candidate path -> reason note (deduplicated)."""
        cands: dict[str, str] = {}
        for f in SENSITIVE_FILES:
            cands.setdefault(f, "sensitive system file")
        for job in facts.scheduled_jobs:
            for p in self._paths_in_command(job.command):
                cands.setdefault(p, f"executed by {job.owner} via {job.kind} ({job.source})")
            # For event-triggered jobs (incron), the watched path is the real
            # primitive: writing it fires the command. Test it (and its parent).
            if job.trigger_path:
                cands.setdefault(
                    job.trigger_path,
                    f"watched by {job.owner}'s {job.kind} rule ({job.source})",
                )
        # SUID/cap binaries that live in writable dirs are also interesting;
        # the binary path itself plus its directory.
        return cands

    @staticmethod
    def _paths_in_command(command: str) -> list[str]:
        paths: list[str] = []
        # absolute paths anywhere in the command line
        paths += re.findall(r"(/[\w./\-]+)", command)
        # first token if relative (PATH-resolved binary)
        first = command.strip().split()[0] if command.strip() else ""
        if first and not first.startswith("/"):
            paths.append(first)  # marker for PATH-hijack analysis
        return list(dict.fromkeys(paths))

    def _test_writable(self, target: SSHTarget, facts: Facts,
                       candidates: dict[str, str]) -> None:
        if not candidates:
            return
        # Build one shell script that tests each path and its parent dir.
        lines = []
        for p in candidates:
            qp = shlex.quote(p)
            lines.append(
                f"if [ -w {qp} ]; then echo \"W|{p}|$(stat -c '%U|%G|%A' {qp} 2>/dev/null)\"; fi"
            )
            # parent dir writable => can replace the file even if file itself isn't writable
            parent = p.rsplit("/", 1)[0] or "/"
            qparent = shlex.quote(parent)
            lines.append(
                f"if [ -w {qparent} ]; then echo \"D|{parent}|$(stat -c '%U|%G|%A' {qparent} 2>/dev/null)\"; fi"
            )
        for d in SENSITIVE_DIRS:
            qd = shlex.quote(d)
            lines.append(f"if [ -w {qd} ]; then echo \"D|{d}|$(stat -c '%U|%G|%A' {qd} 2>/dev/null)\"; fi")

        script = "\n".join(lines)
        res = target.run(script, timeout=45)
        facts.raw["writable_tests"] = res.stdout
        seen: set[str] = set()
        for line in res.stdout.splitlines():
            parts = line.split("|")
            if len(parts) < 2:
                continue
            kind, path = parts[0], parts[1]
            owner = parts[2] if len(parts) > 2 else ""
            group = parts[3] if len(parts) > 3 else ""
            via = self._writable_via(facts, owner, group)
            note = candidates.get(path, "")
            if kind == "D" and path not in candidates:
                note = "writable parent directory"
            key = f"{kind}:{path}"
            if key in seen:
                continue
            seen.add(key)
            facts.writable_targets.append(
                WritableTarget(path=path, writable_via=via,
                               note=(note + (" [parent dir writable]" if kind == "D" else "")).strip())
            )
        self.log(f"{len(facts.writable_targets)} writable target(s) of interest")

    @staticmethod
    def _writable_via(facts: Facts, owner: str, group: str) -> str:
        if owner and owner == facts.current_user:
            return "user"
        if group and group in facts.current_groups:
            return f"group:{group}"
        return "world"

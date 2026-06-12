"""Cron, systemd service, and timer collection.

These are the richest source of multi-step chains: a job runs as root (or
another user) and executes a path. If the current principal can influence that
path -- because it, its directory, or a binary it calls on $PATH is writable --
an escalation edge exists. This collector records the jobs; the graph builder
joins them against writability facts.
"""
from __future__ import annotations

import re

from chainmail.collectors.base import Collector
from chainmail.ssh import SSHTarget
from chainmail.facts import Facts, ScheduledJob


CRON_SOURCES = [
    "/etc/crontab",
    "/etc/cron.d",
]
CRON_DROPIN_DIRS = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
                    "/etc/cron.weekly", "/etc/cron.monthly"]


class ScheduledCollector(Collector):
    name = "scheduled"

    def collect(self, target: SSHTarget, facts: Facts) -> None:
        self._system_crontab(target, facts)
        self._cron_dropins(target, facts)
        self._user_crontabs(target, facts)
        self._systemd(target, facts)
        self.log(f"collected {len(facts.scheduled_jobs)} scheduled job(s)")

    # -- cron --------------------------------------------------------------
    def _system_crontab(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run("cat /etc/crontab 2>/dev/null")
        facts.raw["crontab"] = res.stdout
        for line in res.stdout.splitlines():
            job = self._parse_system_cron_line(line, source="/etc/crontab")
            if job:
                facts.scheduled_jobs.append(job)

    def _cron_dropins(self, target: SSHTarget, facts: Facts) -> None:
        for d in CRON_DROPIN_DIRS:
            res = target.run(
                f"for f in {d}/*; do [ -f \"$f\" ] && echo \"### $f\" && cat \"$f\"; done 2>/dev/null"
            )
            if not res.stdout.strip():
                continue
            current = d
            for line in res.stdout.splitlines():
                if line.startswith("### "):
                    current = line[4:].strip()
                    continue
                if d == "/etc/cron.d":
                    job = self._parse_system_cron_line(line, source=current)
                else:
                    # cron.daily etc: scripts run as root, the file *is* the command
                    job = None
                    if line.strip() and not line.startswith("#"):
                        continue
                if job:
                    facts.scheduled_jobs.append(job)
            # cron.daily/weekly: each file is a root-run script
            if d != "/etc/cron.d":
                listing = target.run(f"ls -1 {d} 2>/dev/null")
                for name in listing.stdout.split():
                    facts.scheduled_jobs.append(
                        ScheduledJob(source=f"{d}/{name}", owner="root",
                                     command=f"{d}/{name}", kind="cron")
                    )

    def _user_crontabs(self, target: SSHTarget, facts: Facts) -> None:
        # Readable only if we have rights; best-effort. Own crontab via `crontab -l`.
        res = target.run("crontab -l 2>/dev/null")
        for line in res.stdout.splitlines():
            job = self._parse_user_cron_line(line, owner=facts.current_user,
                                             source=f"crontab:{facts.current_user}")
            if job:
                facts.scheduled_jobs.append(job)
        # Spool dir may be group/world readable on misconfigured hosts.
        spool = target.run(
            "for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do "
            "[ -f \"$f\" ] && echo \"### $(basename $f)\" && cat \"$f\"; done 2>/dev/null"
        )
        owner = facts.current_user
        for line in spool.stdout.splitlines():
            if line.startswith("### "):
                owner = line[4:].strip()
                continue
            job = self._parse_user_cron_line(line, owner=owner,
                                             source=f"/var/spool/cron/{owner}")
            if job:
                facts.scheduled_jobs.append(job)

    @staticmethod
    def _parse_system_cron_line(line: str, source: str) -> ScheduledJob | None:
        line = line.strip()
        if not line or line.startswith("#") or "=" in line.split()[0:1] and "*" not in line:
            # skip env assignments like PATH=...
            if re.match(r"^[A-Z_]+\s*=", line):
                return None
        if not line or line.startswith("#"):
            return None
        if re.match(r"^[A-Z_]+\s*=", line):
            return None
        # m h dom mon dow user command...
        m = re.match(r"^(\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(\S+)\s+(.+)$", line)
        if not m:
            return None
        user, command = m.group(2), m.group(3).strip()
        return ScheduledJob(source=source, owner=user, command=command, kind="cron")

    @staticmethod
    def _parse_user_cron_line(line: str, owner: str, source: str) -> ScheduledJob | None:
        line = line.strip()
        if not line or line.startswith("#") or re.match(r"^[A-Z_]+\s*=", line):
            return None
        m = re.match(r"^(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$", line)
        if not m:
            return None
        return ScheduledJob(source=source, owner=owner, command=m.group(2).strip(), kind="cron")

    # -- systemd -----------------------------------------------------------
    def _systemd(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run(
            "systemctl show '*.service' "
            "--property=Id,ExecStart,FragmentPath,User 2>/dev/null",
            timeout=45,
        )
        facts.raw["systemd"] = res.stdout
        block: dict[str, str] = {}

        def flush(b: dict[str, str]) -> None:
            if not b.get("ExecStart"):
                return
            exec_line = self._extract_execstart_path(b.get("ExecStart", ""))
            if not exec_line:
                return
            facts.scheduled_jobs.append(
                ScheduledJob(
                    source=b.get("FragmentPath") or b.get("Id", "?"),
                    owner=b.get("User") or "root",
                    command=exec_line,
                    kind="systemd",
                )
            )

        for line in res.stdout.splitlines():
            if not line.strip():
                flush(block)
                block = {}
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                block[k.strip()] = v.strip()
        flush(block)

    @staticmethod
    def _extract_execstart_path(execstart: str) -> str:
        # ExecStart={ path=/usr/bin/foo ; argv[]=/usr/bin/foo --x ; ... }
        m = re.search(r"path=(\S+)", execstart)
        if m:
            return m.group(1)
        m = re.search(r"argv\[\]=([^;]+)", execstart)
        if m:
            return m.group(1).strip()
        return execstart.strip()

"""incron (inotify-cron) rule collection.

incron runs commands in response to *filesystem events* rather than time. A
rule line is:

    <watched_path>  <event_mask>  <command...>

The escalation primitive differs from cron: the dangerous, attacker-influenced
input is the **watched path**, not the command's script. If an unprivileged
principal can write the watched path, they can fire a root-run command (and
usually inject into the file it acts on). HTB "Connected" is the canonical
example -- a root incron rule watching a writable DAHDI/asterisk config path.

Rule sources and the identity their commands run as:
  * /etc/incron.d/*        -> system tables, run as **root**
  * /var/spool/incron/<u>  -> user <u>'s table, run as <u>
  * `incrontab -l`         -> the current user's own table
"""
from __future__ import annotations

from chainmail.collectors.base import Collector
from chainmail.ssh import SSHTarget
from chainmail.facts import Facts, ScheduledJob


class IncronCollector(Collector):
    name = "incron"

    def collect(self, target: SSHTarget, facts: Facts) -> None:
        # Cheap presence check; if incron isn't installed there's nothing to do
        # but we still try the config paths in case the binary is elsewhere.
        present = target.run("command -v incrond incrontab 2>/dev/null")
        self.log(f"incron binaries: {present.stdout.strip() or 'none found'}")

        self._system_tables(target, facts)
        self._user_tables(target, facts)
        self._own_table(target, facts)
        added = [j for j in facts.scheduled_jobs if j.kind == "incron"]
        self.log(f"collected {len(added)} incron rule(s)")

    def _system_tables(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run(
            "for f in /etc/incron.d/*; do [ -f \"$f\" ] && echo \"### $f\" "
            "&& cat \"$f\"; done 2>/dev/null"
        )
        facts.raw["incron_system"] = res.stdout
        self._ingest(res.stdout, facts, owner="root", marker="### ",
                     default_source="/etc/incron.d")

    def _user_tables(self, target: SSHTarget, facts: Facts) -> None:
        # Spool files are named after the owning user; commands run as that user.
        res = target.run(
            "for f in /var/spool/incron/*; do [ -f \"$f\" ] && "
            "echo \"### $(basename \"$f\")\" && cat \"$f\"; done 2>/dev/null"
        )
        facts.raw["incron_spool"] = res.stdout
        self._ingest(res.stdout, facts, owner=None, marker="### ",
                     default_source="/var/spool/incron")

    def _own_table(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run("incrontab -l 2>/dev/null")
        if not res.stdout.strip():
            return
        for line in res.stdout.splitlines():
            job = self._parse_rule(line, owner=facts.current_user or "root",
                                   source=f"incrontab:{facts.current_user}")
            if job:
                facts.scheduled_jobs.append(job)

    def _ingest(self, text: str, facts: Facts, owner: str | None,
                marker: str, default_source: str) -> None:
        """Parse a concatenated dump where ``marker`` lines separate files.

        When ``owner`` is None, the marker value is itself the owning user
        (spool tables); otherwise ``owner`` is fixed (e.g. root for /etc).
        """
        source = default_source
        cur_owner = owner or "root"
        for line in text.splitlines():
            if line.startswith(marker):
                tag = line[len(marker):].strip()
                if owner is None:                 # spool: tag is the username
                    cur_owner = tag
                    source = f"{default_source}/{tag}"
                else:                              # /etc/incron.d: tag is a path
                    source = tag
                    cur_owner = owner
                continue
            job = self._parse_rule(line, owner=cur_owner, source=source)
            if job:
                facts.scheduled_jobs.append(job)

    @staticmethod
    def _parse_rule(line: str, owner: str, source: str) -> ScheduledJob | None:
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        parts = line.split(None, 2)             # path, mask, command
        if len(parts) < 3:
            return None
        watched_path, _mask, command = parts[0], parts[1], parts[2]
        return ScheduledJob(
            source=source, owner=owner, command=command.strip(),
            kind="incron", trigger_path=watched_path,
        )

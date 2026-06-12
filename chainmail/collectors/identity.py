"""Identity, account inventory, and sudo-rights collection."""
from __future__ import annotations

import re

from chainmail.collectors.base import Collector
from chainmail.ssh import SSHTarget
from chainmail.facts import Facts, User, Group, SudoRule


class IdentityCollector(Collector):
    name = "identity"

    def collect(self, target: SSHTarget, facts: Facts) -> None:
        self._host_info(target, facts)
        self._current_identity(target, facts)
        self._passwd(target, facts)
        self._group_db(target, facts)
        self._sudo(target, facts)

    def _host_info(self, target: SSHTarget, facts: Facts) -> None:
        facts.hostname = target.run("hostname").stdout.strip()
        facts.kernel = target.run("uname -r").stdout.strip()
        facts.arch = target.run("uname -m").stdout.strip()
        rel = target.run("grep -E '^(PRETTY_NAME)=' /etc/os-release 2>/dev/null")
        m = re.search(r'PRETTY_NAME="?([^"\n]+)"?', rel.stdout)
        facts.os_release = m.group(1).strip() if m else ""
        self.log(f"{facts.hostname} {facts.os_release} kernel {facts.kernel}")

    def _current_identity(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run("id")
        facts.raw["id"] = res.stdout
        # uid=1000(bob) gid=1000(bob) groups=1000(bob),27(sudo),998(docker)
        m = re.search(r"uid=(\d+)\(([^)]+)\)", res.stdout)
        if m:
            facts.current_uid = int(m.group(1))
            facts.current_user = m.group(2)
        m = re.search(r"gid=(\d+)", res.stdout)
        if m:
            facts.current_gid = int(m.group(1))
        gm = re.search(r"groups=([^\n]+)", res.stdout)
        if gm:
            facts.current_groups = re.findall(r"\d+\(([^)]+)\)", gm.group(1))
        self.log(f"current user {facts.current_user} groups {facts.current_groups}")

    def _passwd(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run("cat /etc/passwd")
        facts.raw["passwd"] = res.stdout
        for line in res.stdout.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            try:
                facts.users.append(
                    User(
                        name=parts[0],
                        uid=int(parts[2]),
                        gid=int(parts[3]),
                        home=parts[5],
                        shell=parts[6],
                    )
                )
            except ValueError:
                continue

    def _group_db(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run("cat /etc/group")
        facts.raw["group"] = res.stdout
        for line in res.stdout.splitlines():
            parts = line.split(":")
            if len(parts) < 4:
                continue
            try:
                members = [m for m in parts[3].split(",") if m]
                facts.groups.append(
                    Group(name=parts[0], gid=int(parts[2]), members=members)
                )
            except ValueError:
                continue

    def _sudo(self, target: SSHTarget, facts: Facts) -> None:
        # -n => never prompt. If a password is required, we record the raw
        # output but do not attempt to authenticate. Many lab/test creds are
        # known to the operator who can re-run `sudo -l` interactively.
        res = target.run("sudo -n -l 2>/dev/null")
        facts.sudo_l_raw = res.stdout
        facts.raw["sudo_l"] = res.out
        facts.sudo_rules = self._parse_sudo_l(res.stdout)
        self.log(f"parsed {len(facts.sudo_rules)} sudo rule(s)")

    @staticmethod
    def _parse_sudo_l(text: str) -> list[SudoRule]:
        """Parse the 'may run the following commands' block of `sudo -l`.

        Example lines:
            (root) NOPASSWD: /usr/bin/find
            (ALL : ALL) ALL
            (svc) NOPASSWD: /opt/app/run.sh
        """
        rules: list[SudoRule] = []
        for raw in text.splitlines():
            line = raw.strip()
            m = re.match(r"\(([^)]*)\)\s*(.*)$", line)
            if not m:
                continue
            runas_part, rest = m.group(1), m.group(2).strip()
            runas_users = [u.strip() for u in re.split(r"[:,]", runas_part) if u.strip()]
            # normalise "ALL" runas to root for analysis purposes
            runas_users = ["root" if u == "ALL" else u for u in runas_users]

            nopasswd = False
            tags = re.findall(r"(NOPASSWD|PASSWD|SETENV|NOEXEC):", rest)
            nopasswd = "NOPASSWD" in tags
            cmd_part = re.sub(r"\b(NOPASSWD|PASSWD|SETENV|NOEXEC):\s*", "", rest)
            commands = [c.strip() for c in cmd_part.split(",") if c.strip()]
            if not commands:
                continue
            rules.append(
                SudoRule(runas_users=runas_users or ["root"], commands=commands, nopasswd=nopasswd)
            )
        return rules

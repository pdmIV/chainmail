"""SUID/SGID binary and file-capability collection."""
from __future__ import annotations

import re

from chainmail.collectors.base import Collector
from chainmail.ssh import SSHTarget
from chainmail.facts import Facts, SuidBinary, CapabilityFile


class SuidCapsCollector(Collector):
    name = "suid-caps"

    def collect(self, target: SSHTarget, facts: Facts) -> None:
        self._suid(target, facts)
        self._caps(target, facts)

    def _suid(self, target: SSHTarget, facts: Facts) -> None:
        # -perm -4000 = SUID, -2000 = SGID. We list with owner + mode so the
        # graph can attribute the binary to the principal it runs as.
        cmd = (
            "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f "
            "-printf '%m %u %p\\n' 2>/dev/null"
        )
        res = target.run(cmd, timeout=60)
        facts.raw["suid"] = res.stdout
        for line in res.stdout.splitlines():
            parts = line.split(None, 2)
            if len(parts) != 3:
                continue
            mode, owner, path = parts
            facts.suid_binaries.append(SuidBinary(path=path, owner=owner, mode=mode))
        self.log(f"found {len(facts.suid_binaries)} suid/sgid binaries")

    def _caps(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run("getcap -r / 2>/dev/null", timeout=60)
        facts.raw["getcap"] = res.stdout
        for line in res.stdout.splitlines():
            # /usr/bin/python3.10 cap_setuid,cap_net_bind_service+ep
            m = re.match(r"(\S+)\s+(.+)$", line.strip())
            if not m:
                continue
            facts.capabilities.append(
                CapabilityFile(path=m.group(1), caps=m.group(2).strip())
            )
        self.log(f"found {len(facts.capabilities)} file capabilities")

"""Offline source: the curated kernel-LPE database (no network)."""
from __future__ import annotations

from chainmail.facts import Facts
from chainmail.knowledge import kernel_cve
from chainmail.vulnsources.base import VulnerabilitySource, VulnFinding


class OfflineSource(VulnerabilitySource):
    name = "offline-db"

    def query(self, facts: Facts) -> list[VulnFinding]:
        findings = []
        for f in kernel_cve.match_all(facts):
            findings.append(VulnFinding(
                cve=f.cve, name=f.name, component=f.component, summary=f.summary,
                reference=f.reference, requires=f.requires, severity=f.severity,
                source="offline-db", local_root=True, corroborated=f.corroborated,
            ))
        self.log(f"{len(findings)} curated LPE match(es) for kernel {facts.kernel}")
        return findings

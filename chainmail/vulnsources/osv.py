"""OSV.dev source (keyless).

Queries https://api.osv.dev/v1/query per package (and the kernel) for the
host's distro ecosystem. Free, no API key, works immediately -- the default
online source when no Vulners key is configured. OSV returns CVE/advisory ids
but no "wild exploited" signal, so its findings are leads unless they intersect
chainmail's curated local-root set.
"""
from __future__ import annotations

from chainmail.facts import Facts
from chainmail.knowledge import kernel_cve
from chainmail.vulnsources.base import VulnerabilitySource, VulnFinding, post_json

QUERY_URL = "https://api.osv.dev/v1/query"

# distro ID (os-release) -> OSV ecosystem name
ECOSYSTEM = {
    "ubuntu": "Ubuntu",
    "debian": "Debian",
    "alpine": "Alpine",
    "rocky": "Rocky Linux",
    "almalinux": "AlmaLinux",
    "redhat": "Red Hat",
    "rhel": "Red Hat",
}


class OSVSource(VulnerabilitySource):
    name = "osv"

    def query(self, facts: Facts) -> list[VulnFinding]:
        eco = ECOSYSTEM.get(facts.distro_id)
        if not eco:
            self.log(f"no OSV ecosystem mapping for distro '{facts.distro_id}'; skipping")
            return []
        findings: dict[str, VulnFinding] = {}
        # the kernel ('linux' source package) + the collected key packages
        targets = [("linux", _kernel_pkg_version(facts))]
        targets += [(p.name, p.version) for p in facts.packages]
        for name, version in targets:
            if not version:
                continue
            try:
                resp = post_json(QUERY_URL, {
                    "package": {"name": name, "ecosystem": eco},
                    "version": version,
                }, timeout=15.0)
            except Exception as exc:
                self.log(f"query {name} failed: {exc}")
                continue
            for v in resp.get("vulns", []) or []:
                self._add(findings, v, component=_component_for(name))
        self.log(f"{len(findings)} finding(s) from OSV ({eco})")
        return list(findings.values())

    @staticmethod
    def _add(acc: dict, vuln: dict, component: str) -> None:
        ids = [vuln.get("id", "")] + (vuln.get("aliases") or [])
        cve = next((i for i in ids if i.upper().startswith("CVE")), vuln.get("id", ""))
        if not cve:
            return
        cve = cve.upper() if cve.upper().startswith("CVE") else cve
        if cve in acc:
            return
        is_local = cve in kernel_cve.LOCAL_ROOT_CVES
        curated = next((e for e in kernel_cve.CURATED if e.cve == cve), None)
        refs = vuln.get("references") or []
        ref = next((r.get("url", "") for r in refs if r.get("type") in ("ADVISORY", "WEB")), "")
        acc[cve] = VulnFinding(
            cve=cve, name=curated.name if curated else (vuln.get("summary") or cve)[:60],
            component=component,
            summary=curated.summary if curated else (vuln.get("summary") or ""),
            reference=(curated.reference if curated else "") or ref,
            requires=curated.requires if curated else "",
            source="osv", local_root=is_local,
        )


def _kernel_pkg_version(facts: Facts) -> str:
    # OSV wants the distro source-package version. We don't always have it; the
    # uname release (e.g. 5.15.0-91) is a usable approximation for many feeds.
    return facts.kernel.split("-generic")[0] if facts.kernel else ""


def _component_for(name: str) -> str:
    n = name.lower()
    if n == "linux":
        return "kernel"
    for key in ("sudo", "polkit", "glibc", "libc", "dbus", "util-linux", "pam"):
        if key in n:
            return key
    return "pkg"

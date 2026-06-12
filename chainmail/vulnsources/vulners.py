"""Vulners Linux-audit source.

Uses the documented, stable v3 linux-audit endpoint:

    POST https://vulners.com/api/v3/audit/audit/
    { "os": "<id>", "version": "<version_id>",
      "package": ["<name> <version> <arch>", ...], "apiKey": "<key>" }

It maps the host's distro + collected key packages to advisories/CVEs. Where a
returned CVE is in chainmail's curated local-root set it is flagged
``local_root`` (and inherits the curated PoC reference); other CVEs are reported
as leads. Requires a Vulners API key (free community plan).
"""
from __future__ import annotations

from chainmail.facts import Facts
from chainmail.knowledge import kernel_cve
from chainmail.vulnsources.base import VulnerabilitySource, VulnFinding, post_json

AUDIT_URL = "https://vulners.com/api/v3/audit/audit/"


class VulnersSource(VulnerabilitySource):
    name = "vulners"

    def __init__(self, api_key: str | None, verbose: int = 0):
        super().__init__(verbose=verbose)
        self.api_key = api_key

    def query(self, facts: Facts) -> list[VulnFinding]:
        if not self.api_key:
            self.log("no API key; skipping")
            return []
        if facts.pkg_manager not in ("dpkg", "rpm"):
            self.log(f"unsupported pkg manager '{facts.pkg_manager}'; skipping")
            return []
        packages = [p.audit_string() for p in facts.packages]
        if not packages:
            self.log("no packages collected; skipping")
            return []
        payload = {
            "os": facts.distro_id or "unknown",
            "version": facts.distro_version or facts.distro_version.split(".")[0],
            "package": packages,
            "apiKey": self.api_key,
        }
        self.log(f"auditing {len(packages)} packages against vulners "
                 f"({payload['os']} {payload['version']})")
        resp = post_json(AUDIT_URL, payload, timeout=25.0)
        if resp.get("result") != "OK" and "data" not in resp:
            self.log(f"unexpected response: {str(resp)[:200]}")
            return []
        return self._parse(resp.get("data", {}))

    def _parse(self, data: dict) -> list[VulnFinding]:
        findings: dict[str, VulnFinding] = {}

        # data.reasons: list of advisories with cvelist + cvss; richest source
        for reason in data.get("reasons", []) or []:
            cvelist = reason.get("cvelist") or []
            cvss = (reason.get("cvss") or {}).get("score")
            pkg = reason.get("package") or reason.get("packageName") or "pkg"
            ref = reason.get("id") or reason.get("bulletinID") or ""
            for cve in cvelist:
                self._add(findings, cve, component=_component_for(pkg), cvss=cvss,
                          reference=f"vulners:{ref}" if ref else "")

        # data.cvelist / data.vulnerabilities: flat CVE id lists
        for cve in (data.get("cvelist") or data.get("vulnerabilities") or []):
            self._add(findings, cve, component="pkg")

        self.log(f"{len(findings)} CVE(s) from vulners audit")
        return list(findings.values())

    @staticmethod
    def _add(acc: dict, cve: str, component: str, cvss=None, reference: str = "") -> None:
        if not cve or not cve.upper().startswith("CVE"):
            return
        cve = cve.upper()
        is_local = cve in kernel_cve.LOCAL_ROOT_CVES
        curated = next((e for e in kernel_cve.CURATED if e.cve == cve), None)
        f = acc.get(cve)
        if f is None:
            f = VulnFinding(
                cve=cve, name=curated.name if curated else cve, component=component,
                summary=curated.summary if curated else "",
                reference=reference or (curated.reference if curated else ""),
                requires=curated.requires if curated else "",
                source="vulners", local_root=is_local,
                severity=_sev(cvss), cvss=cvss,
            )
            acc[cve] = f
        else:
            if cvss and f.cvss is None:
                f.cvss = cvss
                f.severity = _sev(cvss)
            if reference and not f.reference:
                f.reference = reference


def _component_for(pkg: str) -> str:
    pkg = (pkg or "").lower()
    for key in ("sudo", "polkit", "policykit", "glibc", "libc", "dbus", "util-linux", "pam"):
        if key in pkg:
            return "polkit" if "polkit" in key or "policykit" in key else (
                "glibc" if "libc" in key or "glibc" in key else key)
    if "linux" in pkg or "kernel" in pkg:
        return "kernel"
    return "pkg"


def _sev(cvss) -> str:
    if cvss is None:
        return "unknown"
    try:
        s = float(cvss)
    except (TypeError, ValueError):
        return "unknown"
    if s >= 9:
        return "critical"
    if s >= 7:
        return "high"
    if s >= 4:
        return "medium"
    return "low"

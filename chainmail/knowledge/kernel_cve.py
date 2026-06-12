"""Offline curated database of Linux *local privilege escalation* CVEs.

This is the always-available fallback for the CVE-enrichment layer (no network
required) and also the authoritative "is this CVE actually a local-root vector"
signal used to filter noisy online API results. Every entry here is a
well-known LPE with public proof-of-concept exploits.

chainmail never ships or runs exploit code. Each entry points the operator at
the public PoC (Exploit-DB id / reference) so they can verify by hand on a
system they are authorized to test.

Matching is version-range based and intentionally conservative; distros
routinely backport fixes without bumping the upstream version string, so each
finding carries a ``requires`` caveat telling the operator to confirm the
patch level. Treat findings as *leads to verify*, not proof.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from chainmail.facts import Facts


# --------------------------------------------------------------------------
# version helpers
def kver(kernel: str) -> tuple[int, int, int]:
    """Parse '5.15.0-91-generic' -> (5, 15, 0). Missing parts default to 0."""
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", kernel or "")
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def pkg_ver_tuple(version: str) -> tuple[int, ...]:
    """Loose numeric tuple from a distro version string.

    Strips epoch ('1:') and takes the leading dotted-numeric portion, e.g.
    '1.9.5p2-2ubuntu1' -> (1, 9, 5). Good enough for coarse < comparisons;
    callers should pair results with a 'confirm exact version' caveat.
    """
    v = version.split(":", 1)[-1]              # drop epoch
    head = re.split(r"[-~+ ]", v, 1)[0]
    parts = re.findall(r"\d+", head)
    return tuple(int(p) for p in parts[:4]) if parts else (0,)


def _pkg(facts: Facts, *names: str) -> Optional[str]:
    """Return the version string of the first matching installed package."""
    wanted = set(names)
    for p in facts.packages:
        if p.name in wanted:
            return p.version
    return None


def _has_suid(facts: Facts, basename: str) -> bool:
    return any(b.path.rsplit("/", 1)[-1] == basename for b in facts.suid_binaries)


# --------------------------------------------------------------------------
@dataclass
class KernelCVE:
    cve: str
    name: str
    component: str                       # kernel | sudo | polkit | glibc | ...
    summary: str
    reference: str                       # public PoC / Exploit-DB reference
    match: Callable[[Facts], bool]
    requires: str = ""
    severity: str = "high"
    # optional confidence bump predicate (e.g. relevant SUID present)
    corroborate: Optional[Callable[[Facts], bool]] = None


def _between_kernel(lo: tuple, hi: tuple) -> Callable[[Facts], bool]:
    return lambda f: lo <= kver(f.kernel) < hi


CURATED: list[KernelCVE] = [
    KernelCVE(
        cve="CVE-2016-5195", name="Dirty COW", component="kernel",
        summary="Race in copy-on-write lets you write read-only memory -> root.",
        reference="Exploit-DB 40611 / dirtycow.ninja",
        match=_between_kernel((2, 6, 22), (4, 8, 3)),
        requires="confirm distro didn't backport the fix",
    ),
    KernelCVE(
        cve="CVE-2022-0847", name="Dirty Pipe", component="kernel",
        summary="Uninitialized pipe_buffer flags let you overwrite read-only files -> root.",
        reference="Exploit-DB 50808 / dirtypipe.com",
        match=_between_kernel((5, 8, 0), (5, 16, 11)),
        requires="patched in 5.16.11/5.15.25/5.10.102; confirm backport level",
    ),
    KernelCVE(
        cve="CVE-2023-0386", name="OverlayFS uid mapping", component="kernel",
        summary="OverlayFS copy-up uid mishandling -> setuid root binary.",
        reference="GitHub xkaneiki/CVE-2023-0386",
        match=_between_kernel((5, 11, 0), (6, 2, 0)),
        requires="needs unprivileged user namespaces enabled",
    ),
    KernelCVE(
        cve="CVE-2023-32233", name="nf_tables UAF", component="kernel",
        summary="Use-after-free in netfilter nf_tables -> kernel code exec -> root.",
        reference="GitHub Liuk7071/CVE-2023-32233",
        match=_between_kernel((5, 0, 0), (6, 4, 0)),
        requires="needs unprivileged user namespaces; confirm backport",
    ),
    KernelCVE(
        cve="CVE-2022-32250", name="nf_tables OOB", component="kernel",
        summary="netfilter nf_tables out-of-bounds -> root.",
        reference="research.nccgroup.com nf_tables writeup",
        match=_between_kernel((5, 12, 0), (5, 19, 0)),
        requires="confirm backport level",
    ),
    KernelCVE(
        cve="CVE-2021-22555", name="Netfilter heap OOB", component="kernel",
        summary="x_tables heap out-of-bounds write -> root (works in containers).",
        reference="Exploit-DB 50135 / google/security-research",
        match=_between_kernel((2, 6, 19), (5, 12, 0)),
        requires="confirm backport level",
    ),
    KernelCVE(
        cve="CVE-2021-3493", name="OverlayFS (Ubuntu)", component="kernel",
        summary="Ubuntu OverlayFS cap handling -> root.",
        reference="Exploit-DB 49298",
        match=lambda f: f.distro_id == "ubuntu" and kver(f.kernel) < (5, 13, 0),
        requires="Ubuntu-specific; confirm kernel ABI",
    ),
    KernelCVE(
        cve="CVE-2019-13272", name="ptrace TRACEME", component="kernel",
        summary="Mishandled PTRACE_TRACEME parent creds -> root.",
        reference="Exploit-DB 47133",
        match=_between_kernel((4, 10, 0), (5, 1, 17)),
        requires="needs a suitable SUID helper (e.g. pkexec) present",
        corroborate=lambda f: _has_suid(f, "pkexec") or _has_suid(f, "su"),
    ),
    # ---- userland privesc keyed on package version ----
    KernelCVE(
        cve="CVE-2021-3156", name="Baron Samedit (sudo)", component="sudo",
        summary="Heap overflow in sudoedit argv parsing -> root.",
        reference="Exploit-DB 49521 / Qualys advisory",
        match=lambda f: (lambda v: v is not None and (1, 8, 2) <= pkg_ver_tuple(v) < (1, 9, 5))(
            _pkg(f, "sudo")),
        requires="fixed in sudo 1.9.5p2; confirm exact build (epoch/patch suffix)",
        corroborate=lambda f: _has_suid(f, "sudo") or _has_suid(f, "sudoedit"),
    ),
    KernelCVE(
        cve="CVE-2021-4034", name="PwnKit (pkexec)", component="polkit",
        summary="polkit pkexec argv[0] handling -> trivial root.",
        reference="Exploit-DB 50689",
        match=lambda f: _pkg(f, "policykit-1", "polkit", "polkit-1") is not None
                        or _has_suid(f, "pkexec"),
        requires="patched Jan 2022; confirm polkit build date / that pkexec is SUID",
        corroborate=lambda f: _has_suid(f, "pkexec"),
    ),
    KernelCVE(
        cve="CVE-2023-4911", name="Looney Tunables (glibc)", component="glibc",
        summary="glibc ld.so GLIBC_TUNABLES buffer overflow -> root.",
        reference="Exploit-DB 51862 / Qualys advisory",
        match=lambda f: (lambda v: v is not None and (2, 34) <= pkg_ver_tuple(v)[:2] <= (2, 38))(
            _pkg(f, "libc6", "glibc")),
        requires="distro-patched late 2023; confirm exact glibc build",
    ),
]


@dataclass
class CuratedFinding:
    cve: str
    name: str
    component: str
    summary: str
    reference: str
    requires: str
    severity: str
    corroborated: bool = False
    source: str = "offline-db"
    wild_exploited: bool = False
    epss: Optional[float] = None
    extra: dict = field(default_factory=dict)


def match_all(facts: Facts) -> list[CuratedFinding]:
    findings: list[CuratedFinding] = []
    for entry in CURATED:
        try:
            if not entry.match(facts):
                continue
        except Exception:
            continue
        corro = bool(entry.corroborate and entry.corroborate(facts))
        findings.append(CuratedFinding(
            cve=entry.cve, name=entry.name, component=entry.component,
            summary=entry.summary, reference=entry.reference,
            requires=entry.requires, severity=entry.severity, corroborated=corro,
        ))
    return findings


# CVE ids that are known *local root* vectors -- used to filter online API noise
# down to escalation-relevant results.
LOCAL_ROOT_CVES: set[str] = {e.cve for e in CURATED}

"""Vulnerability enrichment sources.

A *vulnerability source* maps collected host facts (kernel, distro, key
packages) to a list of ``VulnFinding`` objects. chainmail combines them:

* the offline curated kernel-LPE database always runs (no network), and is the
  authoritative "this is a local-root vector" signal;
* an optional online source (Vulners audit/host, or keyless OSV) adds freshness
  -- newer CVEs, EPSS scores, and CISA-KEV/AttackerKB "wild exploited" flags.

Network requests go out from the host running chainmail (your Kali box), not
the target. Findings are leads to verify; chainmail prints references to public
PoCs and never runs exploit code.
"""
from __future__ import annotations

import os
import sys

from chainmail.facts import Facts
from chainmail.vulnsources.base import VulnFinding, merge_findings
from chainmail.vulnsources.offline import OfflineSource
from chainmail.vulnsources.osv import OSVSource
from chainmail.vulnsources.vulners import VulnersSource


def select_online_source(name: str, vulners_key: str | None, verbose: int = 0):
    """Pick the online source. ``name`` is auto|vulners|osv|nvd|none."""
    key = vulners_key or os.environ.get("VULNERS_API_KEY")
    if name == "none":
        return None
    if name == "vulners":
        if not key:
            print("[enrich] vulners selected but no API key; set VULNERS_API_KEY "
                  "or --vulners-key. Falling back to OSV.", file=sys.stderr)
            return OSVSource(verbose=verbose)
        return VulnersSource(api_key=key, verbose=verbose)
    if name == "osv":
        return OSVSource(verbose=verbose)
    # auto: prefer Vulners if a key is available, else OSV
    if name in ("auto", ""):
        return VulnersSource(api_key=key, verbose=verbose) if key else OSVSource(verbose=verbose)
    return OSVSource(verbose=verbose)


def enrich(facts: Facts, source_name: str = "auto", vulners_key: str | None = None,
           offline_only: bool = False, verbose: int = 0) -> list[VulnFinding]:
    """Run offline DB + (optionally) one online source, merged & de-duplicated."""
    findings = OfflineSource(verbose=verbose).query(facts)
    if not offline_only:
        online = select_online_source(source_name, vulners_key, verbose=verbose)
        if online is not None:
            try:
                findings = merge_findings(findings, online.query(facts))
            except Exception as exc:                       # network/parse safety
                if verbose:
                    print(f"[enrich] online source {online.name} failed: {exc}",
                          file=sys.stderr)
    return findings


__all__ = ["enrich", "VulnFinding", "OfflineSource", "OSVSource", "VulnersSource"]

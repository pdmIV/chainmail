"""Shared types + a dependency-free JSON HTTP helper for vulnerability sources.

We use urllib from the stdlib rather than requests so chainmail keeps a single
external dependency (paramiko). All network calls are short, timeout-bounded,
and fail soft -- enrichment is additive, so a dead network must never sink a
run.
"""
from __future__ import annotations

import json
import sys
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from chainmail.facts import Facts


@dataclass
class VulnFinding:
    cve: str
    name: str
    component: str                       # kernel | sudo | polkit | glibc | pkg
    summary: str = ""
    reference: str = ""                  # public PoC / advisory
    requires: str = ""
    severity: str = "unknown"            # critical|high|medium|low|unknown
    source: str = ""                     # offline-db | vulners | osv | nvd
    local_root: bool = False             # confirmed local-root vector (curated)
    corroborated: bool = False           # e.g. relevant SUID present on host
    wild_exploited: bool = False         # CISA KEV / AttackerKB
    epss: Optional[float] = None         # exploit prediction score [0,1]
    cvss: Optional[float] = None
    extra: dict = field(default_factory=dict)

    @property
    def confidence(self) -> str:
        if self.local_root and (self.corroborated or self.wild_exploited):
            return "high"
        if self.local_root:
            return "medium"
        if self.wild_exploited:
            return "medium"
        return "lead"


class VulnerabilitySource(ABC):
    name: str = "source"

    def __init__(self, verbose: int = 0):
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[enrich:{self.name}] {msg}", file=sys.stderr)

    @abstractmethod
    def query(self, facts: Facts) -> list[VulnFinding]:
        ...


# --------------------------------------------------------------------------
def post_json(url: str, payload: dict, timeout: float = 20.0,
              headers: Optional[dict] = None) -> dict:
    """POST a JSON body, return parsed JSON. Raises on transport/HTTP error."""
    data = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "User-Agent": "chainmail/0.1"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def merge_findings(a: list[VulnFinding], b: list[VulnFinding]) -> list[VulnFinding]:
    """Merge two finding lists by CVE id, preferring the richer record.

    Offline (local_root=True) entries win on the LPE classification; online
    entries contribute wild_exploited / epss / cvss freshness.
    """
    by_cve: dict[str, VulnFinding] = {}
    for f in a + b:
        key = f.cve or f"{f.component}:{f.name}"
        if key not in by_cve:
            by_cve[key] = f
            continue
        cur = by_cve[key]
        # local_root sticks if either says so
        cur.local_root = cur.local_root or f.local_root
        cur.corroborated = cur.corroborated or f.corroborated
        cur.wild_exploited = cur.wild_exploited or f.wild_exploited
        cur.epss = cur.epss if cur.epss is not None else f.epss
        cur.cvss = cur.cvss if cur.cvss is not None else f.cvss
        if not cur.reference and f.reference:
            cur.reference = f.reference
        if not cur.requires and f.requires:
            cur.requires = f.requires
        if f.source and f.source not in cur.source:
            cur.source = f"{cur.source}+{f.source}" if cur.source else f.source
    return list(by_cve.values())

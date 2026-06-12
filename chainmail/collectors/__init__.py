"""Collector orchestration.

Order matters: identity first (so we know who we are), then suid/caps, then
scheduled jobs, then filesystem -- the filesystem collector consumes the
scheduled jobs to decide which paths are worth writability-testing.
"""
from __future__ import annotations

from chainmail.ssh import SSHTarget
from chainmail.facts import Facts
from chainmail.collectors.identity import IdentityCollector
from chainmail.collectors.suid import SuidCapsCollector
from chainmail.collectors.scheduled import ScheduledCollector
from chainmail.collectors.incron import IncronCollector
from chainmail.collectors.packages import PackagesCollector
from chainmail.collectors.filesystem import FilesystemCollector

COLLECTOR_ORDER = [
    IdentityCollector,
    SuidCapsCollector,
    ScheduledCollector,
    IncronCollector,
    PackagesCollector,
    FilesystemCollector,
]


def run_all_collectors(target: SSHTarget, facts: Facts, verbose: int = 0) -> None:
    for cls in COLLECTOR_ORDER:
        collector = cls(verbose=verbose)
        try:
            collector.collect(target, facts)
        except Exception as exc:  # one bad collector shouldn't sink the run
            if verbose:
                import sys
                print(f"[collect:{collector.name}] error: {exc}", file=sys.stderr)

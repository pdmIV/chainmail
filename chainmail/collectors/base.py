"""Collector base class and registry.

A collector is a read-only enumeration unit: it issues commands over SSH and
mutates a shared ``Facts`` object. Collectors must never run anything that
changes state on the target. Keep each collector focused on one domain so the
graph builder can stay simple.
"""
from __future__ import annotations

import sys
from abc import ABC, abstractmethod

from chainmail.ssh import SSHTarget
from chainmail.facts import Facts


class Collector(ABC):
    name: str = "collector"

    def __init__(self, verbose: int = 0):
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[collect:{self.name}] {msg}", file=sys.stderr)

    @abstractmethod
    def collect(self, target: SSHTarget, facts: Facts) -> None:
        ...

"""Typed containers for facts collected from the target host.

Collectors populate a single ``Facts`` instance. The graph builder consumes
it. Keeping collection (side effects over SSH) separate from analysis (pure
functions over ``Facts``) means the engine can be unit-tested with mock data
and that re-analysis never re-touches the target.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class User:
    name: str
    uid: int
    gid: int
    home: str = ""
    shell: str = ""


@dataclass
class Group:
    name: str
    gid: int
    members: list[str] = field(default_factory=list)


@dataclass
class SudoRule:
    """One entry parsed from ``sudo -l``."""
    runas_users: list[str]          # users we may run as, e.g. ["root"]
    commands: list[str]             # command specs, e.g. ["/usr/bin/find", "ALL"]
    nopasswd: bool = False
    env_keep: list[str] = field(default_factory=list)


@dataclass
class SuidBinary:
    path: str
    owner: str = "root"
    mode: str = ""                  # e.g. "4755"


@dataclass
class CapabilityFile:
    path: str
    caps: str                       # e.g. "cap_setuid+ep"


@dataclass
class ScheduledJob:
    """A cron entry, systemd exec line, or filesystem-event-triggered rule.

    For time-based jobs (cron/systemd) the escalation primitive is writability
    of ``command``'s script. For event-based jobs (incron) it is writability of
    ``trigger_path`` -- the watched file/dir whose modification fires the
    root-run command. ``trigger_path`` is empty for time-based jobs.
    """
    source: str                     # file or unit that defines it
    owner: str                      # user the job runs as (best-effort)
    command: str                    # the command line that gets executed
    kind: str = "cron"              # cron | systemd | timer | incron
    trigger_path: str = ""          # watched path (incron); empty otherwise


@dataclass
class WritableTarget:
    """Something the current principal can write that another principal uses."""
    path: str
    writable_via: str               # "user" or "group:<name>" or "world"
    note: str = ""


@dataclass
class Facts:
    # --- host ---
    hostname: str = ""
    os_release: str = ""
    kernel: str = ""
    arch: str = ""

    # --- current principal ---
    current_user: str = ""
    current_uid: int = -1
    current_gid: int = -1
    current_groups: list[str] = field(default_factory=list)

    # --- inventory ---
    users: list[User] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    sudo_rules: list[SudoRule] = field(default_factory=list)
    sudo_l_raw: str = ""
    suid_binaries: list[SuidBinary] = field(default_factory=list)
    capabilities: list[CapabilityFile] = field(default_factory=list)
    scheduled_jobs: list[ScheduledJob] = field(default_factory=list)
    writable_targets: list[WritableTarget] = field(default_factory=list)
    path_dirs: list[str] = field(default_factory=list)
    writable_path_dirs: list[str] = field(default_factory=list)

    # raw command outputs kept for debugging / -vv
    raw: dict = field(default_factory=dict)

    def user_by_name(self, name: str) -> Optional[User]:
        for u in self.users:
            if u.name == name:
                return u
        return None

    def group_by_name(self, name: str) -> Optional[Group]:
        for g in self.groups:
            if g.name == name:
                return g
        return None

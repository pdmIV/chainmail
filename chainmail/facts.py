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
class Package:
    name: str
    version: str                    # distro package version string
    source: str = ""                # dpkg | rpm | apk
    arch: str = ""                  # e.g. amd64 / x86_64

    def audit_string(self) -> str:
        """Format for the Vulners linux-audit API per package manager."""
        if self.source == "rpm":
            # NVRA, e.g. glibc-common-2.17-157.el7.x86_64
            base = f"{self.name}-{self.version}"
            return f"{base}.{self.arch}" if self.arch else base
        # dpkg / apk: "name version arch"
        return " ".join(p for p in (self.name, self.version, self.arch) if p)


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
class HijackableInclude:
    """A file include/source consumed by a root-run job script that the current
    principal can control -- either it is already writable, or it is missing and
    its nearest existing ancestor directory is writable (so it can be created).

    This is the real "Connected" (HTB) primitive: a root incron helper script
    require_once()s a PHP file under a writable, non-existent path. The watched
    incron file is only the trigger; this is where root code execution comes
    from.
    """
    script_path: str                # the root-run script doing the include
    include_path: str               # the path it includes/requires/sources
    language: str                   # php | shell | perl
    state: str                      # "writable" | "missing-writable-parent"
    writable_via: str               # user | group:<name> | world (of the anchor)
    anchor: str = ""                # existing writable dir (missing case)
    owner: str = "root"             # principal the script runs as
    job_kind: str = ""              # incron | cron | systemd (how it fires)
    job_source: str = ""            # rule/unit that runs the script
    trigger_path: str = ""          # incron watched path to fire it (if any)
    invoke_hint: str = ""           # e.g. "class incron::rootTrigger" for PoC


@dataclass
class Facts:
    # --- host ---
    hostname: str = ""
    os_release: str = ""
    kernel: str = ""
    arch: str = ""
    distro_id: str = ""             # e.g. "ubuntu", "debian", "centos"
    distro_version: str = ""        # e.g. "22.04"
    distro_codename: str = ""       # e.g. "jammy"
    pkg_manager: str = ""           # dpkg | rpm | apk

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
    packages: list[Package] = field(default_factory=list)
    scheduled_jobs: list[ScheduledJob] = field(default_factory=list)
    writable_targets: list[WritableTarget] = field(default_factory=list)
    hijackable_includes: list[HijackableInclude] = field(default_factory=list)
    path_dirs: list[str] = field(default_factory=list)
    writable_path_dirs: list[str] = field(default_factory=list)

    # CVE enrichment findings (chainmail.vulnsources.base.VulnFinding); kept as a
    # loose list here to avoid a circular import with the vulnsources package.
    vuln_findings: list = field(default_factory=list)

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

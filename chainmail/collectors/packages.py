"""Distro identity + targeted package-version collection.

Scope is deliberately narrow (the "kernel + key privesc packages" mode): the
kernel itself plus a curated set of userland components that are the usual
local-root suspects (sudo, polkit/pkexec, glibc/ld.so, dbus, util-linux, PAM,
snapd). This keeps the CVE enrichment focused on things that actually yield
root, and keeps API payloads small and fast.

Collected facts feed two consumers: the offline curated kernel-LPE database and
the live vulnerability-source clients (Vulners/OSV).
"""
from __future__ import annotations

import re

from chainmail.collectors.base import Collector
from chainmail.ssh import SSHTarget
from chainmail.facts import Facts, Package

# Candidate package names across distro families; we query all and keep hits.
KEY_PACKAGES = [
    "sudo",
    "policykit-1", "polkit", "polkit-1",          # PwnKit / pkexec
    "libc6", "glibc", "libc-bin",                 # Looney Tunables / ld.so
    "dbus", "dbus-daemon", "dbus-broker",
    "util-linux", "util-linux-core",              # e.g. su/mount issues
    "libpam-modules", "pam",                      # PAM privesc
    "snapd",                                      # dirty_sock / snap confinement
    "ntfs-3g",                                    # historic SUID root
    "exim4", "exim",                              # local-root MTA bugs
]


class PackagesCollector(Collector):
    name = "packages"

    def collect(self, target: SSHTarget, facts: Facts) -> None:
        self._distro(target, facts)
        self._pkg_manager(target, facts)
        self._key_packages(target, facts)
        self.log(f"distro={facts.distro_id} {facts.distro_version} "
                 f"({facts.distro_codename}); {len(facts.packages)} key packages")

    def _distro(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run("cat /etc/os-release 2>/dev/null")
        kv = {}
        for line in res.stdout.splitlines():
            m = re.match(r'^([A-Z_]+)=(.*)$', line)
            if m:
                kv[m.group(1)] = m.group(2).strip().strip('"')
        facts.distro_id = kv.get("ID", "").lower()
        facts.distro_version = kv.get("VERSION_ID", "")
        facts.distro_codename = kv.get("VERSION_CODENAME") or kv.get("UBUNTU_CODENAME", "")

    def _pkg_manager(self, target: SSHTarget, facts: Facts) -> None:
        res = target.run(
            "for m in dpkg-query rpm apk; do command -v $m >/dev/null 2>&1 && "
            "{ echo $m; break; }; done"
        )
        tool = res.stdout.strip()
        facts.pkg_manager = {"dpkg-query": "dpkg", "rpm": "rpm", "apk": "apk"}.get(tool, "")

    def _key_packages(self, target: SSHTarget, facts: Facts) -> None:
        names = " ".join(KEY_PACKAGES)
        if facts.pkg_manager == "dpkg":
            cmd = (f"dpkg-query -W -f='${{Package}} ${{Version}} ${{Architecture}}\\n' "
                   f"{names} 2>/dev/null")
            src = "dpkg"
        elif facts.pkg_manager == "rpm":
            cmd = (f"rpm -q --qf '%{{NAME}} %{{VERSION}}-%{{RELEASE}} %{{ARCH}}\\n' "
                   f"{names} 2>/dev/null")
            src = "rpm"
        elif facts.pkg_manager == "apk":
            cmd = ("for p in " + names + "; do apk info -e $p >/dev/null 2>&1 && "
                   "echo \"$p $(apk version $p 2>/dev/null | tail -n +2 | awk '{print $1}')\"; done")
            src = "apk"
        else:
            return
        res = target.run(cmd, timeout=30)
        facts.raw["packages"] = res.stdout
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or "is not installed" in line or "no packages" in line.lower():
                continue
            parts = line.split()
            if len(parts) < 2 or parts[1] in ("is", "not"):
                continue
            name, version = parts[0], parts[1]
            arch = parts[2] if len(parts) > 2 else ""
            facts.packages.append(Package(name=name, version=version, source=src, arch=arch))

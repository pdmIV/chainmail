#!/usr/bin/env python3
"""Offline end-to-end exercise of the chainmail analysis engine.

Builds a synthetic but realistic ``Facts`` object (no SSH / paramiko needed),
runs the graph builder + pathfinder + reporter, and asserts that the expected
direct and multi-step chains are discovered. Run:

    python3 tests/demo_offline.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chainmail.facts import (
    Facts, User, Group, SudoRule, SuidBinary, CapabilityFile,
    ScheduledJob, WritableTarget,
)
from chainmail.graph.builder import build_graph
from chainmail.graph.pathfinder import find_chains
from chainmail.report import render_report, render_json


def synthetic_facts() -> Facts:
    f = Facts()
    f.hostname = "lab-web01"
    f.os_release = "Ubuntu 22.04.3 LTS"
    f.kernel = "5.15.0-91-generic"
    f.arch = "x86_64"
    f.current_user = "bob"
    f.current_uid = 1000
    f.current_gid = 1000
    f.current_groups = ["bob", "staff", "docker"]

    f.users = [
        User("root", 0, 0, "/root", "/bin/bash"),
        User("bob", 1000, 1000, "/home/bob", "/bin/bash"),
        User("svc", 1001, 1001, "/home/svc", "/bin/bash"),
    ]
    f.groups = [
        Group("root", 0, []),
        Group("staff", 50, ["bob"]),
        Group("docker", 998, ["bob"]),
    ]

    # Direct: sudo find (GTFOBin), SUID find, cap_setuid python, docker group
    f.sudo_rules = [SudoRule(runas_users=["root"], commands=["/usr/bin/find"], nopasswd=True)]
    f.suid_binaries = [SuidBinary(path="/usr/bin/find", owner="root", mode="4755")]
    f.capabilities = [CapabilityFile(path="/usr/bin/python3.10", caps="cap_setuid+ep")]

    # Multi-step: root cron runs a script writable only via the 'staff' group.
    # bob -> (member of staff) -> write /opt/backup/run.sh -> root.
    f.scheduled_jobs = [
        ScheduledJob(source="/etc/cron.d/backup", owner="root",
                     command="/opt/backup/run.sh --nightly", kind="cron"),
        ScheduledJob(source="/etc/cron.d/report", owner="svc",
                     command="report-gen", kind="cron"),  # PATH-hijack candidate
    ]
    f.writable_targets = [
        WritableTarget(path="/opt/backup/run.sh", writable_via="group:staff",
                       note="executed by root via cron (/etc/cron.d/backup)"),
    ]
    f.path_dirs = ["/home/bob/bin", "/usr/bin", "/bin"]
    f.writable_path_dirs = ["/home/bob/bin"]
    return f


def connected_facts() -> Facts:
    """HTB 'Connected'-style host: a root incron rule watches a writable
    telephony config path, so the 'asterisk' user can fire a root command."""
    f = Facts()
    f.hostname = "connected"
    f.os_release = "CentOS 7"
    f.kernel = "3.10.0-1160"
    f.arch = "x86_64"
    f.current_user = "asterisk"
    f.current_uid = 1001
    f.current_gid = 1001
    f.current_groups = ["asterisk"]
    f.users = [User("root", 0, 0, "/root", "/bin/bash"),
               User("asterisk", 1001, 1001, "/home/asterisk", "/bin/bash")]
    f.groups = [Group("root", 0, []), Group("asterisk", 1001, [])]
    # root incron rule watching a path asterisk can write
    f.scheduled_jobs = [
        ScheduledJob(source="/etc/incron.d/sysadmin", owner="root",
                     command="/var/lib/asterisk/sysadmin.sh $@/$#",
                     kind="incron", trigger_path="/etc/dahdi/system.conf"),
    ]
    f.writable_targets = [
        WritableTarget(path="/etc/dahdi/system.conf", writable_via="user",
                       note="watched by root's incron rule (/etc/incron.d/sysadmin)"),
    ]
    return f


def _check_connected() -> None:
    facts = connected_facts()
    graph = build_graph(facts)
    chains = find_chains(graph, facts, max_depth=6)
    incron_chains = [c for c in chains
                     if any("incron" in (e.title + e.detail) for e in c.edges)]
    print("\n" + "=" * 70)
    print("  Connected-style host check (incron vector)")
    print("=" * 70)
    print(render_report(facts, graph, chains, color=True))
    assert chains, "expected an escalation chain on Connected-style host"
    assert incron_chains, "incron writable-exec chain to root not found"


def main() -> int:
    facts = synthetic_facts()
    graph = build_graph(facts)
    chains = find_chains(graph, facts, max_depth=6)

    print(render_report(facts, graph, chains, color=True))
    print("\n--- JSON (truncated check) ---")
    js = render_json(facts, graph, chains)
    print(js[:300] + " ...")

    # ---- assertions ----
    cats = {tuple(c.categories) for c in chains}
    multistep = [c for c in chains if c.is_multistep]
    assert chains, "expected at least one chain"
    assert any("group-privilege" in c.categories for c in chains), "docker group chain missing"
    assert any("sudo" in c.categories for c in chains), "sudo find chain missing"
    assert any("suid" in c.categories for c in chains), "suid find chain missing"
    assert any("capability" in c.categories for c in chains), "cap_setuid chain missing"
    assert multistep, "expected a multi-step (writable-exec via group) chain"
    assert any("writable-exec" in c.categories for c in multistep), "writable-exec chain missing"

    print(f"\n[OK] {len(chains)} chains, {len(multistep)} multi-step. All assertions passed.")

    _check_connected()
    print("[OK] Connected-style incron vector detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

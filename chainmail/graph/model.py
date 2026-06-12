"""Graph primitives.

Principals (users, groups) and assets (files, binaries, jobs) are nodes.
Edges are *capabilities*: "by doing X, the source principal can act as / become
the destination principal". A privilege-escalation chain is a path from the
current user node to ``user:root``.

This mirrors BloodHound's model (nodes + typed edges, shortest path to a
high-value target) but for Linux local privesc instead of Active Directory.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def user_node(name: str) -> str:
    return f"user:{name}"


def group_node(name: str) -> str:
    return f"group:{name}"


def asset_node(path: str) -> str:
    return f"asset:{path}"


# Edge technique categories (used for grouping/weighting/reporting).
MEMBERSHIP = "membership"        # relationship, zero cost
SUDO = "sudo"
SUID = "suid"
CAPABILITY = "capability"
GROUP_PRIV = "group-privilege"
WRITABLE_EXEC = "writable-exec"  # write a file executed by another principal
PATH_HIJACK = "path-hijack"
SENSITIVE_WRITE = "sensitive-write"


@dataclass
class Edge:
    src: str
    dst: str
    category: str
    title: str                       # short human label for this step
    detail: str = ""                 # why this edge exists (evidence)
    poc: str | None = None           # manual verification command
    requires: str = ""               # caveats / preconditions

    @property
    def weight(self) -> int:
        # Membership is a free relationship hop; real techniques cost 1.
        return 0 if self.category == MEMBERSHIP else 1


@dataclass
class Graph:
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    _adj: dict[str, list[Edge]] = field(default_factory=dict)

    def add_node(self, node_id: str, **attrs) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = {}
        self.nodes[node_id].update(attrs)

    def add_edge(self, edge: Edge) -> None:
        self.add_node(edge.src)
        self.add_node(edge.dst)
        # de-duplicate identical edges
        for e in self._adj.get(edge.src, []):
            if (e.dst, e.category, e.title) == (edge.dst, edge.category, edge.title):
                return
        self.edges.append(edge)
        self._adj.setdefault(edge.src, []).append(edge)

    def out_edges(self, node_id: str) -> list[Edge]:
        return self._adj.get(node_id, [])

"""Find escalation chains: simple paths from the current user to root.

This is the analytical payoff. A flat scanner lists findings; chainmail asks
"is there a *route* from where I stand to root?" and returns each route as an
ordered list of edges. Group-membership hops let routes pass through groups,
so chains that depend on a combination of privileges surface naturally.
"""
from __future__ import annotations

from dataclasses import dataclass

from chainmail.facts import Facts
from chainmail.graph.model import Graph, Edge, user_node, MEMBERSHIP


@dataclass
class Chain:
    edges: list[Edge]

    @property
    def length(self) -> int:
        # count real technique steps, not free membership hops
        return sum(e.weight for e in self.edges)

    @property
    def hops(self) -> int:
        return len(self.edges)

    @property
    def categories(self) -> list[str]:
        return [e.category for e in self.edges if e.category != MEMBERSHIP]

    @property
    def is_multistep(self) -> bool:
        # "Direct" means a single edge straight to root. Anything routing
        # through an intermediary -- a group you're in, a user you can pivot
        # through -- is a chain, even if only one step is a real technique.
        # These relationship-compounding routes are what flat scanners miss.
        return self.hops >= 2

    def signature(self) -> tuple:
        return tuple((e.src, e.dst, e.category, e.title) for e in self.edges)


def find_chains(graph: Graph, facts: Facts, max_depth: int = 6,
                max_chains: int = 200) -> list[Chain]:
    start = user_node(facts.current_user or "current-user")
    goal = user_node("root")
    if start == goal:
        return []

    chains: list[Chain] = []
    seen: set[tuple] = set()

    def dfs(node: str, path: list[Edge], visited: set[str]) -> None:
        if len(chains) >= max_chains:
            return
        # depth measured in real technique steps
        if sum(e.weight for e in path) > max_depth:
            return
        for edge in graph.out_edges(node):
            if edge.dst in visited:
                continue
            new_path = path + [edge]
            if edge.dst == goal:
                ch = Chain(edges=new_path)
                sig = ch.signature()
                if sig not in seen:
                    seen.add(sig)
                    chains.append(ch)
                continue
            dfs(edge.dst, new_path, visited | {edge.dst})

    dfs(start, [], {start})

    # Shortest, most direct chains first; multi-step chains are the interesting
    # ones linpeas misses, so surface them but keep them after quick wins.
    chains.sort(key=lambda c: (c.length, c.hops))
    return chains
# end of pathfinder

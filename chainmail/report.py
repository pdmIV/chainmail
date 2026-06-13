"""Render analysis results: human terminal report and JSON.

The human report leads with chains (the point of the tool), each shown as a
node-to-node route with the manual PoC for every step. chainmail prints PoCs
for the operator to run by hand; it does not execute them.
"""
from __future__ import annotations

import json
from dataclasses import asdict

from chainmail.facts import Facts
from chainmail.graph.model import Graph, MEMBERSHIP
from chainmail.graph.pathfinder import Chain


class _C:
    def __init__(self, enabled: bool):
        self.on = enabled

    def _w(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.on else s

    def bold(self, s): return self._w("1", s)
    def red(self, s): return self._w("31", s)
    def green(self, s): return self._w("32", s)
    def yellow(self, s): return self._w("33", s)
    def blue(self, s): return self._w("34", s)
    def cyan(self, s): return self._w("36", s)
    def dim(self, s): return self._w("2", s)


def render_report(facts: Facts, graph: Graph, chains: list[Chain], color: bool = True) -> str:
    c = _C(color)
    out: list[str] = []
    out.append(c.bold(c.cyan("=" * 70)))
    out.append(c.bold(c.cyan("  chainmail :: Linux privilege escalation chains")))
    out.append(c.bold(c.cyan("=" * 70)))
    out.append("")
    out.append(f"  host    : {facts.hostname}  ({facts.os_release})")
    out.append(f"  kernel  : {facts.kernel} {facts.arch}")
    out.append(f"  user    : {c.yellow(facts.current_user)} "
               f"(uid={facts.current_uid}) groups: {', '.join(facts.current_groups)}")
    out.append("")

    out.append(c.bold("  Enumeration summary"))
    out.append(f"    sudo rules        : {len(facts.sudo_rules)}")
    out.append(f"    suid/sgid binaries: {len(facts.suid_binaries)}")
    out.append(f"    file capabilities : {len(facts.capabilities)}")
    out.append(f"    scheduled jobs    : {len(facts.scheduled_jobs)}")
    out.append(f"    writable targets  : {len(facts.writable_targets)}")
    out.append(f"    hijackable incl.  : {len(facts.hijackable_includes)}")
    out.append(f"    key packages      : {len(facts.packages)}")
    out.append(f"    CVE findings      : {len(facts.vuln_findings)}")
    out.append(f"    graph             : {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    out.append("")
    out.extend(_render_cve_findings(c, facts))

    if not chains:
        out.append(c.yellow("  No escalation chains to root were found with current data."))
        out.append(c.dim("  (Try -vv, supply sudo creds for `sudo -l`, or widen --max-depth.)"))
        return "\n".join(out)

    direct = [ch for ch in chains if not ch.is_multistep]
    multi = [ch for ch in chains if ch.is_multistep]

    out.append(c.bold(c.green(
        f"  {len(chains)} escalation chain(s) to root  "
        f"[{len(direct)} direct, {len(multi)} multi-step]")))
    out.append("")

    n = 0
    for label, group_ in (("DIRECT", direct), ("MULTI-STEP (chained)", multi)):
        if not group_:
            continue
        out.append(c.bold(c.blue(f"  --- {label} ---")))
        out.append("")
        for ch in group_:
            n += 1
            out.extend(_render_chain(c, n, ch))
            out.append("")

    out.append(c.dim("  PoC commands are for manual, authorized verification only. "
                     "chainmail never runs them."))
    return "\n".join(out)


def _render_cve_findings(c: _C, facts: Facts) -> list[str]:
    findings = getattr(facts, "vuln_findings", []) or []
    if not findings:
        return []
    order = {"high": 0, "medium": 1, "lead": 2}
    findings = sorted(findings, key=lambda f: (order.get(getattr(f, "confidence", "lead"), 3),
                                               f.cve))
    lines = [c.bold("  CVE enrichment (kernel + key packages)")]
    for f in findings:
        conf = getattr(f, "confidence", "lead")
        tag = (c.red("LOCAL-ROOT") if getattr(f, "local_root", False) else c.dim("lead"))
        wild = c.red(" WILD-EXPLOITED") if getattr(f, "wild_exploited", False) else ""
        lines.append(f"    {c.yellow(f.cve)} {f.name}  ({f.component}) "
                     f"[{tag}/{conf}{wild}]  src={f.source}")
        if f.reference:
            lines.append(c.dim(f"        ref: {f.reference}"))
    lines.append("")
    return lines


def _render_chain(c: _C, idx: int, ch: Chain) -> list[str]:
    lines: list[str] = []
    route_parts = [ch.edges[0].src] + [e.dst for e in ch.edges]
    route = c.dim(" -> ").join(_short(p) for p in route_parts)
    badge = c.green("DIRECT") if not ch.is_multistep else c.yellow(f"{ch.hops}-HOP")
    lines.append(f"  [{idx}] {badge}  {route}")
    for i, e in enumerate(ch.edges, 1):
        if e.category == MEMBERSHIP:
            lines.append(c.dim(f"        ~ {e.title}"))
            continue
        lines.append(f"      {c.bold(str(i) + '.')} {c.cyan(e.title)}  "
                     f"[{e.category}]")
        if e.detail:
            lines.append(c.dim(f"         {e.detail}"))
        if e.requires:
            lines.append(c.dim(f"         requires: {e.requires}"))
        if e.poc:
            lines.append(f"         {c.green('PoC')} {c.dim('$')} {e.poc}")
    return lines


def _short(node_id: str) -> str:
    if node_id.startswith("user:"):
        return f"\U0001f464 {node_id[5:]}" if False else node_id[5:]
    if node_id.startswith("group:"):
        return f"[grp {node_id[6:]}]"
    return node_id


def render_json(facts: Facts, graph: Graph, chains: list[Chain]) -> str:
    payload = {
        "host": {
            "hostname": facts.hostname,
            "os_release": facts.os_release,
            "kernel": facts.kernel,
            "arch": facts.arch,
        },
        "identity": {
            "user": facts.current_user,
            "uid": facts.current_uid,
            "gid": facts.current_gid,
            "groups": facts.current_groups,
        },
        "summary": {
            "sudo_rules": len(facts.sudo_rules),
            "suid_binaries": len(facts.suid_binaries),
            "capabilities": len(facts.capabilities),
            "scheduled_jobs": len(facts.scheduled_jobs),
            "writable_targets": len(facts.writable_targets),
            "graph_nodes": len(graph.nodes),
            "graph_edges": len(graph.edges),
            "chains_total": len(chains),
            "chains_multistep": sum(1 for c in chains if c.is_multistep),
            "key_packages": len(facts.packages),
            "cve_findings": len(getattr(facts, "vuln_findings", []) or []),
        },
        "cve_findings": [
            {
                "cve": f.cve, "name": f.name, "component": f.component,
                "summary": f.summary, "reference": f.reference,
                "requires": f.requires, "severity": f.severity, "source": f.source,
                "local_root": getattr(f, "local_root", False),
                "corroborated": getattr(f, "corroborated", False),
                "wild_exploited": getattr(f, "wild_exploited", False),
                "epss": getattr(f, "epss", None), "cvss": getattr(f, "cvss", None),
                "confidence": getattr(f, "confidence", "lead"),
            }
            for f in (getattr(facts, "vuln_findings", []) or [])
        ],
        "chains": [
            {
                "rank": i + 1,
                "steps": ch.length,
                "hops": ch.hops,
                "multistep": ch.is_multistep,
                "route": [ch.edges[0].src] + [e.dst for e in ch.edges],
                "edges": [
                    {
                        "from": e.src, "to": e.dst, "category": e.category,
                        "title": e.title, "detail": e.detail,
                        "requires": e.requires, "poc": e.poc,
                    }
                    for e in ch.edges
                ],
            }
            for i, ch in enumerate(chains)
        ],
    }
    return json.dumps(payload, indent=2)
# (end of file)

"""Command-line interface for chainmail."""
from __future__ import annotations

import argparse
import sys

from chainmail import __version__
from chainmail import banner as _banner
from chainmail.ssh import SSHTarget
from chainmail.facts import Facts
from chainmail.collectors import run_all_collectors
from chainmail.vulnsources import enrich
from chainmail.graph.builder import build_graph
from chainmail.graph.pathfinder import find_chains
from chainmail.report import render_report, render_json


def _parse_target(target: str) -> tuple[str, str]:
    """Split ``user@host`` into ``(user, host)``."""
    if "@" not in target:
        raise argparse.ArgumentTypeError(
            f"target must be in the form user@host (got '{target}')"
        )
    user, host = target.split("@", 1)
    if not user or not host:
        raise argparse.ArgumentTypeError(f"invalid target '{target}'")
    return user, host


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chainmail",
        description=(
            "Graph-based Linux local privilege escalation path finder. "
            "Read-only enumeration over SSH; reports multi-step escalation "
            "chains to root with manual proof-of-concept commands. It never "
            "executes escalation on the target."
        ),
        epilog=(
            "Examples:\n"
            "  chainmail bob@10.10.10.5 --password 'hunter2'\n"
            "  chainmail bob@10.10.10.5 -i ~/.ssh/id_rsa\n"
            "  chainmail bob@target -i key --json > chains.json\n\n"
            "Only run chainmail against systems you are authorized to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="SSH target as user@host")
    p.add_argument("-p", "--port", type=int, default=22, help="SSH port (default 22)")

    auth = p.add_mutually_exclusive_group()
    auth.add_argument("--password", help="SSH password (prefer key auth / env var)")
    auth.add_argument(
        "-i", "--identity", dest="key_filename",
        help="path to a private key file for SSH auth",
    )
    p.add_argument(
        "--passphrase", help="passphrase for the private key, if encrypted"
    )

    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument(
        "--max-depth", type=int, default=6,
        help="maximum chain length to search (default 6)",
    )
    p.add_argument(
        "--no-color", action="store_true", help="disable ANSI color in output"
    )

    enr = p.add_argument_group("CVE enrichment")
    enr.add_argument(
        "--vuln-source", default="auto",
        choices=["auto", "vulners", "osv", "none"],
        help="online CVE source (default: auto = vulners if key else osv)",
    )
    enr.add_argument(
        "--vulners-key", default=None,
        help="Vulners API key (or set VULNERS_API_KEY env var)",
    )
    enr.add_argument(
        "--offline", action="store_true",
        help="curated CVE database only; make no network calls",
    )
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v, -vv")
    p.add_argument("--version", action="version", version=f"chainmail {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        user, host = _parse_target(args.target)
    except argparse.ArgumentTypeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    password = args.password
    if not password and not args.key_filename:
        # Neither flag given: fall back to interactive prompt / agent keys.
        import getpass
        try:
            password = getpass.getpass(f"{user}@{host} password (blank to use SSH agent/keys): ")
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return 130
        password = password or None

    target = SSHTarget(
        host=host,
        user=user,
        port=args.port,
        password=password,
        key_filename=args.key_filename,
        key_passphrase=args.passphrase,
    )

    if not args.json:
        print(_banner.render(__version__, color=not args.no_color), file=sys.stderr)
        print(f"[*] connecting to {user}@{host}:{args.port}", file=sys.stderr)

    try:
        target.connect()
    except ConnectionError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    try:
        facts = Facts()
        run_all_collectors(target, facts, verbose=args.verbose)
    finally:
        target.close()

    # CVE enrichment (offline DB always; online source unless --offline/none).
    # Network requests originate from this host, not the target.
    if not args.json:
        print("[*] enriching with CVE data "
              f"({'offline only' if args.offline else args.vuln_source})...",
              file=sys.stderr)
    facts.vuln_findings = enrich(
        facts, source_name=args.vuln_source, vulners_key=args.vulners_key,
        offline_only=args.offline, verbose=args.verbose,
    )

    graph = build_graph(facts)
    chains = find_chains(graph, facts, max_depth=args.max_depth)

    if args.json:
        print(render_json(facts, graph, chains))
    else:
        print(render_report(facts, graph, chains, color=not args.no_color))
    return 0

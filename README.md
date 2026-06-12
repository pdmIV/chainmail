# chainmail

Graph-based Linux local privilege-escalation (LPE) **path finder**. chainmail
connects to a target over SSH, performs read-only enumeration, models the host
as a graph of principals (users/groups) and assets (binaries/files/jobs), and
finds **multi-step escalation chains to root** — the compound routes that flat
scanners like linpeas tend to miss.

Think of it as BloodHound's "shortest path to Domain Admin" idea, applied to
Linux local privesc instead of Active Directory: typed edges between nodes, and
a search for any route from *where you stand* to `user:root`.

> **Authorized use only.** chainmail is for penetration testers and defenders
> assessing systems they own or are explicitly permitted to test. It performs
> read-only enumeration and **never executes an escalation** — for every chain
> it finds, it prints the manual proof-of-concept commands an operator can run
> by hand to verify the vector.

## Install

```bash
pip install -r requirements.txt    # just paramiko
```

Runs on Kali (or any Python 3.10+ box). Nothing is installed on the target.

## Usage

```bash
# password auth (prompts if --password omitted)
python3 chainmail.py bob@10.10.10.5 --password 'hunter2'

# private key auth
python3 chainmail.py bob@10.10.10.5 -i ~/.ssh/id_rsa

# machine-readable output for pipelines / reporting
python3 chainmail.py bob@target -i key --json > chains.json

# search deeper / shallower (default technique-depth 6)
python3 chainmail.py bob@target -i key --max-depth 4
```

Key flags: `-i/--identity` private key, `--password`, `--passphrase`,
`-p/--port`, `--json`, `--max-depth`, `--no-color`, `-v/-vv` (verbose
collection logging).

## What makes it different from linpeas

linpeas is an excellent flat enumerator: it lists findings. chainmail's job is
**relationship reasoning**. Two things fall out of the graph model that a list
can't express:

1. **Multi-step chains.** A root cron job runs `/opt/app/run.sh`; you can't
   write it, but a *group you're in* can; so `you → group → write script →
   root`. Each fact is individually benign; the path is not.
2. **Group/relationship compounding.** Membership edges (`you → group`) are
   free hops, so any privilege attached to a group you belong to composes with
   everything else. Being in `staff` and a writable cron input are separate
   linpeas lines; here they're one route.

Example output (synthetic lab host):

```
  5 escalation chain(s) to root  [3 direct, 2 multi-step]

  --- MULTI-STEP (chained) ---
  [4] 2-HOP  bob -> [grp staff] -> root
        ~ member of group 'staff'
      2. write cron target run by root  [writable-exec]
         /etc/cron.d/backup runs '/opt/backup/run.sh' as root; writable via group:staff
         PoC $ echo '#!/bin/sh' > /opt/backup/run.sh; echo '/bin/sh -i' >> /opt/backup/run.sh
```

## Architecture

```
chainmail/
  cli.py            argparse CLI; orchestrates connect -> collect -> analyze -> report
  ssh.py            paramiko wrapper (password or -i key); read-only run()
  facts.py          typed containers; the seam between collection and analysis
  collectors/       read-only enumeration over SSH (one domain each)
    identity.py       id, /etc/passwd, /etc/group, sudo -l
    suid.py           SUID/SGID binaries + file capabilities
    scheduled.py      cron (system/dropin/user) + systemd services/timers
    filesystem.py     targeted writability of $PATH dirs, job inputs, sensitive files
  knowledge/
    gtfobins.py       binary -> sudo/suid PoC templates (curated GTFOBins subset)
    groups.py         group -> escalation (docker, lxd, disk, shadow, ...)
  graph/
    model.py          Node / Edge / Graph primitives
    builder.py        Facts -> escalation edges (the join logic)
    pathfinder.py     DFS for simple paths: current user -> root
  report.py         terminal + JSON renderers
tests/
  demo_offline.py   end-to-end engine exercise on synthetic facts (no SSH needed)
```

The design deliberately separates **collection** (side effects over SSH) from
**analysis** (pure functions over `Facts`). That means the engine is
unit-testable with mock data and re-analysis never re-touches the target.

```bash
python3 tests/demo_offline.py    # builds synthetic facts, asserts chains found
```

## Edge types the graph understands

`sudo` (GTFOBins via sudo rules) · `suid` (SUID GTFOBins) · `capability`
(`cap_setuid` on interpreters) · `group-privilege` (docker/lxd/disk/shadow/…) ·
`writable-exec` (write a file a scheduled job runs as someone else) ·
`path-hijack` (writable `$PATH` dir ahead of a job's bare command) ·
`sensitive-write` (writable `/etc/passwd`, `sudoers`, `ld.so.preload`, …) ·
`membership` (free relationship hop tying groups into routes).

## Extending it

The knowledge base is intentionally trivial to grow:

- Add a binary technique: one entry in `knowledge/gtfobins.py`
  (`{"sudo": "...", "suid": "..."}`, `{path}`/`{user}` templates).
- Add a group escalation: one `GroupEscalation` in `knowledge/groups.py`.
- Add a whole new edge category: a collector to gather the facts, a small
  `_add_*` function in `graph/builder.py`, and the pathfinder picks it up for
  free.

## Roadmap ideas

- Kernel/exploit-suggester edges keyed on `uname`/package versions.
- NFS `no_root_squash`, writable systemd timers, D-Bus/polkit chains.
- DOT/JSON graph export for visual review in BloodHound-style UIs.
- Pivot through intermediate *users* (not just groups) when creds/keys are
  recovered mid-run.

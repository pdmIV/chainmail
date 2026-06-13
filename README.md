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

## CVE enrichment (kernel / exploit suggester)

chainmail keys known local-root CVEs off the target's `uname` and key package
versions (sudo, polkit/pkexec, glibc, dbus, util-linux, PAM, snapd), then adds
a direct `you -> root` edge for each confirmed vector. It combines two layers:

- **Offline curated database** (`knowledge/kernel_cve.py`) — always on, no
  network. Well-known LPEs (Dirty COW, Dirty Pipe, PwnKit, Baron Samedit,
  Looney Tunables, OverlayFS, nf_tables, ptrace TRACEME, Netfilter…) with
  version ranges and public PoC references. This is also the authoritative
  "is this CVE actually a local-root vector" filter for online noise.
- **Live API** — fresh CVEs, EPSS, and CISA-KEV/AttackerKB "wild exploited"
  flags. Default is **Vulners** `audit/host` (best exploit intel; needs a free
  key), falling back to keyless **OSV.dev** when no key is set.

```bash
# Vulners (recommended): free key from vulners.com, then
export VULNERS_API_KEY=xxxxxxxx
python3 chainmail.py bob@target -i key                 # auto-uses Vulners

python3 chainmail.py bob@target -i key --vuln-source osv     # keyless OSV
python3 chainmail.py bob@target -i key --offline             # curated DB only, no network
```

Network requests go out **from the host running chainmail** (your Kali box),
not the target. Findings are scored by confidence — `high` (curated LPE
corroborated by a relevant SUID on the host, or wild-exploited), `medium`
(curated match), `lead` (online-only). Because distros backport fixes without
bumping version strings, every finding carries a "confirm patch level" caveat:
chainmail reports leads and points at public PoCs, it never runs exploit code.

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
    incron.py         inotify-cron rules (/etc/incron.d, spool tables) + watched paths
    jobscripts.py     reads root-run job scripts; finds hijackable includes
    packages.py       distro id/codename + key privesc package versions
    filesystem.py     targeted writability of $PATH dirs, job inputs, sensitive files
  vulnsources/        CVE enrichment ("exploit suggester")
    offline.py          curated kernel-LPE database matcher (always on, no network)
    vulners.py          Vulners linux-audit client (API key; wild-exploited + EPSS)
    osv.py              OSV.dev client (keyless)
  knowledge/
    kernel_cve.py       curated local-root CVEs + version predicates + PoC refs
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
`kernel-exploit` (known local-root CVE keyed on kernel/package versions) ·
`include-hijack` (writable/missing file included by a root-run script) ·
`membership` (free relationship hop tying groups into routes).

**incron and include-hijacking.** A root `incrond` rule has two distinct
ingredients, and chainmail models them separately:

- If the triggered command *consumes the watched file* (incron `$@`/`$#`
  wildcards, or the path appears in the command), writing the file injects into
  a root context — a `writable-exec` edge with a `touch`-to-fire PoC.
- More commonly the watched file is only a *trigger* for a fixed root helper
  script, and the real code-exec is a file that script `include`s / `require`s
  / `source`s which you can control. This is the actual HTB "Connected" vector:
  `/usr/sbin/sysadmin_ha` runs as root on trigger and `require_once`s a PHP file
  that **doesn't exist** under a writable directory. chainmail's `jobscripts`
  collector reads the root script, resolves its includes (including
  `$var`-assigned paths), and flags any that are writable **or missing with a
  writable ancestor**. The `include-hijack` edge's PoC creates the missing
  include — stubbing the exact `class::method` the script invokes — then fires
  the trigger.

## Extending it

The knowledge base is intentionally trivial to grow:

- Add a binary technique: one entry in `knowledge/gtfobins.py`
  (`{"sudo": "...", "suid": "..."}`, `{path}`/`{user}` templates).
- Add a group escalation: one `GroupEscalation` in `knowledge/groups.py`.
- Add a whole new edge category: a collector to gather the facts, a small
  `_add_*` function in `graph/builder.py`, and the pathfinder picks it up for
  free.
- Add a kernel/userland CVE: one `KernelCVE` entry in `knowledge/kernel_cve.py`
  with a version predicate and a public PoC reference.
- Add a vulnerability source: subclass `VulnerabilitySource` in `vulnsources/`.

## Roadmap ideas

- NFS `no_root_squash`, writable systemd timers, D-Bus/polkit chains.
- DOT/JSON graph export for visual review in BloodHound-style UIs.
- Pivot through intermediate *users* (not just groups) when creds/keys are
  recovered mid-run.

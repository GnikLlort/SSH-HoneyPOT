# SSH HoneyPot

A defensive SSH honeypot: a believable Debian 12 build server that records what
visitors do, built on the current stable [Cowrie](https://github.com/cowrie/cowrie)
release and delivered as a version-pinned, locally-validated deployment
package.

Nothing a visitor sends is ever executed on the host. Cowrie emulates a shell in
Python — it parses commands, it does not run them.

---

## What this is

A single-purpose EC2 instance that looks like an ordinary internal build server
with SSH exposed, and records everything a visitor does to it:

* **A synthetic host** — hostname, OS release, kernel, CPU, memory, disk,
  accounts, ownership, permissions, timestamps, package versions, process
  listings and command output, all generated from one manifest so they cannot
  disagree with each other.
* **~100 emulated commands**, with a generated filesystem including config
  files, planted service logs, decoy documents and unique canary values.
* **Full session recording** — terminal transcripts, authentication attempts,
  every command, and every uploaded file preserved byte-for-byte in quarantine.
* **Off-host evidence shipping** — logs and captures leave the host within five
  minutes, encrypted, to a bucket in a separate AWS account that the honeypot
  cannot delete from.
* **An administrator-only playback interface** — play, pause, seek, step,
  adjustable speed, searchable command transcript, and links to file transfers.
  Loopback-only, reached over AWS Session Manager.
* **An off-host monitoring dashboard** — a second program for a separate
  monitoring host: searchable events and sessions, role-based access with MFA,
  exports, health, and a full audit trail. It cannot reach the honeypot, cannot
  run anything, and never opens a captured file. `deploy/install-dashboard.sh`
  sets it up; `docs/16` is the walkthrough from an empty host to a first
  sign-in, and `docs/15` is what it guarantees.

---

## What this is not

* **Not deployed.** This package is built and validated locally. It has never
  faced the internet. See `docs/09` for exactly what was and was not tested.
* **Not undetectable.** An operator who reads `/proc` or measures timing will
  find it. `docs/10` lists the specific signals, ranked, without softening
  them.
* **Not a sandbox.** It is a recorder. The QEMU high-interaction mode that
  *would* run attacker code is a design (`docs/12`), not an implementation.
* **Not for any host you care about.** It belongs on a new, disposable instance
  in its own network boundary, with no route to production.

---

## Read the safety rule first

> Deploy on a **new, disposable EC2 instance in its own security boundary**, with
> no network route to any production system, and treat every captured password,
> command and uploaded file as sensitive evidence.

If the instance you are looking at hosts anything you care about, stop. It is
the wrong instance.

Never execute, preview or open a captured file on the honeypot or on a normal
workstation.

---

## Layout

```
realism/
  identity.yaml           the single source of truth for the fake host
  build_profile.py        generates every observable artefact from it
overlays/cowrie_realism_overlay/
                          optional, reversible fixes for four Cowrie defects
config/
  cowrie.cfg              operator config (overrides only)
  userdb.txt              credential allow-list
deploy/
  versions.env            the single place a version is written down
  install.sh              10 staged, idempotent, dry-run by default
  update.sh               update to a branch/tag/commit; records the rollback
  install-dashboard.sh    the off-host reviewer, on its own host
  uninstall.sh            --stop (keep evidence) vs --remove (destroy it)
  rebuild.sh              evidence-export-first recovery path
  lib/checkout.sh         clone-or-refresh a pinned checkout, idempotently
  systemd/                the service, health check, log shipper, playback UI,
                          bundle shipper, and the two dashboard units
  aws/security-groups.md  VPC, security groups, IAM, boundary verification
  cowrie-logship.env.example
ops/
  healthcheck.sh          service, banner, log staleness, disk, outbound, isolation
  quarantine_sync.sh      ship evidence and hash manifest; prune only after verify
  export_bundle.sh        pack a bundle for the dashboard and ship it
  alert_dispatch.sh       webhook + local alert log; no captured content
  prune_local.sh, canary_scan.sh, logrotate/, alerts/rules.md
playback/
  server.py               read-only session viewer (on the honeypot, on demand)
dashboard/
  server.py               monitoring UI for a separate host: events, sessions,
                          playback, health, audit, exports
  store.py, ingest.py     the monitoring store and the only writer into it
  auth.py, manage.py      accounts, roles, MFA, lockout recovery, audit trail
  bundle.py, render.py    honeypot-side export staging; HTML rendering
shared/
  terminal_safety.py      the sanitizers both viewers share
  safe_paths.py           the delete guard used by every recursive delete
tests/
  test_conformance.py     198 checks: the realism contract
  test_playback.py        32 checks: the reviewer's safety contract
  test_dashboard.py       95 checks: sanitising, auth, filters, playback bounds
  test_safety_guards.py   31 checks: delete guards and the isolation invariant
  test_deployment_scripts.py 22 checks: update/install scripts, units, doc links
  probe_discovery.py      exploratory 84-command sweep
  lib/                    OpenSSH-based client and lab control
AUDIT.md                  adversarial code audit: 16 findings, fixes and tests
docs/                     see below
```

---

## Documentation

Start with [`docs/README.md`](docs/README.md).

| Doc | Contents |
|---|---|
| [01 — Architecture](docs/01-architecture.md) | Components, data flow, trust boundaries |
| [02 — Threat model](docs/02-threat-model.md) | Adversaries, assets, what is and is not defended |
| [03 — Install on Ubuntu EC2](docs/03-install-ubuntu-ec2.md) | Staged guide; every server-changing command marked |
| [04 — Configuration reference](docs/04-config-reference.md) | Every knob and why it is set that way |
| [05 — Isolation and the network boundary](docs/05-isolation-and-network-boundary.md) | The three boundaries and how to verify them |
| [06 — Evidence handling](docs/06-evidence-handling.md) | Quarantine, hashing, safe inspection |
| [07 — Session playback](docs/07-session-playback.md) | The viewer, and why a recording is untrusted input |
| [08 — Test plan](docs/08-test-plan.md) | What is tested and what would count as failure |
| [09 — Test results](docs/09-test-results.md) | Actual results, including the gaps |
| [10 — Assumptions, limitations, detection signals](docs/10-assumptions-limitations-detection.md) | Where this can be found out, ranked |
| [11 — Rollback and rebuild](docs/11-rollback-and-rebuild.md) | Undo, and rebuild without losing evidence |
| [12 — QEMU high-interaction design](docs/12-qemu-high-interaction.md) | The optional later phase; design only |
| [13 — LLM mode review](docs/13-llm-mode-review.md) | Why it is off, and the preconditions to enable it |
| [14 — Operations runbook](docs/14-operations-runbook.md) | Day-to-day, alerts, maintenance, incident response |
| [15 — Monitoring dashboard](docs/15-monitoring-dashboard.md) | The off-host reviewer: roles, limits, what it cannot do |
| [16 — Getting the dashboard working](docs/16-dashboard-setup.md) | Step by step to a working sign-in: bundles, install, accounts |
| [17 — Updating an installed deployment](docs/17-updating-the-deployment.md) | Install a branch, verify it, roll it back |

Related material outside `docs/`:

* [`AUDIT.md`](AUDIT.md) — an adversarial audit of the dashboard and the
  package: every finding, how it was proven, and the test that guards the fix.
* [`deploy/aws/security-groups.md`](deploy/aws/security-groups.md) — the network
  boundary, with the checks that should all fail.
* [`ops/alerts/rules.md`](ops/alerts/rules.md) — alert rules and thresholds.

---

## Current state

| | |
|---|---|
| Honeypot | Cowrie **3.1.0**, commit `6ec36d0d5d4a1a14bc6e6ddadcb7b8f255e0570b` |
| Platform | Ubuntu 24.04 LTS, Python 3.12 |
| Emulated host | Debian 12.5, kernel `6.1.0-21-amd64`, `OpenSSH_9.2p1 Debian-2+deb12u3` |
| Conformance | **197 / 198**, 0 actionable failures (1 `info`-level interop note) |
| Playback | **32 / 32** |
| Dashboard | **95 / 95** |
| Safety guards | **31 / 31** |
| Deployment scripts and docs | **22** (21 pass; 1 needs root) |
| Profile build | 6 / 6 invariants |
| Audit | 16 findings, all fixed; see [`AUDIT.md`](AUDIT.md) |

Fully pinned in [`deploy/versions.env`](deploy/versions.env) — Cowrie plus every
transitive dependency, with the commit rather than the tag, because tags are
mutable.

---

## Local validation

```bash
python3 -m venv .venv && .venv/bin/pip install -e .        # or install Cowrie 3.1.0
.venv/bin/python realism/build_profile.py \
    --identity realism/identity.yaml --out build/profile
bash tests/lib/labctl.sh lab_init     # materialise lab/ from build/profile
bash tests/lib/labctl.sh lab_restart  # (lab_start initialises it too, if missing)
python3 tests/test_conformance.py --expect build/profile/expectations.json
python3 tests/test_playback.py
python3 tests/test_dashboard.py
python3 tests/test_safety_guards.py
python3 tests/test_deployment_scripts.py
bash deploy/install.sh                                     # dry run — changes nothing
```

The lab is loopback-only on `127.0.0.1:2222` and is built from the same
generated profile the deployment installs — `lab_init` is idempotent, so
re-running it after an edit to `realism/identity.yaml` refreshes the lab.
`lab_start` prints the captured startup log instead of timing out silently if
Cowrie refuses to start.

`deploy/install.sh` prints its full plan and changes nothing without `--apply`.

---

## Before you deploy

1. Read `docs/02-threat-model.md`.
2. Confirm the instance is disposable and has no route to production
   (`docs/03` §0).
3. Create the evidence bucket **in a separate AWS account**.
4. Follow `docs/03`, then verify the boundary with
   `deploy/aws/security-groups.md` §6 — **all of those checks should fail.**
5. Confirm that operating a honeypot is lawful where you are and permitted by
   your provider and your organisation. This package cannot answer that for you.

---

## Scope and intent

Authorised defensive security tooling, for systems the operator owns or is
explicitly authorised to monitor. It captures the credentials and files that
attackers send to it, which makes it sensitive by construction: restrict access,
encrypt storage, define retention, and never send captured data to a third party
by default.

Never block or report an IP merely because it connected. The honeypot is built
to receive those connections.

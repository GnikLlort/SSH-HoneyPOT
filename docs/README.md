# SSH honeypot — documentation

A defensive SSH honeypot: a believable Debian build server that records what
visitors do, built on the current stable Cowrie release.

**Read this first if you are about to deploy.** The package is validated
locally and has never been run against the internet. Section
[What has and has not been proven](#what-has-and-has-not-been-proven) below is
the honest summary.

---

## Contents

| Doc | What it covers |
|---|---|
| [01 — Architecture](01-architecture.md) | Components, data flow, and where the trust boundaries are |
| [02 — Threat model](02-threat-model.md) | What we defend against, what we accept, what we cannot claim |
| [03 — Install on Ubuntu EC2](03-install-ubuntu-ec2.md) | Staged, copy-paste installation guide |
| [04 — Configuration reference](04-config-reference.md) | Every knob, what it does, why it is set that way |
| [05 — Isolation and the network boundary](05-isolation-and-network-boundary.md) | The three boundaries, and how to verify each one holds |
| [06 — Evidence handling](06-evidence-handling.md) | Captured files: quarantine, hashing, safe inspection |
| [07 — Session playback](07-session-playback.md) | The administrator-only recording viewer |
| [08 — Test plan](08-test-plan.md) | What is tested, how, and what would count as failure |
| [09 — Test results](09-test-results.md) | What the results actually were, including the gaps |
| [10 — Assumptions, limitations, detection signals](10-assumptions-limitations-detection.md) | Where this can be detected, and what it does not protect against |
| [11 — Rollback and rebuild](11-rollback-and-rebuild.md) | How to undo, and how to rebuild from nothing |
| [12 — QEMU high-interaction design](12-qemu-high-interaction.md) | The optional later-phase guest pool (design only, not built) |
| [13 — LLM mode review](13-llm-mode-review.md) | Why LLM mode is off, and the conditions for turning it on |
| [14 — Operations runbook](14-operations-runbook.md) | Day-to-day operation, alert response, maintenance, incident response |
| [15 — Monitoring dashboard](15-monitoring-dashboard.md) | The off-host reviewer: roles, limits, what it cannot do |

Related material outside `docs/`:

* `deploy/aws/security-groups.md` — security groups, routing, IAM, verification
* `ops/alerts/rules.md` — alert rules, thresholds and response
* `deploy/versions.env` — the single source of every version pin
* `AUDIT.md` — adversarial audit of the dashboard and the package: 14 findings,
  each with the proof and the test that now guards it

---

## Thirty-second orientation

```
Internet ──tcp/22──► [ Cowrie, unprivileged ]
                          │  emulated shell, ~100 fake commands,
                          │  synthetic Debian 12 filesystem
                          ▼
                     var/log/cowrie/cowrie.json   ← the event record
                     var/lib/cowrie/tty/*         ← session recordings
                     var/lib/cowrie/downloads/*   ← captured uploads
                          │
                          │  ops/quarantine_sync.sh, every 5 min
                          ▼
                     S3, separate account, SSE-KMS, Object Lock
```

Nothing a visitor sends is ever executed on the host. Cowrie is a Python
program that emulates a shell; it parses commands, it does not run them.

---

## What has and has not been proven

**Proven, with evidence in `docs/09-test-results.md`:**

* The synthetic host is internally consistent under ordinary discovery
  commands — 197 of 198 automated conformance checks pass, across identity,
  CPU, memory, storage, network, accounts, processes, services, logs, command
  output, leakage and canary categories.
* No real host data leaks into the emulated shell. Sixteen leakage checks look
  specifically for the real host's files, environment, and metadata service.
* The credential policy behaves: documented weak passwords are accepted,
  everything else is rejected, consistently with `PermitRootLogin
  prohibit-password`.
* A hostile recording cannot affect a reviewer using the playback interface —
  32 tests cover escape sequences, bidirectional overrides, markup injection
  and path traversal in the evidence store.
* Recorded evidence ships off-host on a schedule, is encrypted, and cannot be
  deleted by the honeypot.

**Not proven, and should not be claimed:**

* **This has never faced the internet.** It has only been exercised from
  `127.0.0.1` on the build machine. Real scanners behave differently from a
  test harness, and the first hours of real traffic will teach you things.
* **It is not undetectable.** An operator who reads the emulated
  `/proc`, diffs behaviour against a real kernel, or measures timing will find
  it. `docs/10` lists the specific signals, honestly. No honeypot fools every
  attacker, and any vendor claiming otherwise is selling something.
* **The QEMU high-interaction mode is a design, not an implementation.**
  `docs/12` explains what it would take.
* **The `ps` and `service` commands rely on a small overlay** because Cowrie's
  built-in implementations truncate output at `COLUMNS` and ignore the
  configured process table. The overlay falls back to stock behaviour on any
  error, which means a regression there degrades to *less* realistic output
  rather than a broken session. See `docs/04`.

---

## The one-sentence safety rule

Deploy this on a **new, disposable EC2 instance in its own security boundary**,
with no network route to any production system, and treat every captured
password, command and file as sensitive evidence.

If the instance you are looking at hosts anything you care about, stop — this
is the wrong instance.

# 08 — Test plan

Results are in [`09-test-results.md`](09-test-results.md). This page is the plan:
what is tested, how, and what would count as a failure.

---

## 1. What is being tested

The claim under test is not "this honeypot is undetectable". It is:

> **A visitor who runs ordinary Linux discovery commands gets answers that
> agree with each other and with the advertised identity, and gets nothing that
> reveals the real host, the honeypot software, or the surrounding
> infrastructure.**

Two things follow from that framing. First, most of the tests are about
**agreement** — the same fact reported consistently through several channels —
rather than about any single output being "correct". Second, the negative tests
matter as much as the positive ones: a check that passes because a command
failed is worse than useless, so every output-parsing check also asserts that
the command produced parsable output.

---

## 2. Test environments

### The local lab

Cowrie runs on `127.0.0.1:2222` with the generated profile as its filesystem and
the realism overlay loaded. Built, started and stopped with `tests/lib/labctl.sh`.

```
tests/lib/labctl.sh lab_init                    # build lab/ from build/profile
tests/lib/labctl.sh lab_start | lab_stop | lab_restart
```

`lab_init` materialises the lab from the generated profile: the same filesystem,
process table, txtcmd overrides, credential policy and operator config that
`deploy/install.sh` stage 7 installs, with two deliberate differences — it
listens on the loopback interface and port 2222 rather than `0.0.0.0:22`, and it
runs as the invoking user rather than the `cowrie` service account. It is
idempotent, so re-running it after editing `realism/identity.yaml` refreshes the
lab. `lab_start` runs it automatically when `lab/etc/cowrie.cfg` is missing, so
the documented sequence works from a clean checkout; when Cowrie refuses to
start it prints the last lines of `lab/var/log/cowrie/lab-start.log` rather than
timing out silently.

`lab_stop` resolves the PID from the pidfile, and falls back to scanning `/proc`
for a `twistd` whose working directory is the lab. It **never** uses
`pkill -f twistd`, because that pattern also matches the shell running the
command and kills the test harness.

Sessions run over OpenSSH, not a library, because the point is to exercise
behaviour a real client produces. The client uses a single multiplexed
connection (`ControlMaster`) and drives real `ssh`, `scp` and `sftp`.

### The isolated test network

The lab is loopback-only and has no public exposure. Nothing in the test suite
opens a listener on a routable address. `test_conformance.py` connects to
`127.0.0.1` by default and takes `--host`/`--port` for use against a deployed
instance.

---

## 3. Test suites

### `tests/test_conformance.py` — the realism contract

198 checks across 16 categories, all derived from `expectations.json`, which is
generated from `realism/identity.yaml`. That derivation is the point: the test
does not hardcode "the hostname is `deploy-01`", it asserts that the hostname
reported by `hostname`, by `uname -n`, by `/etc/hostname` and by the SSH banner
are **the same value the manifest declares**. Change the manifest, and the tests
follow.

| Category | What it covers |
|---|---|
| `identity` | Hostname, kernel, OS release and SSH banner agree across every channel |
| `consistency` | Facts reported through different commands agree (`/proc/version` vs `uname`; no VMware artefacts) |
| `cpu` | `/proc/cpuinfo`, `lscpu`, `nproc` agree on model, socket/core counts and cache |
| `memory` | `/proc/meminfo`, `free` agree; `/run` and `/dev/shm` sizes follow `MemTotal` |
| `storage` | `df`, `mount`, `/etc/fstab`, `/proc/mounts`, `/etc/mtab`, `lsblk` all describe one disk |
| `network` | `ifconfig`, `ip addr`, `netstat -rn`, `/etc/resolv.conf` agree; no link-local leaks |
| `accounts` | `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/home`, `id` agree |
| `processes` | `ps aux` and `ps -ef` render the configured table with parsable columns |
| `services` | `systemctl` and `ss` are functional and consistent with an active sshd |
| `logs` | Planted logs exist, are non-empty, and `last` works |
| `commands` | 108 checks: every supported command runs and produces output rather than an error |
| `leakage` | 16 negative checks that nothing about the real host is visible |
| `realism` | Absence of specific historical tells (`mountall.sh`, `lightdm`, `whoopsie`, `open-vm-tools`) |
| `canary` | The canary set is defined and available to `ops/canary_scan.sh` |
| `interop` | SSH client interoperability, including the known paramiko limitation |

**Severity model.** Every check carries `high`, `medium`, `low` or `info`. The
suite exits non-zero only for failures above `info`. This exists so that a known
and documented divergence can stay visible without making the suite red — a
permanently failing test gets ignored, which is how real regressions hide.

**The leakage checks are the ones to read first.** They assert that a visitor
cannot see: the `cowrie` account or any Cowrie path, `/.dockerenv`, `twistd` or
`cowrie` on `PATH`, the repository path or honeypot directory in the environment
or in `/proc/self/environ`, any build directory, link-local addresses, or
artefacts of the software that implements the honeypot.

### `tests/test_playback.py` — the reviewer's safety contract

32 tests. The claim under test: **a recording controlled by an attacker cannot
affect the person reviewing it, and a captured secret is not displayed by
default.**

Includes a deliberately hostile recording containing ANSI escapes, an OSC 52
clipboard write, a bidirectional override, `<script>` markup, an attempted
`</script>` breakout, null bytes, and invalid UTF-8 — all in one session. Also
covers path traversal through a poisoned log line, truncated logs and truncated
recordings, refusal to bind publicly, and the response headers.

See `docs/07-session-playback.md` §4 for the mapping between each attack and its
test.

### `tests/probe_discovery.py` — the exploratory sweep

An 84-command sweep an operator might run, used to find inconsistencies that
were not yet encoded as checks. Output is kept under `lab/probe*/` for
before/after comparison. This is where the defects that later became fixes were
originally found.

```bash
python3 tests/probe_discovery.py --out lab/probe
```

The defaults are the shipped credential policy: `deploy` with the synthetic
password from `config/userdb.txt`. The sweep also attempts the pairs that policy
must reject (`root/root`, `admin/admin`, `test/test`, `svc-backup/svc-backup`)
and records, per attempt, whether the observed outcome matched the expected one.
A mismatch fails the run, because a divergence there means the honeypot is
either accepting credentials it must not or refusing ones the operator
configured. Override with `--user`/`--password` if you changed the allow-list.

---

## 4. Manual test procedures

Automated checks cannot cover everything. These are the procedures that must be
run by hand.

### T1 — Credential policy

| Input | Expected |
|---|---|
| `deploy` / `deploy` | Accepted — shell session |
| `deploy` / `Sunrise-Ledger-1972` | Accepted — shell session |
| `deploy` / `wrongpass` | Rejected, `cowrie.login.failed` recorded |
| `root` / `root` | Rejected — consistent with `PermitRootLogin prohibit-password` |
| `root` / `toor` | Rejected |
| `admin` / `admin` | Rejected, `cowrie.login.failed`, and `Failed password for invalid user admin` in the log |
| `svc-backup` / anything | Rejected — consistent with `/usr/sbin/nologin` |
| `test` / `test` | Rejected. **If this succeeds, the credential policy is wrong** — it means the wildcard rule is still in force |

### T2 — Interaction types

* **Interactive shell** — connect with a PTY, run commands, verify a recording is
  written and a transcript is derivable.
* **Exec** — `ssh host 'uname -a'`, verify output and that
  `cowrie.command.input` is recorded.
* **SCP and SFTP upload** — upload a small synthetic file, verify it lands in
  `var/lib/cowrie/downloads/` under its SHA-256, that the event records the
  original filename, and that **nothing executed it**.
* **SFTP download** — attempt to download a file, verify the attempt is
  recorded.
* **Disconnection** — kill the client mid-session, verify the recording is
  complete up to that point and the session is closed in the log.

### T3 — State coherence within a session

Create a file, `chmod` it, `cat` it back, `ls -l` it, and confirm the reported
size and mode agree with what was written. Repeat an inspection and confirm the
answer is identical. An attacker who sees a file's content change between two
`cat` invocations has found the honeypot.

### T4 — Log forwarding

Confirm evidence reaches the evidence store: objects present, manifest
matching, `duplicate` fields sane, and that local pruning happened only after a
verified upload.

### T5 — Resource exhaustion

* Upload past `QUARANTINE_WARN_MB` and confirm the alert fires and pruning
  preserves the event record.
* Send a very long command line and confirm it is bounded by `max_input_size`.
* Send an unbounded traversal (`find /`) and confirm the documented wedge
  behaviour (see `docs/10`) — then recover with
  `systemctl kill -s SIGKILL cowrie`.

### T6 — Isolation

The full verification block in `deploy/aws/security-groups.md` §6. **All of
those commands should fail.** Run them after every network change and record the
output.

### T7 — Playback review

Start the playback service, reach it over SSM, and confirm: sessions list,
terminal replays, transcript searches, transfer rows seek, secrets are masked by
default, and `?unmask=1` reveals them.

---

## 5. What would count as a failure

Anything in this list is a release blocker:

1. Any leakage check failing — real host data, real paths, or honeypot software
   visible inside the emulated shell.
2. Any consistency check failing above `info` — two channels disagreeing about
   the same fact.
3. Any command returning `cannot execute binary file: Exec format error` or an
   unrelated payload. An operator running `df` and getting an execution error
   has found the honeypot in one command.
4. A command whose output cannot be parsed.
5. A recorded secret appearing in the playback UI without `?unmask=1`.
6. The playback UI binding to a non-loopback address without the explicit flag.
7. Any of the isolation checks in T6 succeeding.
8. A captured file being executed, opened, or previewed anywhere on the
   honeypot host.
9. A test that passes only because a command failed. Every output-parsing check
   must also assert the command produced output.

---

## 6. What this plan does not test

Stated plainly, because a test plan that overstates its coverage is worse than a
short one:

* **Detectability by a determined analyst.** The suite checks internal
  consistency, not indistinguishability from a real host. `/proc` is not backed
  by the emulated filesystem; timing differs from a real kernel; there is no
  real scheduler. `docs/10` enumerates the signals.
* **Adversarial behaviour at scale.** Load testing is limited to the resource
  bounds above. No test drives thousands of concurrent sessions.
* **The QEMU high-interaction mode.** Not implemented — see `docs/12`.
* **The kernel, Twisted or Cowrie having a vulnerability.** Out of scope by
  construction; mitigated by isolation, not prevented.
* **AWS misconfiguration.** The isolation tests verify reachability, not that
  the security group, route table and IAM policy are otherwise well-formed.
* **Legal or policy compliance.** Yours to confirm.

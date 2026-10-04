# 09 — Test results

**Run:** 2026-10-04, against the local lab instance
(`tests/lib/labctl.sh lab_start`, `127.0.0.1:2222`), Cowrie 3.1.0 at commit
`6ec36d0d5d4a1a14bc6e6ddadcb7b8f255e0570b`.

> **Scope of these results.** Everything below was measured on the build
> machine against a loopback listener. **The package has never faced the
> internet.** Real scanners behave differently from a test harness, and the
> first hours of real traffic will teach you things this suite cannot. Treat
> these numbers as "the internal consistency holds", not as "it works in
> production".

---

## 1. Summary

| Suite | Result | Notes |
|---|---|---|
| `realism/build_profile.py` | **exit 0**, 6/6 invariants | Generates 25 artefacts |
| `tests/test_conformance.py` | **196 / 197 pass**, 0 actionable failures | 1 `info`-severity interop note |
| `tests/test_playback.py` | **32 / 32 pass** | Includes a hostile-recording test |
| `deploy/install.sh` (dry run) | **exit 0**, full 10-stage plan printed | No changes made |
| `deploy/uninstall.sh`, `deploy/rebuild.sh` | `bash -n` clean | Not executed — they are destructive |
| Shell scripts (`ops/*.sh`, `deploy/*.sh`) | `bash -n` clean | All |

Reproduce:

```bash
.venv/bin/python realism/build_profile.py --identity realism/identity.yaml --out build/profile
bash tests/lib/labctl.sh lab_restart
python3 tests/test_conformance.py --expect build/profile/expectations.json --json lab/conformance.json
python3 tests/test_playback.py
bash deploy/install.sh                      # dry run
```

---

## 2. Profile build

```
accounts: deploy, svc-backup (plus 22 system accounts)
core identity files written: 22
home directories created: 2
decoy documents planted: 4
service logs planted: 5
txtcmd overrides written: 20
commands added to filesystem: 6
forbidden paths removed: /.dockerenv
process table entries: 65
normalised 1 inherited size/content mismatch(es):
  - /proc/modules (0 -> 3842)

INVARIANT 1 ok: every embedded file's size matches its content length
INVARIANT 2 ok: no forbidden path present in the finished filesystem
INVARIANT 3 ok: SSH banner and `ssh -V` both report OpenSSH 9.2p1 Debian-2+deb12u3
INVARIANT 4 ok: /run and /dev/shm sizes are consistent with MemTotal
INVARIANT 5 ok: df disk arithmetic closes (used < size)
INVARIANT 6 ok: all decoy/log owners resolve to a generated account
```

Invariant 2 is what removes `/.dockerenv`, which ships with Cowrie's bundled
filesystem and is an immediate "this is a container" tell. Invariant 1 is what
makes `ls -l` agree with `cat`.

---

## 3. Conformance suite

```
TOTAL: 196/197 passed
Actionable failures (severity != info): 0

Severities: high 176, medium 18, info 3
```

### By category

| Category | Pass | Fail | What it establishes |
|---|---:|---:|---|
| `commands` | 108 | 0 | Every supported command runs and produces parsable output |
| `leakage` | 16 | 0 | Nothing about the real host is visible |
| `storage` | 12 | 0 | `df`, `mount`, `/etc/fstab`, `/proc/mounts`, `/etc/mtab` describe one disk |
| `identity` | 10 | 0 | Hostname, kernel, OS and banner agree across every channel |
| `network` | 8 | 0 | `ip addr`, `ifconfig`, `resolv.conf` agree; no link-local leaks |
| `cpu` | 7 | 0 | `/proc/cpuinfo`, `lscpu`, `nproc` agree |
| `logs` | 7 | 0 | Planted logs exist and are non-empty; `last` works |
| `accounts` | 6 | 0 | `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/home`, `id` agree |
| `realism` | 6 | 0 | No Debian-7-era service names |
| `processes` | 5 | 0 | `ps aux` and `ps -ef` render the configured table |
| `consistency` | 4 | 0 | Cross-command agreement |
| `memory` | 4 | 0 | `free` agrees with `/proc/meminfo` |
| `services` | 2 | 0 | `systemctl` and `ss` functional |
| `canary` | 1 | 0 | Canary set available to `ops/canary_scan.sh` |
| `interop` | 0 | 1 | Known paramiko limitation — `info` severity |

### The one failure

```
[info] interop: paramiko exec interop
       paramiko could not complete an exec request: paramiko not installed
```

`info` severity, and it does not fail the build. Two notes:

* In this environment the cause is simply that paramiko is not installed in the
  test interpreter. With paramiko present the check runs and reports a **real,
  documented incompatibility**: Cowrie 3.1.0 closes an exec channel within a few
  milliseconds, and paramiko can observe the channel close before it processes
  the exec acknowledgement, raising `SSHException: Channel closed.` Standard
  OpenSSH clients are unaffected — every other check in the `commands` and
  `interop` categories drives a real `ssh` binary and passes.
* This is worth knowing for two reasons. It is a **detection signal**: an
  attacker whose toolkit uses paramiko will see anomalous behaviour, and it is
  listed in `docs/10`. It is also why the test harness itself is built on
  OpenSSH rather than on a Python SSH library.

### Fixed during this work

Each of these was found by the sweep, fixed, and is now covered by a check:

| Defect | Was | Now |
|---|---|---|
| `free` read the **real** host's `/proc/meminfo` | Leaked the real instance's RAM; contradicted the emulated `/proc/meminfo`; `free -m` even contradicted `free -k` because it divided by 1000 not 1024 | Emulated values, procps-style units, **plus** a systemd bind-mount masking the real file — so the leak stays closed even with the overlay disabled |
| `ps aux` truncated to `COLUMNS` (80) | Silently deleted the TIME and COMMAND columns | All 11 columns; short or full command by `COLUMNS` |
| `ps aux` START column | Hardcoded `Jul22`/`06:30`, contradicting `uptime` and `last` | Derived from the emulated boot time |
| `ps -ef` / `ps -e` / `ps -f` | Returned two rows unrelated to the configured process table | Renders the configured table in `-ef` form |
| `service --status-all` | Hardcoded Debian 7 list: `cups`, `lightdm`, `open-vm-tools`, `whoopsie`, `mountall.sh` | Consistent with the emulated systemd service list |
| `/.dockerenv` | Present in the bundled filesystem | Removed by build invariant 2 |
| `/etc/fstab`, `/etc/mtab`, `/etc/ssh/sshd_config`, `/etc/os-release` | `ls -l` reported a size but `cat` printed nothing | Generated with content, size normalised |
| `df`, `mount`, `dmesg`, `top`, `lscpu`, `nproc`, `dpkg`, `systemctl`, `ss`, `ip` | Served the wrong payload, or `cannot execute binary file: Exec format error` | 20 txtcmd overrides installed under the correct paths |
| `ifconfig` / `netstat -rn` | Reported the real instance's address | `internet_facing_ip` / `fake_addr` pinned in config |
| `/var/log/auth.log`, `/var/log/syslog`, `/etc/crontab` | Missing on a host that should have them | Planted service logs |

### Defects found and fixed in the tooling itself

| Defect | Consequence | Fix |
|---|---|---|
| A `sitecustomize` patch called `self._emit(...)` on a nested *function* | `AttributeError` inside a command handler wedged the Twisted reactor: the session hung, the process ignored `SIGTERM`, the port stayed bound | Nested calls invoked correctly, **and every patched entry point wrapped in `try/except` falling back to stock behaviour** |
| `deploy/install.sh` used `act ... > file` | The shell performed the redirect at call time, so even a **dry run** tried to create a file in a directory that did not exist — aborting the plan and hiding stages 8–10 | Redirection moved inside the command string |
| `free` reported kernel-thread `TIME` as a bare float | `ps` output was not parsable as `ps` output | Rendered as `0:00` (procps `mm:ss`) |
| `ops/canary_scan.sh` excluded its own manifest by name | Could mask a real canary match | Explicit path exclusion |

---

## 4. Playback suite

```
Ran 32 tests — OK
```

Including the hostile-recording test, which is the one that matters: a single
crafted session containing ANSI escapes, an OSC 52 clipboard write, a
bidirectional override, `<script>` markup, an attempted `</script>` breakout,
null bytes and invalid UTF-8. The assertions are that the served page contains
**no raw markup characters**, that the payload is still valid JSON, that the CSP
nonce on the header matches the one on the script tag, and that no captured
secret appears without `?unmask=1`.

Also verified: a poisoned `cowrie.json` claiming a recording at
`../../../../etc/shadow` and at `/etc/hostname` yields **no chunks** — the
viewer refuses to leave the recordings directory.

---

## 5. Behaviour verified by hand

| Check | Result |
|---|---|
| `deploy/deploy` login | Accepted; shell session recorded |
| `deploy/Sunrise-Ledger-1972` login | Accepted |
| `root/root`, `root/toor`, `admin/admin`, `test/test` | Rejected; `Failed password for invalid user` recorded |
| `svc-backup` with any password | Rejected |
| SFTP upload | Captured under its SHA-256; original filename in the event record; nothing executed |
| SCP upload | Same |
| Session recording | Written, renamed to the input hash, `duplicate` field correct |
| Recording deduplication | 24 of 139 sessions in the lab shared a recording with an earlier session, correctly reported rather than shown as "missing" |
| Bind-mount of synthetic `/proc/meminfo` | Verified in a mount namespace: synthetic values visible inside, real file unaffected outside |
| Playback UI, 139 sessions | Rendered; terminal replay, transcript search and transfer seeking all functional |
| `install.sh` dry run | Full 10-stage plan printed; no changes made |

---

## 6. Not tested

Restating the honest gaps, because a results table implies more than it should:

* **No internet exposure.** No real attacker traffic has ever reached this
  configuration.
* **No fingerprint test against a real Debian 12.5 host.** The consistency
  checks compare channels *within* the honeypot, and compare against the
  manifest. They do not compare against a genuine Debian installation. A
  difference that is internally consistent but wrong on a real host would pass.
* **`/proc` is not backed by the emulated filesystem.** Files not explicitly
  generated come from Cowrie's bundled data or are absent. `docs/10` lists this
  as the largest remaining signal.
* **No load test.** Resource bounds are enforced by systemd and by Cowrie's
  limits; they were not exercised with thousands of concurrent sessions.
* **QEMU high-interaction mode is not implemented.** Design only — `docs/12`.
* **The destructive scripts were not run.** `uninstall.sh --remove` and
  `rebuild.sh` were syntax-checked, not executed, because executing them
  destroys the evidence these tests depend on.

---

## 7. Re-verification after the packaging fixes

**Run:** 2026-10-04, from a clean checkout on the same build machine. Sections 1
to 6 above are unchanged; this section records what was re-run and what it found.

Every suite was re-executed against a freshly generated profile and a freshly
initialised lab (`lab_init`, `127.0.0.1:2222`, Cowrie 3.1.0 at the pinned commit):

| Suite | Result |
|---|---|
| `realism/build_profile.py` | exit 0, 6/6 invariants |
| `tests/test_conformance.py` | **196 / 197**, 0 actionable — the same `info` interop note |
| `tests/test_playback.py` | **32 / 32** |
| `tests/test_dashboard.py` | **47 / 47** |
| `tests/probe_discovery.py` | 84 commands, exit 0; all credential-policy expectations met; no host leakage in the output |
| `deploy/install.sh` (dry run) | exit 0, all 10 stages printed |
| `deploy/install.sh --apply` | stages 1, 3, 4, 5, 6, 9, 10 executed in a scratch `STATE_DIR`; see the limitations below |
| `ops/*.sh` | `canary_scan` clean **and** planted-canary control, `prune_local` refusal paths, `quarantine_sync` missing-bucket guard, `alert_dispatch` local fallback, `healthcheck` against the lab |

### Defects found by the re-verification, and fixed

| # | Where | Was | Now |
|---|---|---|---|
| 1 | `deploy/versions.env` | **Missing from every clone, and the cause was `.gitignore`**: the `*.env` rule (meant for secret-bearing files) matched `deploy/versions.env`, so the pin file was silently never committed. `install.sh`, `uninstall.sh`, `rebuild.sh` and `quarantine_sync.sh` all died on their first `source` line, so the documented dry run never printed a plan | `.gitignore` now carries an explicit `!deploy/versions.env` exception (`cowrie-logship.env` stays ignored). The file itself is restored: Cowrie commit pin, PyYAML pin, Python floor, layout and retention defaults. Operational knobs use `${VAR:-default}`, so `/etc/cowrie-logship.env` keeps the documented precedence over the shipped default |
| 2 | `tests/lib/labctl.sh` | Nothing created `lab/etc/cowrie.cfg`, so the documented `lab_restart` could never start Cowrie; it failed silently after a 20 s wait | `lab_init` builds the lab from `build/profile`; `lab_start` runs it when the lab is missing and prints the captured startup log on failure |
| 3 | `tests/probe_discovery.py` | Default credentials were Cowrie's stock `phil`/`fout`, which `config/userdb.txt` deliberately denies — the documented sweep could not authenticate | Defaults are the shipped policy; the auth probes record expected vs observed and fail the run on a divergence |
| 4 | `ops/healthcheck.sh` | The banner check read a fixed byte count (`head -c 128`) from a connection the honeypot keeps open: it blocked for the full 10 s timeout and lost its buffered output, so **every run raised the P1 `ssh_no_banner` alert on a healthy honeypot** and the check could never report healthy | Reads one line with a timeout. Verified against the lab: 0.23 s, no false alert |
| 5 | `deploy/install.sh` | (a) `--apply --stage N` for N≠4 exited 127 with **no message**, because the installed-version check ran before the virtualenv existed. (b) Stage 3 was not idempotent: a second `--apply` died on `useradd: user 'cowrie' already exists`, contradicting the header's promise of safe re-runs | (a) the check is skipped with a warning when there is no virtualenv to inspect. (b) the account is created only when it does not already exist |
| 6 | `deploy/systemd/cowrie-healthcheck.service` | Did not load `/etc/cowrie-logship.env`, so the operator knobs documented as reaching `healthcheck.sh` (`QUARANTINE_WARN_MB`, `QUARANTINE_CRITICAL_MB`) never did | `EnvironmentFile=-/etc/cowrie-logship.env` added, optional so a host without the file still runs the check |

None of these change the emulated host: the profile, the credential policy and
the realism overlay are untouched, and the conformance result is identical
before and after.

### Limits of this re-verification

* **Stage 2 could not run**: this machine's package mirror has no
  `python3-dev`, `libffi-dev`, `libssl-dev` or `rsync`. Stage 7 therefore
  completed every install step except its final `rsync` of the package copy,
  and stage 8 (systemd units) cannot run without a systemd bus. The stages that
  did run executed for real against a scratch `STATE_DIR`, not as a dry run.
* **Still no internet exposure, no load test and no comparison against a real
  Debian 12.5 host** — the gaps in section 6 stand.
* **The dashboard has no page in `docs/`.** Its behaviour is covered by
  `tests/test_dashboard.py` (47 tests) and `AUDIT.md`; the open findings there
  (F-03 to F-11) are unchanged by this work.

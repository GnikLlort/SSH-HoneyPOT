# 04 — Configuration reference

Two layers of configuration, and it matters which one you edit.

| Layer | File | Edit it when… |
|---|---|---|
| **The identity manifest** | `realism/identity.yaml` | The fake machine should look different: hostname, OS version, CPU, memory, disk, accounts, decoy documents, canaries, alert thresholds |
| **Operator config** | `config/cowrie.cfg` | You want to change Cowrie behaviour that is not derived from the identity |

Everything a visitor can observe is generated from `realism/identity.yaml` by
`realism/build_profile.py`. Do not hand-edit generated artefacts: the next
build overwrites them, and hand-edits are how the contradictions this design
exists to prevent get introduced.

---

## 1. The identity manifest

### Why it is one file

The most common way a honeypot is unmasked is not a bug — it is two answers to
the same question disagreeing. `uname -r` says one kernel while `/proc/version`
says another. `ls -l /etc/fstab` reports 37 bytes while `cat /etc/fstab` prints
nothing. `ssh -V` reports Debian 10 while the banner says Debian 12.

Generating every observable from one manifest turns those contradictions into
build errors.

### Fields

| Field | Drives |
|---|---|
| `identity.hostname` | `[honeypot] hostname`, `/etc/hostname`, the `127.0.1.1` line in `/etc/hosts`, `hostname`, `uname -n`, the shell prompt |
| `identity.domain` / `fqdn` | `/etc/hosts`, `/etc/resolv.conf` search domain, TLS-less hostnames in logs. Uses RFC 6761 reserved TLDs, so it can never resolve to a real domain |
| `identity.role` | Keeps decoy documents, planted service logs and the installed-package list on-message |
| `identity.timezone` | `[honeypot] timezone`. UTC, so honeypot logs correlate with CloudTrail and VPC flow logs without arithmetic. Note the *emulated* machine also claims UTC; changing one without the other is a contradiction |
| `os.kernel_abi` + `os.kernel_build_string` | `uname -r`, `uname -v`, `/proc/version`. **These must stay paired** |
| `os.openssh_banner` + `os.openssh_shell_version` + `os.openssh_package_version` | The SSH banner, `ssh -V`, and `dpkg -l`. The build fails if the banner and the shell string disagree |
| `os.point_release` | `/etc/debian_version` |
| `os.boot_offset_seconds` | `[honeypot] boot_offset`, and therefore `/proc/uptime`, `uptime`, `last`, and the `ps` START column. **Pinned** rather than left to Cowrie's random 1–90 day default so all of these describe one boot event |
| `hardware.*` | `/proc/cpuinfo`, `lscpu`, `nproc`, `/proc/meminfo`, `free`, `lsblk`, and the sizes of `/run` and `/dev/shm` |
| `storage.*` | `df`, `mount`, `/etc/fstab`, `/proc/mounts`, `/etc/mtab`, `lsblk` |
| `network.*` | `ifconfig`, `ip addr`, `netstat -rn`, `/etc/resolv.conf`, and `[honeypot] internet_facing_ip` / `fake_addr` |
| `accounts[]` | `/etc/passwd`, `/etc/group`, `/etc/shadow`, home directories, `~/.bashrc`, `~/.profile`, `~/.ssh/known_hosts`, file ownership |
| `filesystem.decoys[]` | Harmless documents planted in the fake filesystem |
| `filesystem.logs[]` | Planted service logs under `/var/log` |
| `filesystem.canaries[]` | Unique markers that must never appear outside the emulated filesystem |
| `alerts.*` | Thresholds consumed by the generated expectations and the alert rules |

### Invariants enforced at build time

`realism/build_profile.py` refuses to produce a profile that violates any of
these, and prints the reason:

1. Every embedded file's `A_SIZE` equals the length of its content. (This is
   what makes `ls -l` agree with `cat`.)
2. No forbidden path is present. This is how `/.dockerenv` — which ships with
   the Cowrie base image and is an immediate "this is a container" tell — is
   removed.
3. The SSH banner and `ssh -V` report the same OpenSSH release.
4. `/run` and `/dev/shm` sizes are consistent with `MemTotal`.
5. `df` arithmetic closes: used + available = size, used < size.
6. Every decoy and log owner resolves to a generated account.

### Rebuilding after a change

```bash
.venv/bin/python realism/build_profile.py \
    --identity realism/identity.yaml --out build/profile
```

Outputs, all derived:

```
fs.pickle              the emulated filesystem, including embedded file contents
cmdoutput.json         the process table behind `ps`
cowrie-profile.cfg     config fragment: identity values for Cowrie
expectations.json      what the conformance suite asserts
procfs/meminfo         a synthetic /proc/meminfo (see §3)
txtcmds/               command output overrides
BUILD-REPORT.txt       what was generated, and the invariant results
```

On the deployed host the same build writes to `/opt/cowrie/build/profile`, and
the artefacts are installed into `/opt/cowrie/var/lib/cowrie/` and
`/opt/cowrie/share/txtcmds/`.

---

## 2. Operator config — `config/cowrie.cfg`

Installs to `<state>/etc/cowrie.cfg`. It contains **overrides only**: Cowrie 3.x
loads its bundled `cowrie.cfg.dist` as a defaults layer first.

> **Do not start from `cowrie init` output.** `cowrie init` writes the entire
> 49 KB template. Appending your own section then duplicates it, and Cowrie
> refuses to start with `DuplicateSectionError: section 'ssh' already exists`,
> which twistd reports as the thoroughly unhelpful
> `twistd --umask=0022: Unknown command: cowrie`.

### Values marked GENERATED

These are also written to `<state>/etc/profile.cfg` by the profile builder.
They are repeated in `cowrie.cfg` so that file is a complete readable
description of the deployment. **If the two disagree, `profile.cfg` wins**,
because it is included second. When changing one of these, change
`realism/identity.yaml` and rebuild.

| Setting | Shipped value | Note |
|---|---|---|
| `[honeypot] hostname` | `deploy-01` | Must equal the manifest |
| `[honeypot] boot_offset` | `1209600` | 14 days |
| `[honeypot] internet_facing_ip`, `fake_addr` | `10.20.30.40` | **Mandatory.** If unset, Cowrie derives the address shown by `ifconfig` and `netstat -rn` from the host's real outbound socket, so the honeypot advertises the address of the instance it actually runs on |
| `[ssh] version` | `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3` | Must match `ssh -V` and `dpkg -l` |
| `[shell] ssh_version`, `kernel_version`, `kernel_build_string`, `hardware_platform`, `operating_system`, `arch` | Debian 12.5 / 6.1.0-21-amd64 | |

### Choices worth understanding

**`[honeypot] txtcmds_path` is under `[honeypot]`, not `[shell]`.** Putting it
under `[shell]` silently does nothing: the affected commands then fall through
to Cowrie's binary-format emulation and answer
`cannot execute binary file: Exec format error` — an immediate tell. This trap
cost real debugging time; it is called out here because it is easy to repeat.

**`[ssh] listen_endpoints = tcp:22:interface=0.0.0.0`.** Port 22, not Cowrie's
default 2222. A host that answers SSH on 22 *and* 2222 is a honeypot that has
not finished configuring itself.

**`[ssh] sftp_enabled = true`.** File transfers are among the highest-value
events recorded. Every upload is quarantined, never run.

**`[ssh] forwarding = true`, but `forward_redirect` and `forward_tunnel` stay
`false`.** Cowrie answers direct-tcpip channel requests inside the emulated
protocol. Setting either of the other two would send a visitor's traffic to a
real destination, turning the honeypot into a proxy into networks it exists to
be isolated from. Do not enable them.

**Authentication flags are all disabled.** No `auth_publickey_allow_any`, no
`auth_none_enabled`, no keyboard-interactive. Each would let a client in without
presenting a credential, which removes the authentication telemetry this
deployment exists to collect.

**`[shell]` limits** — `max_input_size = 16384`, `parse_timeout_seconds = 10`,
`gc_collect_threshold = 512`, `scp_max_files_per_session = 20`. These bound how
much work one visitor can cause and are the reason a single session cannot
trivially exhaust the process.

**`[llm] backend = shell`.** See `docs/13-llm-mode-review.md`. Enabling it sends
every command a visitor types to a third-party model provider and returns
non-deterministic output that cannot be kept consistent with the manifest.

**Every other output plugin is `enabled = false`.** Several of them (VirusTotal,
GreyNoise, DShield, Slack, Telegram, Discord, AbuseIPDB) transmit data about a
visitor to a third party by design. See `docs/06`.

---

## 3. The `/proc/meminfo` problem, and how it is solved

Stock Cowrie's `free` command reads the **real host's** `/proc/meminfo`
(`cowrie/commands/free.py`), and divides by 1000 rather than 1024, so `free -m`
disagreed with the emulated `/proc/meminfo` *and* leaked the real instance's RAM
to the visitor.

Configuration cannot fix this, because the code path never consults
`CowrieConfig`. Two mechanisms address it:

1. **`realism/procfs/meminfo`** — a synthetic `/proc/meminfo` generated from
   `hardware.memory`, installed to `/opt/cowrie/share/synthetic/meminfo`.
2. **A mount namespace bind** in `cowrie.service`:

   ```ini
   BindReadOnlyPaths=/opt/cowrie/share/synthetic/meminfo:/proc/meminfo
   ```

   systemd applies this inside the service's private mount namespace, so the
   honeypot process sees the synthetic file at `/proc/meminfo` and **cannot see
   the real one**. The rest of the host is unaffected.

Because the same file backs both `free` and the emulated `/proc/meminfo`, they
cannot disagree, and the real host's memory is not observable at all.

> The overlay's `install_free_patch()` also renders `free` in procps style
> (`Mi`/`Gi` units) from the emulated values. The bind mount is what makes the
> *stock* path safe as well, so the two are complementary: if the overlay fails
> to load, the bind mount still prevents the leak.

---

## 4. The realism overlay

`overlays/cowrie_realism_overlay/` fixes four defects that configuration cannot
reach, each of which is a one-command fingerprint:

| Command | Stock behaviour | Fixed behaviour |
|---|---|---|
| `free` | Reads the **real** host `/proc/meminfo`; divides by 1000 not 1024 | Emulated values, procps-style units |
| `ps aux` | Truncates every line to `COLUMNS` (default 80), silently deleting the TIME and COMMAND columns; appends rows hardcoded to `Jul22`/`06:30` regardless of the emulated boot time | All 11 columns, short-or-full command by `COLUMNS`, START derived from the emulated boot |
| `ps -ef`, `ps -e`, `ps -f` | Returns a two-row list unrelated to the configured process table | Renders the configured table in `-ef` form |
| `service --status-all` | Returns a hardcoded Debian 7-era list (`cups`, `lightdm`, `open-vm-tools`, `whoopsie`, `mountall.sh`) on a host claiming to run systemd on Debian 12 | Consistent with the emulated service list |

### How it is applied

Nothing in the installed Cowrie tree is modified. The directory is placed on
`PYTHONPATH`; CPython imports `sitecustomize` automatically at interpreter
startup, which calls `apply()`.

```
PYTHONPATH=/opt/cowrie/share/overlay
COWRIE_REALISM_OVERLAY=1
```

`verify_targets()` checks that the classes and methods being patched still
exist, and refuses to load rather than half-applying against a different
release. It is pinned to Cowrie 3.1.0
(`6ec36d0d5d4a1a14bc6e6ddadcb7b8f255e0570b`).

### The fallback rule, and why it matters more than the fix

During development, a patch raised `AttributeError` inside a command handler.
The exception propagated into the Twisted reactor, which left the session open
and the process unresponsive: it ignored `SIGTERM`, kept the port bound, and
required `SIGKILL`. A wrong-looking `ps` is cosmetic; a wedged reactor takes the
honeypot down.

Every patched entry point is therefore a thin `try/except` wrapper that falls
back to the original implementation and logs a warning:

```python
def call(self) -> None:
    try:
        self._render_ps(now=time.time())
    except Exception:
        log.warn(...)
        _ORIGINAL_PS_CALL(self)
```

**If you extend the overlay, preserve this rule.** A patch that can raise inside
a command is worse than no patch.

### Reverting

Remove the two environment lines from `deploy/systemd/cowrie.service`, run
`systemctl daemon-reload && systemctl restart cowrie`. Cowrie then behaves
exactly as the pinned upstream release. Set `COWRIE_REALISM_OVERLAY=0` to
disable it without editing the unit.

---

## 5. Credential policy — `config/userdb.txt`

Installs to `<state>/etc/userdb.txt`. Format: `username:x:password`, where `*`
is a wildcard, `!` denies, and processing stops at the first match.

Cowrie's built-in default ends with `*:x:*` — every username with every
password is accepted. With that in force, every login succeeds, which means:
an operator typing `test`/`test` learns immediately that no authentication took
place, and the `authentication_result` field becomes worthless because nothing
ever fails.

The shipped file is an explicit allow-list:

| Rule | Effect | Why |
|---|---|---|
| `root:x:!*` | Root cannot log in by password | Makes the generated `sshd_config` (`PermitRootLogin prohibit-password`) truthful |
| `deploy:x:<5 weak passwords>` | The operator account is reachable | Ordinary brute-force occasionally succeeds, which yields a shell session to record |
| `svc-backup:x:!*` | The service account cannot log in | Its `/usr/sbin/nologin` shell says so |
| `*:x:!*` | Everything else denied | Unknown usernames produce `Failed password for invalid user <name>`, the same sequence a real host emits |

**Review before deployment.** Deleting all but the first `deploy` line makes the
account reachable only with the synthetic password — the strictest
configuration, and the one to choose if you want successful logins to be rare
and therefore high-signal.

The passwords are synthetic. They are deliberately weak because a honeypot must
occasionally be crackable to be useful. **Never put a real credential here, and
never reuse one of these passwords anywhere real.**

---

## 6. Limits and hardening

| Setting | Where | Default | Purpose |
|---|---|---|---|
| `idle_timeout` | `[honeypot]` | 300 | Releases resources from scanners that authenticate and go quiet |
| `authentication_timeout` | `[honeypot]` | 120 | Disconnects a client that never authenticates |
| `download_limit_size` | `[honeypot]` | 67108864 (64 MiB) | Stops one enormous upload filling the volume |
| `max_input_size` | `[shell]` | 16384 | Bounds one command line |
| `parse_timeout_seconds` | `[shell]` | 10 | Bounds parsing work |
| `scp_max_files_per_session` | `[shell]` | 20 | Bounds transfer count |
| `MemoryMax`, `CPUQuota`, `TasksMax` | `cowrie.service` | see unit | Bounds the whole service |
| `QUARANTINE_WARN_MB`, `QUARANTINE_CRITICAL_MB` | `/etc/cowrie-logship.env` | 2048, 4096 | Aggregate capture budget, with alerts |

---

## 7. Things that are deliberately not configurable

**Third-party output plugins.** Enabling DShield, VirusTotal, GreyNoise or
AbuseIPDB transmits data about a visitor to a third party. That is a decision
about someone else's data, not a configuration preference, and it belongs in
`docs/06` rather than in a config file.

**`forward_redirect` / `forward_tunnel`.** Enabling either makes the honeypot a
proxy to a real destination. That directly contradicts the isolation
requirement, so it is documented as forbidden rather than offered as a knob, and
**now asserted by a test**: `tests/test_conformance.py` reads this file and fails
the suite if either value is anything but `false`
(`tests/lib/config_check.py`, also run by `tests/test_safety_guards.py`). The
distinction matters — `forwarding = true` is safe only while those two stay
false, so the safety of the deployment rested on two values that nothing
previously read.

**Auto-banning on connection.** There is no rule, anywhere, that blocks or
reports an IP merely for connecting to the honeypot. The honeypot exists to
receive those connections. See `ops/alerts/rules.md`.

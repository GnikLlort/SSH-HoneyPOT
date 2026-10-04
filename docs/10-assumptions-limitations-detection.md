# 10 — Assumptions, limitations and detection signals

This page exists because the honest answer to "can an attacker tell?" is **yes**.
The question worth answering is *how*, and *how much work it takes*.

A honeypot that claims to be undetectable is either lying or measuring the
wrong thing. This one is designed to survive ordinary inspection: an operator
who runs the discovery commands they always run, and reads the answers, gets a
consistent Debian 12.5 build server. An operator who looks specifically for
emulation will find it.

---

## 1. Assumptions

If any of these stop being true, revisit the design rather than the controls.

| # | Assumption | If it breaks |
|---|---|---|
| 1 | The instance is dedicated to the honeypot and holds nothing else | Real data becomes reachable from an attacker-facing service. Stop and use a different instance. |
| 2 | The VPC is dedicated, with no peering, transit gateway or VPN | The honepot can reach production. The isolation argument collapses. |
| 3 | The evidence bucket is in a separate AWS account, or is otherwise protected by a KMS key and Object Lock the honeypot cannot modify | A compromised honeypot can destroy or rewrite its own evidence. |
| 4 | No real credential is ever entered into the emulated shell, including during testing | A real password is now stored in `cowrie.json` on a disposable host and shipped to a bucket. |
| 5 | Anything uploaded by a visitor is treated as hostile and never opened on the honeypot or a normal workstation | The most likely way this deployment harms a person. |
| 6 | Someone reads the alerts | Telemetry that nobody reads is not security. |
| 7 | Third-party output plugins stay disabled | Captured credentials and files are transmitted to a commercial service. |
| 8 | Operating a honeypot is lawful where you are, permitted by your provider, and permitted by your organisation | Out of scope for this package. Yours to confirm. |

---

## 2. Limitations of emulated mode

### 2.1 The fundamental one

Cowrie emulates a shell in Python. There is no kernel, no scheduler, no real
processes, no real filesystem. It is a program that answers questions about a
Linux system. Anything that measures the *system* rather than asking about it
can distinguish the two.

This is not a bug to be fixed. It is the design, and it is also what makes the
mode safe: because nothing a visitor sends is executed, an entire class of risk
disappears. The trade is explicit — safety in exchange for realism.

### 2.2 `/proc` is not backed by the emulated filesystem

**This is the largest remaining signal**, and it is worth understanding
precisely.

`/proc/cpuinfo`, `/proc/meminfo`, `/proc/version`, `/proc/mounts` and
`/proc/modules` are generated and consistent. Most other `/proc` entries are
either absent or come from Cowrie's bundled data. So:

* Files that should exist on a real Debian 12 host are missing —
  `/proc/loadavg`, `/proc/stat`, `/proc/self/status`, `/proc/self/cmdline`,
  `/proc/uptime` (partially), and the per-PID directories.
* Where a file exists but is not backed by the emulated tree, `ls -l` can report
  a size while `cat` prints nothing. The build normalises known cases (it fixed
  `/proc/modules`, 0 → 3842 bytes) but cannot cover everything.

**What an attacker sees:** `ls /proc/self/` returning a short or wrong list, or
`cat /proc/loadavg` failing, on a host that otherwise looks healthy.

**Partial mitigation, not implemented:** setting `[honeypot] contents_path` to a
generated directory that mirrors the emulated tree would back more of `/proc`
from real content. It is a genuine improvement and the natural next step.

### 2.3 Timing

Every command is Python executing in a Twisted reactor. There is no real
scheduler arbitration, so:

* Command output may arrive in a burst rather than the paced writes a real shell
  produces.
* `time <command>` reports an emulated value, but wall-clock observation of a
  streamed command does not match a real kernel's behaviour.
* An attacker who runs `ping` in one session and watches how the reactor behaves
  under load in another can infer a shared event loop.

Not mitigated. A QEMU guest pool is the answer (`docs/12`).

### 2.4 The reactor wedge

**A single pathological command can make the honeypot unresponsive.** An
unbounded traversal such as `find /` inside the emulated filesystem can wedge the
Twisted reactor. The observed behaviour:

* the session hangs;
* the process **ignores `SIGTERM`** and must be `SIGKILL`ed;
* the listening port stays bound, so the service appears to be up;
* TCP connections are accepted but the SSH banner is never sent.

This is a real availability weakness. An attacker who discovers it can silence
the honeypot while leaving it looking alive.

**Mitigations in place:** the health check reads the SSH banner rather than
checking the port, specifically to catch this; `TimeoutStopSec=20` with
`KillMode=mixed` escalates the stop; `Restart=always` brings it back;
`labctl.sh` uses the same escalation for tests. **Not fixed** — fixing it means
patching Cowrie's command dispatch, which trades a known availability problem
for an unknown one.

### 2.5 Commands with no implementation

These have no emulated behaviour and produce a wrong or empty answer:

| Command | Behaviour | Signal |
|---|---|---|
| `du -sh` | Unsupported; prints `.` | Obvious — `du` is a common first command |
| `su`, `chmod` on some paths, `useradd`, `visudo` | Fall through to the binary emulation | `Exec format error` or nothing |
| `sed`, `tr` | Implemented in 3.1.0, but simpler than GNU | `sed -i`, BRE edge cases differ |
| `ip route`, `ip link` | Served the `ip addr` payload — one txtcmd cannot branch on argv | `ip route` prints address information. Documented as a known limitation at `info` severity |
| `dpkg -l openssh-server` | The canned package list omits itself | Mildly inconsistent with `ssh -V` |

`du -sh` is the one to fix first if you extend this package.

### 2.6 Interoperability: paramiko exec

Cowrie 3.1.0 closes an exec channel within a few milliseconds. paramiko can
observe the channel close before it processes the exec acknowledgement and
raises `SSHException: Channel closed.` OpenSSH clients are unaffected.

**This is a detection signal in both directions.** An attacker using a
paramiko-based toolkit sees anomalous behaviour, and — more usefully — a
toolkit that behaves anomalously is itself worth correlating on.

### 2.7 The command set is finite

Roughly 100 commands are emulated. A real Debian host has thousands of
utilities. An attacker who runs `strace`, `perf`, `lsof`, `journalctl -u`,
`apt-get install`, `dpkg --verify`, `systemd-analyze` or anything unusual will
find nothing, and finding nothing on a busy system is itself informative.

---

## 3. Detection signals, ranked

For an operator trying to identify this deployment, roughly in order of how
easily each is found.

**Trivially — one command**

1. `du -sh /var/log` prints `.` (§2.5).
2. Missing `/proc` entries (§2.2) — a short `ls /proc/self/`.
3. An unimplemented command returning empty output or `Exec format error`
   (§2.5).
4. `ip route` printing address information (§2.5).

**With a few commands**

5. Timing: a streamed command arriving in a burst, or the shared event loop
   visible under load (§2.3).
6. Package database weakness — `dpkg -l` returns a canned list; `dpkg -S`,
   `apt-cache policy` and `dpkg --verify` do not hold up.
7. `/var/log` entries that are plausible but do not grow, and whose contents do
   not match what a real service would write over time.

**With deliberate effort**

8. Comparing against a real Debian 12.5 host: file timestamps, inode numbers,
   `/proc/self/stat`, and the exact byte-level format of command output.
9. The reactor wedge (§2.4) — send a pathological traversal and observe the
   whole service stop answering.
10. Banner and version alignment over time: the advertised kernel gets older
    while the host never receives the security update it should.

**Not really avoidable**

11. A determined analyst who assumes any internet-facing SSH server with no
    user population might be a honeypot will treat it as one regardless, because
    the cost of being wrong in that direction is low.

---

## 4. What this deployment does not protect against

* **A Cowrie, Twisted or Python vulnerability giving code execution as
  `cowrie`.** Mitigated by isolation and disposability, not prevented.
* **Volumetric denial of service.**
* **An attacker who can reach the evidence bucket directly.** A different threat
  model.
* **Being found.** See above. The goal is to defeat casual and intermediate
  inspection and to keep the cost of certainty high.
* **Attribution.** The honeypot records IP addresses, not identities.
* **Legal or policy questions.**
* **A determined attacker filling the disk**, past the point where pruning
  keeps up. The quarantine caps and disk alerts bound the damage and raise a
  P1, but a sustained flood will eventually stop recording.

---

## 5. Signals that are deliberately present

Two things that look like tells are intentional:

* **`SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3` is a real, current, unremarkable
  banner.** Advertising something exotic would be more distinctive than
  advertising the truth about a common release.
* **The credential policy accepts a small, documented list of weak passwords.**
  This means an occasional scripted login succeeds, which produces the
  highest-value telemetry. A honeypot where nothing ever succeeds collects far
  less.

---

## 6. If you need to reduce detection further

In rough order of value per unit of effort:

1. **Set `[honeypot] contents_path`** to a generated directory mirroring the
   emulated tree, so `/proc` is backed by real content (§2.2).
2. **Implement `du`.** One command, high visibility (§2.5).
3. **Move to the QEMU pool** (`docs/12`). The only way to address timing and
   `/proc` properly, because the guest is a real kernel.
4. **Vary the profile per sensor.** A fleet of honeypots all reporting
   `deploy-01` at `10.20.30.40` is correlated trivially. Edit
   `realism/identity.yaml` per instance and rebuild.
5. **Keep the banner current.** A pinned point release that never ages is itself
   a signal over months. Rotate the profile periodically and rebuild.

None of these make it undetectable. They raise the cost.

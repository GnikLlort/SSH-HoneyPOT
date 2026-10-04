# 02 — Threat model

Written from the position that the honeypot is a **target**, not a tool. The
question is not "can we detect attackers" but "what can an attacker do to us,
and what can we do to them".

---

## 1. Assets, in priority order

| # | Asset | Why it matters | Worst realistic outcome |
|---|---|---|---|
| 1 | **Production and personal systems** | Someone else's data, someone else's uptime | Attacker pivots from the honeypot to a real system. Unrecoverable. |
| 2 | **Evidence integrity** | The reason the honeypot exists | Attacker deletes or rewrites the record of their own intrusion. The honeypot becomes worse than useless. |
| 3 | **Captured credentials and files** | They belong to third parties, and they are evidence | Leaked to a public service, or executed on a workstation. |
| 4 | **The honeypot host** | Disposable, but confusing if lost | Attacker roots it and uses it as a base. Bounded by isolation, not by hardening. |
| 5 | **Realism / cover** | If the honeypot is identified, it stops producing useful telemetry | Attacker recognises it, feeds it garbage or leaves. |

Note the ordering. **The honeypot host is fourth.** It is deliberately
disposable, and the design spends far more effort on not touching production
than on defending the instance itself. That is the right trade for a decoy, and
it is a deliberate choice, not an oversight.

---

## 2. Adversaries

### A1 — Opportunistic scanner / botnet

Automated, high volume, low sophistication. Tries a handful of credentials,
runs a fixed command list, uploads a payload, moves on.

*What they do here:* authenticate rarely (the credential list is narrow), get
recorded, occasionally upload a file which lands in quarantine.
*Value:* volume, credential-stuffing wordlists, payload hashes, source-IP
geography. This is the bulk of the telemetry.
*They cannot tell they are in a honeypot* in most cases, because they never look
past the banner and a command exit status.

### A2 — Motivated operator, hands on keyboard

Runs reconnaissance before committing: `uname -a`, `cat /proc/cpuinfo`,
`lscpu`, `free`, `df`, `ps aux`, `ss -tlnp`, `systemctl list-units`, `dmesg`,
`find`, checks for a writable path, looks at `/proc` and the network layout.
This is the adversary the realism work is aimed at.

*What they find:* an internally consistent Debian 12.5 build server
(`docs/09` shows 197 of 198 conformance checks passing). Against a careful
operator they will eventually find something — `docs/10` lists the specific
signals.

### A3 — Targeted attacker who has identified the honeypot

Knows it is Cowrie. Goals become: poison the evidence, escape to something real,
use the honeypot as an attack relay, or feed false intelligence.

*What stops them:* there is nothing to escape to. No route to production, no
instance profile, no credentials, no outbound tcp/22. Evidence is already
shipped off-host within 5 minutes and cannot be deleted from the honeypot.
*What they can still do:* flood the honeypot to fill disk (mitigated by
quarantine caps and pruning), or waste analyst time with fabricated activity.
**Assume A3 can generate misleading evidence, and correlate before acting on
any single session.**

### A4 — Insider / operator mistake

The most likely way this deployment causes harm. Someone installs it on the
wrong instance, reuses a real credential in `userdb.txt`, copies a real file
into the synthetic filesystem, or bridges the VPC "temporarily".

*What stops them:* `install.sh` refuses to run on a host that looks like it has
a life (a real SSH service already on the target port, existing user data,
production-looking directories) and is dry-run by default. `ops/canary_scan.sh`
searches the real filesystem for canary values that must exist only inside the
emulated one. `docs/11` documents the undo.

---

## 3. What we defend against, and how

### 3.1 Attacker escapes the emulated shell into the host

**Threat:** Cowrie has a parsing bug or a command implementation that reaches
the real filesystem or spawns a real process.

**Controls:**
1. Cowrie simulates the shell in Python. There is no `exec` of visitor input
   anywhere in the path.
2. The four commands that *do* touch host state in stock Cowrie are known and
   handled: `free` reads the host's `/proc/meminfo`, and the overlay replaces it
   with the emulated values. This leak is fixed, not merely documented — see
   `docs/04`.
3. The service account is unprivileged, has no shell, no sudo, and can write
   only under `/opt/cowrie/var`, `/var/log`, `/run` (enforced by
   `ProtectSystem=strict` plus `ReadWritePaths`).
4. No IAM instance profile: even full code execution yields no AWS credentials.
5. `IMDSv2` required with hop limit 1, so the metadata service cannot be used to
   obtain instance identity or credentials.
6. `ops/canary_scan.sh` detects the aftermath: canary values are unique markers
   that exist only inside the emulated filesystem. If one appears on the real
   filesystem, an escape has occurred or honeypot content was copied out.
7. `tests/test_conformance.py`'s 16 leakage checks assert that no real host
   path, environment variable, or metadata response is visible inside the
   emulated shell.

**Residual:** an unpatched Cowrie vulnerability could still yield code execution
as the `cowrie` user. Accepted — the instance is disposable and isolated, and
that is exactly why.

### 3.2 Honeypot is used as a pivot into production

**Threat:** outbound connectivity from the honeypot reaches a real system.

**Controls:**
1. Separate VPC, no peering, no transit gateway, no VPN, no Direct Connect.
2. Deny-by-default egress; allow-list limited to the evidence endpoint, OS
   update mirrors, and (during install only) PyPI.
3. **No outbound tcp/22 rule.** Cowrie's `ssh`, `scp`, `wget`, `curl`, `nc` and
   `tftpget` commands emulate their protocols in-process. Adding an outbound
   tcp/22 rule would turn a successful lure into a real outbound attack
   capability. This is the single most important egress rule.
4. No route to `10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16`.
5. `ops/healthcheck.sh` alerts on unexpected outbound traffic.

**Residual:** if the VPC is reused and its CIDR overlaps production ranges, the
`local` route would provide reachability. `deploy/aws/security-groups.md`
section 3 calls this out for verification.

### 3.3 Attacker destroys or rewrites evidence

**Threat:** an operator who compromises the honeypot deletes logs, or edits
`cowrie.json` to remove a session.

**Controls:**
1. `ops/quarantine_sync.sh` copies evidence off-host every 5 minutes, bounding
   what can be lost.
2. The evidence bucket lives in a **separate AWS account**; the honeypot's
   principal has no delete or read permission.
3. SSE-KMS with a customer-managed key, versioning, and Object Lock with
   retention — so even the account owner cannot quietly rewrite history within
   the retention window.
4. A SHA-256 manifest is written **before** the payload, so truncation or
   substitution is detectable.
5. Local pruning happens **only after** a verified successful ship. Deleting
   first and copying second is how evidence gets lost.

**Residual:** up to 5 minutes of activity can be lost if the host is destroyed
between runs. Tune the timer if that matters more than the API cost.

### 3.4 Captured files harm an analyst

**Threat:** an uploaded payload is opened on the honeypot or on a normal
workstation.

**Controls:** every upload is stored byte-for-byte in a dedicated quarantine
directory, hashed, recorded with session id and transfer method, shipped
off-host, and never executed, previewed, or opened. `ops/alert_dispatch.sh`
never includes captured content in a notification. The playback UI labels
uploads as quarantined and renders only metadata, never bytes.

**This is a process control as much as a technical one.** `docs/06` is explicit
that analysis requires a separate disposable environment, and that the original
stays quarantined.

### 3.5 Honeypot content leaks onto the real host

**Threat:** the reverse of 3.1 — synthetic content (including canary values)
contaminates the real filesystem, making the canary useless and potentially
confusing a real system with decoy files.

**Controls:** `ops/canary_scan.sh` searches the real filesystem for the three
canary values in `realism/identity.yaml`. `docs/10` notes the canary
`hq.example.net` is a search domain and appears in `/etc/resolv.conf` of the
*emulated* system only.

### 3.6 Reviewer's device is attacked by a recording

**Threat:** a visitor sends escape sequences, an OSC 52 clipboard write, a
bidirectional override to disguise a command, or markup, hoping to attack
whoever reviews the session.

**Controls:** the playback server strips escape sequences, removes control
characters and bidi overrides, masks secrets by default, renders every string
via `textContent` (never `innerHTML`), serves a per-start CSP nonce with no
`unsafe-inline`, escapes `<`, `>`, `&` in the embedded JSON so a recording cannot
close the `<script>` element, refuses to bind publicly without an explicit flag,
and confines ttylog path resolution to the recordings directory so a poisoned
log line cannot make it read `/etc/shadow`. 32 tests cover these paths.

**This is tested against a deliberately hostile recording** containing all of
the above; see `tests/test_playback.py`.

### 3.7 Resource exhaustion / denial of service

**Threat:** fill the disk with uploads, spawn unbounded commands, or wedge the
reactor.

**Controls:** `MemoryMax`, `CPUQuota`, `TasksMax` on both services; Cowrie's own
`max_input_size`, `parse_timeout_seconds`, `scp_max_files_per_session`;
quarantine size caps with warn/critical alerts and oldest-first pruning that
preserves the event record even when bytes are dropped; log rotation with
`copytruncate`; a health check that reads the SSH banner to detect a reactor
that accepts TCP but never answers.

**Residual — observed during testing:** an unbounded `find /` inside the
emulated filesystem can wedge the Twisted reactor. The process then ignores
`SIGTERM` and keeps the port bound, requiring `SIGKILL`. This is a genuine
availability weakness: an attacker who discovers it can make the honeypot
unresponsive. It is documented in `docs/10` and the health check is designed to
catch it, but it is not fixed.

### 3.8 Honeypot is identified by fingerprinting

**Threat:** the attacker decides this is not worth their time, or worse, feeds
disinformation.

**Controls, and their limits:** internal consistency (one identity manifest
generates everything), realism conformance testing, and fixing the known
divergences. **The limit is real and must be stated plainly: this honeypot is
detectable.** `docs/10` lists the concrete signals. The goal is to defeat casual
and intermediate inspection, not all inspection.

---

## 4. Explicitly out of scope

| Not defended | Reason |
|---|---|
| A zero-day in Cowrie 3.1.0 allowing code execution | Mitigated by disposability and isolation, not prevented. The instance is designed to be lost. |
| An attacker who can read the evidence bucket | Assumes the separate account is itself compromised — a different threat model. |
| DDoS volumetric attacks on the AWS account | An AWS-level concern; the honeypot has no role in it. |
| Legal or jurisdictional questions about honeypot operation | Out of scope. **You are responsible for confirming that operating a honeypot is lawful in your jurisdiction and acceptable under your provider's terms.** |
| Attributing activity to a real person | The honeypot records IP addresses, not identities. IPs are shared, spoofable, and frequently not the operator. |

---

## 5. Standing rules

These come from the deployment requirements and are not negotiable in this
design:

1. **Never auto-ban or auto-report an IP because it connected to the honeypot.**
   Connection alone is evidence of nothing; the honeypot is designed to attract
   it. Correlate first. `ops/alerts/rules.md` carries the rationale.
2. **Never execute, preview or open a captured file** on the honeypot or a
   normal workstation.
3. **Never fetch files from attacker-controlled URLs automatically.**
4. **No real data, credentials, keys or personal information** anywhere in the
   package or the synthetic filesystem.
5. **Never expose the management interface publicly.** Session Manager or a VPN.
6. **Never enable Cowrie's LLM mode** without the privacy and containment
   review in `docs/13`.

---

## 6. Assumptions

If any of these stops being true, revisit the model rather than the controls:

* The instance is dedicated to the honeypot and holds nothing else.
* The VPC is dedicated to the honeypot and does not overlap production ranges.
* The evidence bucket is in a separate account, or the account boundary is
  compensated for by a separate KMS key and Object Lock.
* No human credentials for real systems are ever entered into the emulated
  shell during testing. (Test logins use the documented synthetic passwords
  only.)
* The operator reads alerts. An alert nobody reads is telemetry, not security.

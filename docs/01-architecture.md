# 01 — Architecture

## 1. What this system is

A single-purpose EC2 instance that looks like an ordinary internal Debian build
server with SSH exposed, and records everything a visitor does to it.

It is not a sandbox for running attacker code. It is a **recorder**. The
distinction matters for every design decision below: because Cowrie simulates a
shell in Python instead of providing a real one, the attacker never gets code
execution, and the whole class of "escape the sandbox" risk disappears from the
emulated mode. What remains is the risk of the *honeypot software itself* having
a vulnerability, which is why the instance is disposable and isolated.

---

## 2. Component map

```
┌──────────────────────────────────────────────────────────────────────────┐
│ EC2 instance: cowrie-hp-01    Ubuntu 24.04 LTS, t3.small                  │
│ Own VPC. No route to production. No IAM instance profile. IMDSv2-only.   │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ systemd unit: cowrie.service                                       │  │
│  │   User=cowrie (unprivileged, no shell, no sudo)                    │  │
│  │   CapabilityBoundingSet=CAP_NET_BIND_SERVICE   (only, to bind 22)  │  │
│  │   ProtectSystem=strict, ReadWritePaths=/opt/cowrie/var             │  │
│  │   MemoryMax / CPUQuota / TasksMax bounded                          │  │
│  │                                                                    │  │
│  │   ┌──────────────────────────────────────────────────────────┐    │  │
│  │   │ Cowrie 3.1.0 @ 6ec36d0  (venv, /opt/cowrie/venv)         │    │  │
│  │   │                                                          │    │  │
│  │   │  ssh/channel.py ─► insults.py ─► shell.py                │    │  │
│  │   │       │                 │             │                  │    │  │
│  │   │       │                 │             └─► honeyfs         │    │  │
│  │   │       │                 │                 (fs.pickle:     │    │  │
│  │   │       │                 │                  the synthetic  │    │  │
│  │   │       │                 │                  filesystem)    │    │  │
│  │   │       │                 │                                │    │  │
│  │   │       │                 └─► commands/*  (~100 emulated    │    │  │
│  │   │       │                                  commands)        │    │  │
│  │   │       └─► ttylog.py  (session recordings)                │    │  │
│  │   │                                                          │    │  │
│  │   │  events.py ─► output plugins ─► cowrie.json, cowrie.log  │    │  │
│  │   └──────────────────────────────────────────────────────────┘    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────┐  ┌──────────────────────────────────────┐  │
│  │ REALISM OVERLAY          │  │ OPERATIONAL HELPERS                  │  │
│  │ overlays/cowrie_realism_ │  │   ops/healthcheck.sh    (5 min)      │  │
│  │   overlay/               │  │   ops/quarantine_sync.sh (5 min)     │  │
│  │                          │  │   ops/prune_local.sh                 │  │
│  │ Injected via PYTHONPATH  │  │   ops/canary_scan.sh                 │  │
│  │ + sitecustomize, never   │  │   ops/alert_dispatch.sh              │  │
│  │ by editing Cowrie.       │  │   ops/logrotate/cowrie               │  │
│  │ Fixes ps, free, service. │  │                                      │  │
│  │ Falls back to stock on   │  │ COULD ONLY WRITE HERE:               │  │
│  │ any error.               │  │   /opt/cowrie   /var/log  /run       │  │
│  └──────────────────────────┘  └──────────────────────────────────────┘  │
│                                                                          │
│  ┌──────────────────────────┐                                            │
│  │ PLAYBACK (on demand)     │  Binds 127.0.0.1:8081 only. Read-only over │
│  │   playback/server.py     │  the state directory. Reached over SSM.    │
│  └──────────────────────────┘                                            │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                  outbound: only the pinned allow-list
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ SEPARATE AWS ACCOUNT                                                     │
│   S3 evidence bucket                                                     │
│     SSE-KMS, customer-managed key, versioning, Object Lock               │
│     bucket policy denies s3:DeleteObject to the honeypot's principal     │
│   CloudTrail (management events), KMS key policy owned here              │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Data flow: what happens when someone connects

1. **TCP accept.** `iptables` permits only tcp/22 inbound. Cowrie's SSH
   transport answers.
2. **Banner exchange.** Cowrie presents
   `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`, which matches
   `openssh_banner` in `realism/identity.yaml` and the `ssh_version` reported
   by the emulated `ssh -V`.
3. **Key exchange.** Real cryptography (Twisted Conch), so the handshake is
   genuine. This is the main reason an attacker cannot tell it apart at the
   protocol layer: the SSH implementation is real, only the *system behind it*
   is synthetic.
4. **Authentication.** Credentials are checked against
   `config/userdb.txt`, an explicit allow-list. `root` and `svc-backup` have
   `!` passwords and cannot authenticate, which is consistent with the
   emulated `/etc/ssh/sshd_config` setting `PermitRootLogin prohibit-password`.
5. **Session starts.** A fresh copy-on-write filesystem tree is handed to the
   session. Writes inside the session are visible to the visitor and discarded
   when the session ends, so an attacker can create files, `chmod` them, and
   `cat` them back, and everything behaves.
6. **Recording.** Every byte in both directions is written to
   `var/lib/cowrie/tty/`. On close, Cowrie renames the file to the SHA-256 of
   the visitor's input and **deletes it if an identical recording already
   exists** — so `cowrie.log.closed` events carry `shasum` and `duplicate`
   fields, and several sessions can legitimately share one recording. The
   playback UI relies on this; anything parsing recordings by session id will
   silently find nothing.
7. **Event record.** Structured JSON lines to `var/log/cowrie/cowrie.json`:
   connect, auth attempts, commands, uploads, downloads, session close.
8. **Shipping.** Within 5 minutes, `ops/quarantine_sync.sh` copies the log,
   recordings and captured files to the evidence bucket, writes a manifest
   containing the SHA-256 of every captured file, and only then prunes the
   local copy.

---

## 4. Trust boundaries

| # | Boundary | What crosses it | Control |
|---|---|---|---|
| 1 | Internet → SSH service | Arbitrary attacker bytes | Only tcp/22 is open. Cowrie parses them; it never executes them. |
| 2 | Attacker session → host OS | Should be nothing | Cowrie is a Python emulator. No shell, no `exec`, no file writes outside the state dir. The `cowrie` account is unprivileged. |
| 3 | Honeypot → production | Should be nothing | Separate VPC, no peering, no TGW, no VPN; explicit deny-by-default egress; no route to private ranges. |
| 4 | Honeypot → evidence store | Log and capture uploads, one way | Bucket in a separate account; honeypot's principal cannot delete or read history. |
| 5 | Evidence → analyst | Only through inspection tooling | Captured files are quarantined and never opened on the honeypot or a workstation. See `docs/06`. |
| 6 | Recording → reviewer's browser | Escaped, masked text | Terminal control stripped, secrets masked by default, `textContent` rendering, per-start CSP nonce. See `docs/07`. |
| 7 | Admin → host | Session Manager only | No inbound management port. The playback UI binds to loopback. |

Boundary 2 is the interesting one, and it is the one the design leans on. It is
not that attacks on the honeypot software are impossible; it is that an
attacker who succeeds lands in an unprivileged account on a disposable instance
with no credentials, no route to anything real, and no ability to destroy the
evidence of what they did to get there.

---

## 5. Why the pieces are where they are

**Why an overlay instead of patching Cowrie.** Four built-in commands are wrong
in ways configuration cannot fix: `ps` truncates to `COLUMNS` and `ps -ef`
ignores the configured process table entirely; `free` reads the *real* host's
`/proc/meminfo` and divides by 1000 instead of 1024; `service` misreports
status. Editing files inside the installed Cowrie would make the deployment
un-upgradable and impossible to verify against upstream. Instead,
`overlays/cowrie_realism_overlay/` is injected via `PYTHONPATH` and
`sitecustomize.py`, version-guards itself against Cowrie 3.1.0, and wraps every
patch in `try/except` that falls back to stock behaviour. Rollback is unsetting
two environment variables.

**Why the fallback matters more than the fix.** During development a patch
raised `AttributeError` inside a command handler, which left the Twisted
reactor wedged: the session hung, the process ignored `SIGTERM`, and the port
stayed bound. A wrong-looking `ps` is a cosmetic problem; a wedged reactor takes
the honeypot down. Every patch therefore degrades to stock output on error, and
the health check reads the SSH banner specifically to detect a reactor that
accepts TCP but never answers.

**Why one identity manifest.** Consistency is the whole game in a fake host. If
`/etc/hostname` says `deploy-01` but the prompt says `localhost`, or `/proc/cpuinfo`
says 2 cores while `nproc` says 8, an attacker has a tell. Rather than hand-editing
a dozen artefacts, `realism/identity.yaml` is the single source from which the
filesystem, command outputs, process table and Cowrie config are generated, so
they cannot drift apart. `tests/test_conformance.py` then verifies the
agreement independently.

**Why the evidence bucket is in another account.** An attacker who gets code
execution on the honeypot must not be able to erase the record of getting
there. Cross-account means the honeypot's credentials (if it has any at all)
cannot touch the objects it has already shipped.

---

## 6. Deployment layout on the instance

```
/opt/cowrie/                     state directory, owned by cowrie:cowrie
  venv/                          pinned virtualenv (Cowrie + deps)
  etc/cowrie.cfg                 operator config: overrides only
  etc/userdb.txt                 credential allow-list
  share/pkg/                     this package, installed read-only
    realism/identity.yaml        the identity manifest
    deploy/, ops/, docs/, tests/, playback/
  var/log/cowrie/                cowrie.json, cowrie.log
  var/lib/cowrie/tty/            session recordings
  var/lib/cowrie/downloads/      captured uploads (quarantine staging)
  var/lib/cowrie/fs.pickle       generated synthetic filesystem
  var/run/cowrie.pid             pid file

/etc/cowrie-logship.env          evidence destination + alerting (0640 root:cowrie)
/etc/logrotate.d/cowrie          rotation with copytruncate
/usr/local/sbin/                 operational helper scripts
/etc/systemd/system/             cowrie.service and timers
```

The honeypot account can write only inside `/opt/cowrie/var`, `/var/log`, and
`/run`. It cannot read `/home/*` of real users, cannot read `/etc/shadow`, and
has no sudo.

---

## 7. Modes

| Mode | Status | Safety | Realism |
|---|---|---|---|
| **Emulated shell** (this package) | Built, tested | Attacker code never runs | High for casual and intermediate operators; detectable by `/proc` and timing analysis |
| **QEMU guest pool** | Design only (`docs/12`) | Attacker code *does* run, inside a disposable guest | Very high; the guest is a real kernel |
| **LLM mode** | Disabled (`docs/13`) | Requires containment review | Can improve free-text plausibility; adds a data-egress path |

Emulated mode stays the safe fallback: if the guest pool is unavailable, the
honeypot degrades to a recorder rather than to nothing.

# 15 — Monitoring dashboard

The honeypot records; this is where an administrator reads the record.

`dashboard/` is a separate program from everything else in the package, and it
runs on a **different host**: the honeypot's state directory never contains the
dashboard, and the dashboard has no credential, socket or address for the
honeypot. Data reaches it as exported bundles, one way.

`deploy/install.sh` does **not** install it — that script is honeypot-side, and
staging the reviewer on the host under test would defeat the separation. This
page describes what the dashboard is, what it guarantees, and how to run it.

---

## 1. Where it sits

```
honeypot host                         monitoring host
  /opt/cowrie                           (separate instance, SSM/VPN reachable)
    var/log/cowrie/cowrie.json            dashboard/server.py  ← the UI
    var/lib/cowrie/tty/*        ──┐       dashboard/ingest.py  ← loads bundles
    var/lib/cowrie/downloads/*    │       store.sqlite3        ← the index
        │                         │       recordings/          ← recordings
        │  quarantine_sync.sh      │       quarantine/          ← captures
        │  (hashes, then ships)    │
        ▼                         │
   S3 evidence bucket ────────────┘
```

`dashboard/bundle.py` is the honeypot-side half: it packs the state directory
into a staging directory (or a tarball), re-hashing every recording and capture
under its own SHA-256 so a file renamed or truncated in transit is detected
rather than indexed under the wrong name. `ingest.py` is the monitoring-side
half, and it is the only writer of the evidence tables.

---

## 2. Running it

```bash
# on the monitoring host, from the repository root
python3 dashboard/manage.py --store /var/lib/honeypot-store adduser \
    --username <you> --role admin            # prints the TOTP secret once
python3 dashboard/ingest.py \
    --store /var/lib/honeypot-store --bundle /var/spool/honeypot-export
python3 dashboard/server.py \
    --store /var/lib/honeypot-store --listen unix:/run/honeypot-dashboard/dashboard.sock
```

The default bind is loopback (`127.0.0.1:8443`) and the recommended deployment
is a **UNIX socket**, reached with `socat` over an SSM port-forwarding session or
a VPN. `server.py` refuses a non-loopback bind unless it is passed
`--i-know-this-exposes-monitoring`, and that flag must not appear in a unit file
you are deploying.

Roles (`manage.py adduser --role`, `manage.py role`):

| Role | Can |
|---|---|
| `viewer` | Read events, sessions, transfers and health; watch recordings with captured secrets masked |
| `analyst` | Everything a viewer can, plus **reveal** captured secrets and **export** evidence — both audited |
| `admin` | Everything an analyst can, plus management of dashboard accounts (`users.read`, `users.write`, `config.read`, `retention.read`). There is nothing above this that reaches the honeypot, because nothing reaches the honeypot |

| Task | Command |
|---|---|
| Create an administrator | `manage.py adduser --username <name> --role admin` |
| Reset a password or authenticator | `manage.py passwd --username <name>` / `manage.py totp --username <name>` |
| **Clear a lockout** (5 failed logins, 15 minutes) | `manage.py unlock --username <name>` |
| Disable or re-enable an account | `manage.py disable` / `manage.py enable` |
| Read the audit trail | `manage.py audit --limit 40`, or the **Audit** page |

There is no self-service password reset and no email path: an administrator
creates or resets accounts out of band, and the action is audited. `unlock`
clears the failure counter without touching the password — before that command
existed, the only way to clear a lock was `passwd`, which is not something an
operator should have to work out at 3 a.m.

---

## 3. What it cannot do

These are structural, not policy:

* **Cannot reach the honeypot.** No host, address or credential for it exists in
  the code, and no outbound client (`paramiko`, `requests`, `urllib.request`,
  `subprocess`, `ftplib`, `socket.connect`) is imported. A test asserts this by
  scanning the module sources.
* **Cannot execute anything.** There is no shell, and no endpoint that takes a
  command. A recording is parsed and rendered as text, never run.
* **Cannot modify evidence.** The evidence store is opened `mode=ro` plus
  `PRAGMA query_only=ON`; a write through that handle is rejected by SQLite, not
  by the program's restraint. The web process writes only to its own tables —
  `admin_user`, `admin_session`, `audit`, `export_log`.
* **Cannot read a captured file.** Uploads are shown by metadata and hash only;
  no code path opens the quarantine directory. Analysis happens in a separate
  disposable environment (`docs/06`).
* **Cannot be framed or scripted from elsewhere.** A per-process nonce CSP, no
  external resources, `SameSite=Strict` cookies, and a CSRF token bound to the
  session for every POST, including `/login`.

---

## 4. Limits and behaviours worth knowing

| Behaviour | Why |
|---|---|
| A recording above **8 MB** is listed but not rendered; you get its size, hash and a pointer to the offline workflow | Rendering builds the bytes, the parsed chunks and the JSON at once — measured at ~3× the file. A 64 MB recording would be ~192 MB per request, and the server has no natural concurrency limit. The limit is applied **before** the file is read |
| At most **4 recordings render at once**; the fifth is told the renderer is busy | Same reason, from the other direction. The audit trail records `view.recording.deferred` |
| A search with an unparsable date (`since=garbage`) returns **HTTP 400**, not results | A bound that cannot be parsed used to be dropped, which silently returned every event instead of none. For a tool that establishes what happened in a window, the wrong direction to fail is "wider" |
| `%` and `_` in a search are **literal characters** | They are LIKE wildcards; unescaped, a search for `_` matched 1 183 of 4 874 events. A search must return what was typed |
| A session cookie presented with a **different User-Agent** is destroyed and audited (`session.ua_mismatch`) | The column existed and was never read. This is a signal that a token leaked; it is skipped when either side is empty, so it is not a second password |
| The startup banner lists **every relaxed control** (demo mode, non-loopback bind, framing, cookie policy, plain HTTP) | A comment claimed `--demo-mode` could not run on a reachable interface. With `--i-know-this-exposes-monitoring` it can. Comments that overstate controls are how an audit gets a false pass |

---

## 5. Safety properties and where they are tested

| Property | Test |
|---|---|
| Sanitisation is identical to the on-host playback viewer | `tests/test_dashboard.py::TestSanitizerParity` |
| Captured credentials are masked, including in Cowrie's prose `message` field | `TestCredentialRedaction` |
| A hostile recording cannot exhaust CPU through the masker | `TestSanitizerPerformance` |
| Response headers cannot be split by attacker text | `TestHeaderInjection` |
| Filters fail loudly; LIKE wildcards are literal | `TestFilterValidation` |
| Recording rendering is memory-bounded and concurrency-bounded | `TestPlaybackBounds` |
| Expired sessions are purged; sessions are bound to a client | `TestSessionHousekeeping` |
| The login POST is bound to the page the browser was served | `TestLoginCsrf` |
| Relaxed controls are stated at startup | `TestRelaxedControls` |

`AUDIT.md` is the adversarial record behind all of this: eleven findings, what
each one was, how it was proven, and the test that now guards it.

---

## 6. Known limitations

* **Nothing here has run against the internet**, and the dashboard has never been
  exposed beyond loopback in any test. It is designed for a management path, not
  for a network.
* **No fuzzing.** The ttylog parser is probed with adversarial inputs, not fuzzed
  (see `AUDIT.md` §5).
* **No TLS is configured by the program.** Confidentiality comes from the
  management path (SSM or VPN). If you terminate TLS in front of it, read the
  request-smuggling note in `AUDIT.md` (F-10, fixed) before adding a proxy.
* **Single store, single writer.** `ingest.py` writes; `server.py` reads. There is
  no replication or clustering, and none is planned: the workload is one
  administrator reviewing evidence.

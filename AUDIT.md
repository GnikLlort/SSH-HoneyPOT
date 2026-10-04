# Code audit — SSH honeypot package and monitoring dashboard

**Date:** 2026-10-04
**Commit audited:** `2a904f6` plus the working tree of this session
**Scope:** every tracked file in this repository (20 Python modules, 9 shell
scripts, the Cowrie configuration, systemd units, ops scripts, docs)
**Method:** adversarial reading combined with executed proof. Nothing below is
reported on the strength of reading alone: each finding was reproduced, and
each claim of "verified correct" was tested or traced into the Cowrie source.

---

## 1. Summary

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| F-01 | **High** | HTTP response splitting through the export filename | **Fixed** |
| F-02 | **High** | Quadratic regex in the credential masker (ReDoS) | **Fixed** |
| F-03 | Medium | Recursive delete on an unvalidated path | Open |
| F-04 | Medium | No memory bound when rendering a recording | Open |
| F-05 | Medium | Account lockout with no unlock path | Open |
| F-06 | Medium | Invalid date filter silently widens a search | Open |
| F-07 | Low | Login POST is not CSRF-protected; its token is a constant | Open |
| F-08 | Low | Security comment contradicts the code (demo mode) | Open |
| F-09 | Low | Dead code implying controls that never run | Open |
| F-10 | Low | A rejected request body is not drained | Open |
| F-11 | Info | `safe_html` does not escape backticks | Open |

Two findings are high severity. Both were found by executing the code against
hostile input, not by reading it. One of them (F-02) was introduced by this
project during this session.

Section 4 lists the claims that were tested and found **sound**, which matters
as much as the findings: several of them are the controls the whole design
depends on, and two of them were single-line-of-configuration away from being
false.

---

## 2. Findings

### F-01 — HTTP response splitting through the export filename — HIGH — FIXED

**Location:** `dashboard/server.py`, `_export()` and `_send()`

**What happens.** `/export` accepted a `kind` form field, truncated it to 32
characters, and interpolated it into a `Content-Disposition` header:

```python
kind = (form.get("kind") or "events")[:32]
filename = f"honeypot-{kind}-{stamp}.{fmt}"
return Response(body, ctype=ctype, headers=[
    ("Content-Disposition", f'attachment; filename="{filename}"'),
])
```

`kind` was allowlisted for the *data* branch (`if/elif/else` falls through to
events) but not for the header. `http.server` writes header values verbatim, so
a line break in the value splits the response. Truncation is not a sanitiser:
32 characters is ample room for a CRLF and the start of a new header.

**Proof.** Reproduced against a running instance. Request:

```
kind = "\r\nContent-Type: text/html\r\n\r\n<script>alert(document.domain)</script>"
```

Response received on the wire:

```
Content-Disposition: attachment; filename="honeypot-
Content-Type: text/html          <- injected header
                                 <- injected blank line; header block ends here
<sc-20261004T085007Z.csv"        <- body begins with attacker-chosen bytes
sensor,session_id,eventid,...    <- real body follows
```

A simpler variant injecting only `\r\nX-Injected-Header: pwned` was also
confirmed.

**Impact.** Reachable by any account holding the `export` permission (analyst,
admin) — that is, by a normal UI action, not an exotic request. Consequences:
arbitrary response-header injection; early termination of the header block so
the attacker chooses the first bytes of the body; and, because `Content-Length`
was already emitted with the original value, a body longer than declared, which
desynchronises a keep-alive connection. Whether the injected markup executes in
a browser depends on how the browser resolves a duplicated `Content-Type`; I
could not test that here (see §5) and do not claim it.

**Fix applied.** Three layers:
1. `kind` is allowlisted to `events|sessions|transfers` rather than truncated.
2. `safe_filename()` reduces the name to `[A-Za-z0-9._-]` by construction.
3. `_send()` validates the **entire** header block (`invalid_header()`) before
   writing the status line, and answers with a bare 500 if any value contains a
   line break or is not latin-1 encodable. This is the layer that matters: the
   next person to add a dynamic header inherits the check instead of
   rediscovering the problem.

Regression tests: `TestHeaderInjection` (5 tests), including a static assertion
that `kind` is still allowlisted.

---

### F-02 — Quadratic regex in the credential masker — HIGH — FIXED

**Location:** `shared/terminal_safety.py`, `SENSITIVE_PATTERNS[0]`

**What happens.** The pattern that masks Cowrie's
`login attempt [user/password]` wording was written as:

```python
re.compile(r"(?i)(\blogin attempt \[[^\]\n]*/)([^\]\n]*)(?=\])")
```

The first group can end at *any* slash. On a line with many slashes and no
closing bracket, the engine tries every split point, and for each one the second
group scans to the end of the input. That is O(n²).

**Proof.** Measured on this machine, before the fix:

| input | time |
|-------|------|
| 2 KB | 22 ms |
| 4 KB | 85 ms |
| 8 KB | 334 ms |
| 16 KB | 1213 ms |
| 40 KB | **33 185 ms** |

Perfectly quadratic. Cowrie accepts a 16 KB command (`[shell] max_input_size`),
and a visitor types commands over SSH — so the input is attacker-controlled and
the ceiling is 1.2 s of CPU per rendered occurrence, on the *monitoring* host,
every time the events, session or transcript page is rendered. A few hundred
such commands would make the dashboard unusable. It cannot be used to stop
evidence collection: masking is a display path only, and I confirmed it is not
called from `store.py`, `ingest.py` or `bundle.py`.

**Fix applied.** The username class now excludes `/`, removing the ambiguity,
and every quantifier is bounded:

```python
re.compile(r"(?i)(\blogin attempt \[[^/\]\n]{0,64}/)([^\]\n]{0,256})(?=\])")
```

Worst hostile input measured after the fix: **4.2 ms** (from 33 185 ms), scaling
linearly to 24 ms at 128 KB. Masking behaviour is unchanged for all realistic
inputs, including empty passwords, passwords with spaces, and passwords
containing slashes or brackets.

Regression tests: `TestSanitizerPerformance` runs 13 hostile payloads against
the whole pattern set and fails any pattern that backtracks catastrophically. I
checked that the test actually catches the bug: **reinstating the old pattern
fails it at 5569 ms against a 400 ms budget.** The first version of this test
used a 2 s budget and passed the old pattern — a test that does not fail on the
bug it guards is worse than no test, so the budget was tightened until it did.

---

### F-03 — Recursive delete on an unvalidated path — MEDIUM — Open

**Locations:**
- `realism/build_profile.py:1354` — `shutil.rmtree(out)` where `out` is `--out`
- `deploy/uninstall.sh:96` — `rm -rf "$STATE_DIR"`

**Impact.** `build_profile.py` removes its output directory before regenerating.
Nothing validates the path. The documented invocations pass `build/profile`, but
`--out` is an ordinary command-line argument and the script is run as root during
installation (`env HOME=/root …`). `--out /opt/cowrie` — a plausible slip for the
state directory — would recursively delete the honeypot's state tree, which
contains `var/lib/cowrie/tty/`: the session recordings, which are evidence.
`--out /` is worse. `uninstall.sh` is the same shape: it is *meant* to delete the
state directory, and it checks that it is running as root, but not that
`STATE_DIR` names something the honeypot owns.

This is operator-reachable rather than attacker-reachable, hence Medium. The
blast radius includes irreplaceable evidence, hence not Low.

**Recommended fix.** A shared guard: refuse unless the path is absolute, is not
`/`, is not a mount point, has at least two path components, and (for the build
tool) either contains a `.honeypot-profile` marker from a previous run or lives
under a directory named `build`. Deletion of a directory that does not look like
this package's own output should require an explicit `--force`.

---

### F-04 — No memory bound when rendering a recording — MEDIUM — Open

**Location:** `dashboard/server.py`, `_session_api()` and `_session_detail()`

```python
data = path.read_bytes()                      # no size check before the read
parsed = parse_ttylog_bytes(data, ...)        # ceiling checked after the read
```

`MAX_RECORDING_BYTES` (64 MB) is enforced *inside* the parser, so it prevents
nothing: the file is already in memory by then, and the parsed chunks and the
JSON payload are built on top of it.

**Measured** (16.8 MB recording, `tracemalloc`): peak **50 MB** per request —
3.0× the file. Extrapolated to the 64 MB ceiling: **~192 MB per request**. The
server is a `ThreadingHTTPServer` with no concurrency cap, so five simultaneous
viewers of a large recording ask for roughly **1 GB** on the monitoring host.

**Impact.** Memory exhaustion of the monitoring host by concurrent playback
requests. The honeypot itself is unaffected, and the evidence store is not
corrupted — this is availability, not integrity.

**Recommended fix.** `stat()` the file before reading and refuse to render above
a display limit (8 MB is generous for a terminal session), showing the size, the
hash and a note that the full recording is available for offline analysis. Bound
the number of concurrent playback requests.

---

### F-05 — Account lockout with no unlock path — MEDIUM — Open

**Location:** `dashboard/auth.py`, `_record_failure()`; `dashboard/manage.py`

Five failed logins lock an account for 15 minutes. The lock is keyed on the
account, not on the source, so anyone who can reach the login page can keep an
administrator locked out indefinitely with five requests every 15 minutes.
Behind SSM or a VPN this needs a foothold on the management path first, which is
the mitigation — but the recovery story is the problem: `manage.py` has no
`unlock` command. The only command that clears the lock is `passwd`, because it
happens to reset `failed_count` and `locked_until`. So the documented recovery
from a lockout is "change the password", which is not what an operator should
have to do, and is not what they will guess at 3 a.m.

**Recommended fix.** Add `manage.py unlock --username`, calling the existing
reset path without touching the password. Consider per-source throttling in
addition to the per-account lock so one source cannot lock out everyone.

---

### F-06 — Invalid date filter silently widens a search — MEDIUM — Open

**Location:** `store.py::_date_bound()`

```python
try:
    ...
except ValueError:
    return None            # the bound is dropped
```

A malformed date is discarded and the clause is simply not added, so the query
runs **without** the time bound and returns more than was asked for. For a tool
whose purpose is establishing what happened in a window, silently returning a
wider set than requested is the wrong direction to fail.

**Proof.** Against the demo store (all 4 874 events dated 2026-10-04):

| filter | events returned |
|--------|-----------------|
| `since=2026-12-31` (valid, in the future) | **0** |
| `since=garbage` (unparsable) | **4 874** |

A bound that should exclude everything excludes nothing, and the page looks
normal either way. `_date_bound()` returns `None` for `not-a-date`, `2026-13-45`
and `2026-07-31T99` alike.

**Second half of the same finding.** The free-text search is a `LIKE` with the
term wrapped in `%…%`, and the term is not escaped, so `%` and `_` are
wildcards. Searching for the literal character `_` returns 1 183 of 4 874 events
— every event with a non-empty `command`, `filename`, `url` or `username` —
rather than the zero literal matches. A search that silently over-matches is how
an investigator concludes an indicator appears somewhere it does not.

**Recommended fix.** Reject an unparsable bound with a visible error rather than
dropping it. Escape `%` and `_` in free-text search terms (`ESCAPE '\'`).

---

### F-07 — Login POST is not CSRF-protected, and its token is a constant — LOW — Open

`_route_post()` handles `/login` *before* the CSRF check, and `_do_login()` never
validates the token. The login page nevertheless renders one:

```python
self.app.csrf_for("")     # = HMAC(process_secret, "") — same for every visitor
```

Because the secret is per-process and the token is derived from an empty
session, every visitor to `/login` receives the same value, and anyone can fetch
it. So the field protects nothing even if it were checked.

**Impact.** Login CSRF: an attacker can cause a victim's browser to sign in to an
account the attacker controls, after which the victim's actions are attributed
to that account in the audit trail. On a read-only dashboard showing an empty
account, the practical impact is low — but the audit trail attribution is
exactly the kind of thing this tool exists to get right, and the form *looks*
protected, which is the dangerous part.

**Recommended fix.** Either (a) a cookie-bound double-submit token set on the
login page response and verified on the POST, or (b) if login CSRF is accepted
as a risk, remove the decorative field and document the acceptance. Every other
POST in this program does enforce CSRF correctly, bound to the session token.

---

### F-08 — Security comment contradicts the code — LOW — Open

`dashboard/auth.py:419`, inside the demo-mode branch:

> `# Local demonstration only. The server refuses to combine this with a`
> `# non-loopback bind, and prints a warning at startup.`

The server does **not** refuse. It refuses only when the acknowledgement flag is
absent:

```python
if args.demo_mode and kind == "tcp" and address[0] not in ("127.0.0.1", …):
    if not args.i_know_this_exposes_monitoring:
        print("refusing: …"); return 2
```

So `--demo-mode --i-know-this-exposes-monitoring` runs with the authenticator
step disabled on any interface. That is the configuration this session's preview
uses, deliberately, in a sandbox.

**Why it matters.** A reader auditing this code would conclude that MFA cannot be
disabled on a reachable interface. It can. Comments that overstate controls are
how an audit gets a false pass.

**Recommended fix.** Correct the comment to describe the acknowledgement, and
print a consolidated startup banner listing every relaxed control in effect
(demo mode, `--allow-framing`, `--relax-cookie-policy`, non-loopback bind) rather
than one warning per flag.

---

### F-09 — Dead code implying controls that never run — LOW — Open

- **`Authenticator.purge_expired_sessions()` is never called.** Expired sessions
  are deleted only when someone presents that exact token again. The
  `admin_session` table therefore grows without bound on a long-lived monitoring
  host. Expiry is still *enforced* on validation, so this is housekeeping, not a
  bypass — but a maintenance method that never runs invites the belief that
  maintenance happens.
- **`admin_session.ua_hash` is written as `""` and never read.** The column
  implies user-agent binding. No such binding exists. Either implement it or
  drop the column.

---

### F-10 — A rejected request body is not drained — LOW — Open

`_read_form()` returns `{}` when `Content-Length` exceeds 1 MB **without reading
the body**. With HTTP/1.1 keep-alive, the unread bytes stay in the socket and
are parsed as the next request on that connection. Nothing desynchronises today
because `socat` is a byte-forwarder with no opinion about framing, and because
the sender is the same party who would send the second request. It becomes a
request-smuggling primitive the moment a reverse proxy or a CDN is placed in
front of the dashboard — a plausible future change, since the deployment
guidance mentions a VPN and a management path.

**Recommended fix.** On rejecting a body, drain it or set
`self.close_connection = True`. Cheap, and removes the class of problem.

---

### F-11 — `safe_html` does not escape backticks — INFORMATIONAL

`safe_html` escapes `< > & " '` but not `` ` ``. Every attribute in this codebase
is quoted, so it is not exploitable as written. It is latent: in HTML5 an
unquoted attribute value terminated by a backtick would break out. Worth adding
for the same reason F-01 got a central guard — the next author may not quote.

---

## 3. What was verified as correct

These were tested or traced to a source of truth. They are the claims the design
rests on, and two of them were one configuration value away from being false.

**The honeypot never proxies a visitor to a real destination.** `config/cowrie.cfg`
sets `[ssh] forwarding = true` while claiming this is answered inside the
emulated protocol. That looked wrong enough to check against the pinned source
(`cowrie/ssh/forwarding.py`, v3.1.0). With `forward_redirect` and
`forward_tunnel` false, `cowrieOpenConnectForwardingClient()` falls through both
real-connection branches to `FakeForwardingChannel`, whose `channelOpen()` does
nothing and whose `dataReceived()` dispatches an event and calls
`_close("Connection refused")`. **No outbound connection is made.** The claim
holds.

*Caveat, worth stating where the config is:** the safety of the deployment rests
entirely on those two values staying `false`. `SSHConnectForwardingChannel` — a
real TCP connection to an attacker-named host — is one `forward_redirect = true`
away. The config comment says this; it should also be asserted by a test in
`tests/test_conformance.py` so a future edit cannot silently reopen it.

**The dashboard cannot reach the honeypot.** No outbound client code exists in
`dashboard/`: no `paramiko`, no `requests`, no `urllib.request`, no `subprocess`,
no `ftplib`, no `socket.connect`. `urllib` is imported for parsing only
(`parse_qs`, `quote`, `urlencode`, `urlsplit`, `unquote`). `socket` is used to
listen and to read the local hostname. There is no shell, and no path by which
one could be constructed.

**Evidence is read-only against the web process.** The evidence store is opened
`mode=ro` plus `PRAGMA query_only=ON`, and a `DELETE` through that handle raises
(tested). The web process's only writes are to its own tables — `admin_session`,
`audit` and `export_log` — confirmed by grepping every `INSERT`/`UPDATE`/`DELETE`
in `server.py`.

**SQL is parameterised.** Every query is parameterised with `?`. The only two
places a column name is interpolated (`top_values`, `distinct`) are guarded by
explicit allowlists. All filter values, including the free-text search, are bound
parameters.

**HTML escaping covers attribute context.** `safe_html` escapes `"` to `&quot;`
and `'` to `&#x27;`, so the many `value="{…}"` and `href="{…}"` interpolations
are safe. A static analyser over every f-string in `server.py` and `render.py`
(171 interpolations) found no data value reaching HTML without passing an
escaper; all flagged sites were HTML composed from already-escaped fragments, or
values that had been through `esc()` on a previous line.

**No archive extraction anywhere.** `tarfile` is imported in `bundle.py` and used
only to *create* a tarball (`"w:gz"`). No `extractall`, no `extract`, no
`zipfile`, no `shutil.unpack_archive`. The Tar Slip class does not apply.

**The ttylog parser is robust against hostile bytes.** A record claiming a
2 GB payload in an 8-byte file returns no chunks and allocates nothing; a
negative length returns no chunks; input above the 64 MB ceiling returns the
view-limit notice. Record-count amplification is 4.4×, proportional, not
explosive. Truncated recordings — the normal result of a hard kill — parse to the
last complete record without raising.

**Path traversal is refused.** `Queries.recording_path()` rejects
`../../etc/passwd`, absolute paths and anything that is not 64 hex characters
(tested, including a crafted `.part` suffix).

**Shell scripts are disciplined.** All nine use strict mode (`set -euo pipefail`,
or `-uo pipefail` where a health check must run every check and report). No
`eval`, no backticks, no unquoted `rm -rf $VAR`, no `curl | bash`. The
`healthcheck.sh` pattern of counting failures and exiting non-zero is correct.

**Redaction and storage are correctly separated.** Masking is display-only: the
stored event retains the true captured password (asserted by test), and masking
is not on the ingestion path, so a pathological command cannot stall evidence
collection.

**Session and audit integrity.** Tokens are stored only as SHA-256 hashes
(tested); a password change revokes live sessions (tested); the audit table
rejects `UPDATE` and `DELETE` through a trigger (tested); role changes invalidate
existing sessions.

**Authentication against published vectors.** TOTP is checked against all six
RFC 6238 Appendix B SHA-1 vectors at 6 and 8 digits, and the ±1 step window is
tested at both edges and beyond.

---

## 4. Tests added or changed by this audit

`tests/test_dashboard.py` — 39 tests before, **47 after**; all passing.

| Test | Guards |
|------|--------|
| `TestHeaderInjection` (5) | F-01: line breaks refused, allowlist intact, filename reduced, non-latin-1 refused before the status line |
| `TestSanitizerPerformance` (3) | F-02: 13 hostile payloads within budget, linear rather than quadratic growth, masking still correct |

Both regression tests were verified to *fail* against the pre-fix code, by
reinstating the old logic and running the test. A guard that passes on the bug it
describes provides false assurance, so this was checked rather than assumed.

---

## 5. Limitations — what this audit did not do

- **No browser was available.** The XSS consequence of F-01 (script execution
  via an injected `Content-Type`) is inferred from the wire capture, not
  demonstrated in a rendering engine. The header injection and response split
  themselves *are* demonstrated.
- **`realism/build_profile.py` (1744 lines) was not read in depth.** It was
  scanned for dynamic execution, unsafe YAML loading (`yaml.safe_load` — correct)
  and destructive operations (F-03). Its output correctness was not audited;
  that is what `tests/test_conformance.py` and the six build invariants cover.
- **The realism overlay (3 modules) was reviewed only for dynamic execution and
  error handling.** Its monkeypatches of `free`, `ps` and `service` were not
  re-tested; `tests/test_conformance.py` (196/197) and the lab probes are the
  evidence for those.
- **No fuzzing.** The ttylog parser was probed with specific adversarial inputs,
  not fuzzed. A coverage-guided fuzz run would be a reasonable follow-up.
- **The AWS guidance was not verified** against AWS documentation:
  `deploy/aws/security-groups.md` §4 and two environment-example claims remain
  formally unverified.
- **No TLS or reverse-proxy deployment was examined.** F-10 would matter more
  there.
- **Timing and memory figures are from this machine** and should be treated as
  order-of-magnitude, not exact. The quadratic-versus-linear distinction is
  robust; the absolute milliseconds are not.

---

## 6. Remediation status

Fixed in this session, with tests: **F-01**, **F-02**.

Unchanged, recommended in priority order: **F-03** (destructive delete — cheap
guard, large blast radius), **F-05** (lockout recovery — small change, removes an
operational trap), **F-04** (memory bound), **F-06** (fail loudly on a bad
filter), then F-07 through F-11.

One finding should be closed by a test rather than a patch: assert in
`tests/test_conformance.py` that `forward_redirect` and `forward_tunnel` are
false, because everything the isolation story claims about port forwarding
depends on two configuration values that nothing currently checks.

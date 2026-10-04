# 07 — Session playback

A read-only viewer for recorded sessions, for one reviewer at a time, reachable
only over a protected management path.

Source: `playback/server.py`. Unit: `deploy/systemd/cowrie-playback.service`.
Tests: `tests/test_playback.py` (32 checks).

---

## 1. Reaching it

The viewer binds to **127.0.0.1 only** and has **no authentication of its own**.
Its entire access control is the network boundary: you must already be
authorised to reach the host.

```bash
# On your workstation:
aws ssm start-session \
    --target i-xxxxxxxxxxxxxxxxx \
    --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["8081"],"localPortNumber":["8081"]}'
# then browse to http://127.0.0.1:8081
```

Start and stop it around a review rather than leaving it running:

```bash
sudo systemctl start cowrie-playback     # on demand
sudo systemctl stop  cowrie-playback     # when the review is done
```

The unit is installed but **deliberately not enabled**, so a session viewer with
access to captured credentials is not sitting on the host the rest of the time.

### Why the refusal is in the code

Binding to anything other than loopback requires an explicit
`--i-know-this-exposes-evidence` flag:

```
$ playback/server.py --host 0.0.0.0
refusing to bind to 0.0.0.0.
This interface serves captured credentials and session recordings with no
authentication of its own. Reach it through AWS SSM port forwarding: ...
```

The flag exists so that exposing it can only ever be a decision someone made on
purpose. **Do not put it behind a public load balancer or an internet-facing
ALB.**

---

## 2. What it shows

```
┌─────────────────┬──────────────────────────────────────────────────────────┐
│ sessions        │ [Play] [Step] [-5s] [+5s]  12.4s / 41.2s   0.25…8×       │
│                 │ ─────────────────────────────────────────────────────────│
│ 203.0.113.9     │ Terminal │ Command transcript │ File transfers            │
│ root · rejected │──────────────────────────────────────────────────────── │
│ 8.1s · no rec.  │ uname -a                                                  │
│                 │ Linux deploy-01 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC …  │
│ 198.51.100.7    │ whoami                                                    │
│ deploy · accept │ deploy                                                    │
│ 41.2s           │                                                           │
└─────────────────┴──────────────────────────────────────────────────────────┘
```

* **Session list** — source IP, username, login result, duration, and whether a
  recording exists. Filterable by IP, username or session id.
* **Terminal** — the recording replayed at its original timing. Play, pause,
  seek by dragging, step, ±5 s, and playback speed from 0.25× to 8×.
* **Command transcript** — every command derived from the recording, with a
  timestamp, clickable to seek the terminal to that moment, and searchable.
* **File transfers** — uploads and downloads with time, filename, size and
  SHA-256. Uploads are labelled `quarantined, not executed`. Click a row to seek
  the terminal to the moment of transfer.

### Duration and the timeline

Session durations come from `cowrie.session.closed` when present, and otherwise
fall back to the last recording timestamp, so the timeline is never empty just
because a close event is missing.

---

## 3. Why the recordings are filed by hash

Cowrie renames a finished recording to the SHA-256 of the visitor's input and
**deletes it if an identical recording already exists**. So:

* the viewer correlates recordings through the `cowrie.log.closed` event
  (`ttylog`, `shasum`, `duplicate`), not by session id;
* `duplicate: true` means the recording is stored under an earlier hash and is
  **shared**. This is not missing data;
* two sessions can legitimately display the same terminal content.

Anything built to consume Cowrie recordings must handle this. The viewer does;
a naive tool that globs `tty/<session_id>` finds nothing at all.

---

## 4. Safety properties, and how they are tested

A recording is **untrusted input**. A visitor fully controls what appears in it,
and they may be attacking whoever reviews the session. Every property below has
a corresponding test in `tests/test_playback.py`, including a deliberately
hostile recording that contains all of these attempts at once.

| Attack | Control | Test |
|---|---|---|
| ANSI escape sequences | Stripped before display | `test_escape_sequences_are_stripped` |
| OSC 52 clipboard write | OSC sequences stripped | `test_osc_sequence_is_stripped` |
| Bidirectional override (disguise a command's appearance) | Bidi control characters removed | `test_bidi_override_is_stripped` |
| Markup injection (`<script>`) | `<`, `>`, `&` escaped in the embedded JSON; all rendering via `textContent`, never `innerHTML` | `test_embedded_payload_cannot_close_script_element`, `test_html_in_recording_is_neutralised` |
| CSP nonce brute force | Per-start random nonce; `script-src 'nonce-…'` with **no** `unsafe-inline`; header nonce must match the tag | `test_serves_page_and_safety_headers` |
| Null bytes, other control characters | Removed | `test_control_characters_are_stripped` |
| Escape parameters leaking into the transcript | Escape sequences stripped **before** line assembly, so `\x1b[2J` does not become a literal `[2J` "command" | `test_escape_parameters_do_not_leak_into_transcript` |
| Secret exposure by default | Passwords and tokens masked; unmasking requires an explicit `?unmask=1` | `test_secrets_absent_by_default` |
| Path traversal via a poisoned log | Recording paths confined to the tty directory; `../../etc/shadow` and `/etc/hostname` both refused | `test_traversal_in_ttylog_path_is_refused`, `test_absolute_ttylog_path_outside_state_is_refused` |
| Corruption from a hard kill | Truncated log lines skipped; truncated recordings parsed up to the last whole record | `test_truncated_log_line_is_tolerated`, `test_truncated_recording_is_tolerated` |
| Accidental public exposure | Refuses to bind non-loopback without the explicit flag; exits 2 | `test_refuses_to_bind_publicly_without_acknowledgement` |

Headers on every response: `Content-Security-Policy` (nonce-based),
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
`Cross-Origin-Resource-Policy: same-origin`.

### The sandbox around the process

`cowrie-playback.service` runs the viewer as the unprivileged `cowrie` account
with `ProtectSystem=strict`, `ProtectHome=yes`, an empty
`CapabilityBoundingSet`, `MemoryDenyWriteExecute=yes`, and
`ReadOnlyPaths=/opt/cowrie` — so **even a compromised viewer cannot modify or
delete evidence**. Its `MemoryMax=512M` and `CPUQuota=50%` keep a large or
malformed recording from exhausting the host.

---

## 5. What playback does not do

* **It never executes anything.** Recorded bytes are decoded to text, masked,
  and displayed. They are never passed to a shell, never interpreted as a
  command, and never used to build a request.
* **It never modifies the original recording.** Masking and escaping apply to
  the displayed copy only. The file on disk is byte-for-byte what Cowrie wrote.
* **It never shows captured file contents.** The transfers tab renders metadata
  only — name, size, hash. Opening a captured file is a separate,
  deliberately-controlled activity described in `docs/06`.
* **It has no write endpoints.** There is no route that writes, deletes or
  changes anything. The only paths are `/`, `/index.html` and `/healthz`, and
  anything else is a 404.

---

## 6. Masking

On by default. The header shows `secrets masked — append ?unmask=1 to reveal`.

Masked patterns include `password=…`, `passwd:`, `pwd:`, `mysqldump -p…`,
`-passin`/`-passout`, `curl -u user:pass`, `wget --password=`,
`Authorization:`/`Bearer` tokens, AWS access key IDs (`AKIA…`/`ASIA…`), SSH
authorized-key blobs, and private-key headers.

Two details that matter:

* Masking runs **after** escape stripping. If it ran before, an attacker could
  split `password=` with an escape sequence and the masker would miss it
  (`test_masking_runs_after_escape_stripping`).
* A transcript row that contained a masked value is marked
  `(contained a masked value)` rather than silently showing something different
  from what the visitor typed.

`?unmask=1` is a query parameter precisely so that revealing secrets is a
deliberate action: the default view is safe to screen-share or project during a
review.

---

## 7. Known limitations

* **Exec-only sessions have no interactive transcript.** A command sent as an
  SSH exec request appears as a single `TYPE_INTERACT` record. The transcript
  shows it correctly as a command, but there is no shell history around it. The
  authoritative record for exec commands is `cowrie.command.input` in
  `cowrie.json`; the UI says so on the transcript tab.
* **Deduplicated recordings are shared.** See §3. Two sessions showing the same
  terminal output is expected, not a bug.
* **Timing is the recording's, not wall-clock.** Chunk offsets are relative to
  the first record in that file, so a session that idled for a long time between
  two commands shows that gap; a session with no traffic at all shows a short
  timeline.
* **Very large recordings are truncated for display** at 64 MiB per file, with a
  visible marker. The file on disk is untouched.
* **No authentication.** By design — loopback plus SSM. If you ever need to
  reach it from more than one place, put it behind a VPN rather than adding a
  login form.

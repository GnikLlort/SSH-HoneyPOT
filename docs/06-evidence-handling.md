# 06 — Evidence handling

Everything a visitor does to the honeypot is security evidence: the usernames
and passwords they tried, the commands they ran, and above all **the files they
uploaded and the files they tried to download**. This page is about treating
that material as evidence rather than as data.

Three rules, and everything else follows from them:

1. **Never execute, preview or open a captured file** on the honeypot or on a
   normal workstation.
2. **Never send captured data to a third party by default** — no public LLM, no
   threat-intel API, no chat webhook.
3. **Preserve the original bytes unchanged**, and keep them somewhere the
   honeypot cannot reach.

---

## 1. What is captured

| Artefact | Location on the host | What it contains |
|---|---|---|
| Event record | `var/log/cowrie/cowrie.json` | One JSON object per line: connects, authentication attempts and outcomes, every command, uploads, downloads, session close |
| Human log | `var/log/cowrie/cowrie.log` | Same events, plain text |
| Session recordings | `var/lib/cowrie/tty/*` | Full terminal transcript, both directions |
| Captured uploads | `var/lib/cowrie/downloads/*` | The original bytes of every file an attacker uploaded via SFTP or SCP |
| Download attempts | recorded in `cowrie.json` only | URL, command, session, and hash where Cowrie learned one |

The parts that are **sensitive**, in order: captured uploads (potentially
malware), credentials typed during authentication, and session recordings —
which contain both.

### A note on recording filenames

Cowrie renames a finished recording to the **SHA-256 of the visitor's input**,
and **deletes the file outright if an identical recording already exists**. This
has two consequences that bite in practice:

* Recordings are identified by hash, not by session id. Correlating them
  requires the `cowrie.log.closed` event, which carries `ttylog`, `shasum` and
  `duplicate`.
* `duplicate: true` means the session's recording was byte-identical to an
  earlier one and is stored under that earlier hash. It does **not** mean the
  recording is missing. Any tool that looks up recordings by session id will
  silently show nothing.

The playback UI handles both correctly (see `docs/07`).

---

## 2. Upload quarantine

**On capture**, Cowrie writes the upload to `var/lib/cowrie/downloads/` under a
name derived from its SHA-256, and emits `cowrie.session.file_upload` with
`filename`, `shasum` and `size`. The original filename is recorded in the event
but is **not** used as a path — a file uploaded as `../../etc/passwd` is stored
by hash, never at that path.

**Uploads are never executed.** Nothing in this package runs, opens, parses or
previews a captured file. Not the honeypot, not the health check, not the
alerting path, not the playback UI (which renders metadata only: name, hash,
size, and a labelled "quarantined" note).

**Within 5 minutes**, `ops/quarantine_sync.sh` ships the capture to the evidence
store:

1. Builds a manifest listing the SHA-256 of every captured file.
2. Uploads the manifest **first**, so truncation or substitution is detectable.
3. Uploads the logs, recordings and captured files with SSE-KMS.
4. Prunes local copies **only after** the copy is verified.

Copy-then-verify-then-delete, never the other order. Deleting first and copying
second is how evidence gets lost.

### Storage limits and retention

| Control | Value | Where |
|---|---|---|
| Per-file cap | 64 MiB | `download_limit_size` in `config/cowrie.cfg` |
| Aggregate warn | 2048 MiB | `QUARANTINE_WARN_MB` |
| Aggregate critical | 4096 MiB | `QUARANTINE_CRITICAL_MB` |
| Local retention | 30 days | `RETENTION_DAYS_LOCAL` |

When the aggregate cap is exceeded, uploads are still recorded in the event log
but the bytes are pruned oldest-first after shipping, and an alert fires. **The
event record survives even when the bytes do not** — the filename, session,
timestamp and SHA-256 are what matter for correlation and for checking against
threat-intel feeds, and those are in JSON, not in the file.

This is deliberate: an attacker must not be able to fill the disk by uploading.
The honeypot stops recording when the disk is full, which is exactly what an
attacker who wants to operate unobserved would like.

---

## 3. Download attempts

This deployment **does not auto-fetch files from attacker-controlled URLs**.
Cowrie records the attempt — the URL, the command, the session, and a hash when
it can compute one — and the emulated `wget`/`curl` answer inside the honeypot's
fake network stack. Nothing leaves.

If you need the actual bytes, retrieve them through a **separately controlled
collection process**, deliberately and by hand:

* from a dedicated collection host with no route to production or personal
  systems,
* with the URL treated as hostile input (it is chosen by the attacker),
* recording the request, the response, and the time in the case notes.

The session evidence that the attempt happened — URL, command line, timestamp,
session id — is preserved regardless. That is usually what an investigation
needs; the bytes are a separate decision.

---

## 4. Inspecting a capture safely

**Analysis requires a separate disposable environment.** Not the honeypot, not
the honeypot host, not a workstation you use for anything else.

Minimum conditions for an analysis environment:

* A disposable VM or sandbox with **no route to production or personal
  systems**, and no credentials of any kind.
* No shared folders, no host clipboard, no USB passthrough, no shared
  credentials.
* Snapshotted before analysis, reverted (not cleaned) after.
* The original stays in quarantine. **Analyse a copy** — the original's hash is
  evidence, and analysis can alter it.
* Egress denied by default, with a documented exception if you need to fetch a
  sample for comparison.

Recommended order of operations:

1. **Record the metadata first**, before doing anything with the bytes:
   filename, SHA-256, size, session id, timestamp, transfer method. This is what
   you will still have if the analysis environment is destroyed.
2. Compute the hash yourself from the quarantined original and confirm it matches
   the manifest. A mismatch means the transfer or the store is broken, and you
   need to know that before you trust anything else.
3. Only then copy into the analysis environment.
4. Never attribute the file to a person or an organisation based on the
   upload alone. It is routine for tooling to upload files that are years old,
   and for one actor's tooling to be reused by others.

**Do not open a capture on the honeypot host to "take a quick look".** That is
the single most likely way this deployment causes harm.

---

## 5. Access control and retention

| Control | Implementation |
|---|---|
| Restrict access | Evidence lives in a separate AWS account. Read access via the evidence-administrator role only. |
| Encrypt storage | SSE-KMS with a customer-managed key in the evidence account. Vault and instance volumes encrypted at rest. |
| Prevent destruction | S3 Object Lock (governance or compliance mode) with a retention period at least as long as your obligation; bucket policy denies `s3:DeleteObject` to the honeypot's principal. |
| Audit access | CloudTrail management events enabled in the evidence account; every read of the bucket is logged. |
| Define retention | Object Lock retention for the archive; `RETENTION_DAYS_LOCAL` for the on-host cache. |
| Never public | Block Public Access enabled on the bucket. No presigned URLs that outlive the investigation. |

**Retention is a commitment, not a default.** Decide how long you must keep this
material — it may be set by policy, by an incident, or by law — and set the
Object Lock period accordingly. Object Lock in compliance mode cannot be
shortened, not even by the account root, which is a feature when the material is
evidence and a liability if you set the period carelessly.

---

## 6. Deliberately disabled: third-party data sharing

These Cowrie output plugins are **off**, and the reason is not configuration
taste:

| Plugin | What it would send | Where |
|---|---|---|
| VirusTotal | Uploads an attacker's file, or its hash | A commercial third party |
| DShield / SANS ISC | Source IP, ports, credentials tried | A public research feed |
| GreyNoise | Source IP | A commercial third party |
| AbuseIPDB | Source IP, with a report | A public reputation service |
| Slack / Telegram / Discord | Session events as messages | A commercial chat service |

Each of them transmits data about a visitor to a third party by design. That is
a decision about someone else's data — the visitor's credentials, and a file
that may contain someone else's information — and it is not a decision a config
file should make silently. A public feed also tells anyone watching that you run
a honeypot, and how much attention it gets.

If you decide to enable one:

* Understand that a submitted file may be redistributed by the recipient.
* Prefer submitting **hashes** over files, and only where the hash is not
  itself sensitive.
* Never submit session recordings or credentials.
* Note in the deployment record that you enabled it and why.

`ops/alert_dispatch.sh` is the one outbound path, and it is deliberately
different: it posts to **your own** webhook, and its payload contains **no
captured data** — no passwords, no command text, no filenames. Rule name,
severity, sensor, UTC timestamp, and the facts needed to triage. Keep it that
way if you modify it.

---

## 7. Correlation before action

**Never automatically ban or report an IP solely because it connected to the
honeypot.**

The honeypot is built to attract connections. A connection is evidence of
nothing on its own: it is produced by internet background noise, by scanners
doing someone else's inventory, by a misconfigured device scanning its local
subnet, and by your own monitoring. It is also trivially caused by anyone who
wants a specific IP to look bad, by connecting from that IP — or simply by
spoofing it.

Before acting on any session:

1. Correlate the source IP across multiple sessions and multiple sensors, with
   timestamps.
2. Look for behaviour, not presence: what did they try, what did they upload,
   did they succeed, how long did they stay.
3. Treat uploaded file hashes as the strongest indicator, and still check them
   against real intelligence rather than assuming.
4. Remember that IP addresses are shared, reassigned, and frequently not the
   operator.

`ops/alerts/rules.md` carries the same rule at the point of use, because that is
where someone will be tempted to break it.

# Alert rules

These are the conditions that should page a human. They are expressed here as
the canonical definitions; the implementation lives in whatever the operator
actually runs (CloudWatch Logs metric filters, Grafana/Loki rules, or the
on-host `healthcheck.sh`).

Design rules used throughout:

* **Alert on absence, not only presence.** A honeypot that stops recording is
  indistinguishable from a quiet one unless you alert on the absence of events.
* **Never alert on a single connection.** A single probe is noise. Alerts fire
  on patterns that have meaning in aggregate.
* **Never auto-ban or auto-report an IP.** See the note at the bottom.
* **Do not put evidence in the alert.** The alert says "go and look"; it names
  the sensor and the event key, not the captured command or credential.

---

## Priority 1 — page immediately

| Event key | Condition | Why it matters |
|---|---|---|
| `isolation_broken` | The `cowrie` account can read `/etc/shadow`, `/root`, or any real user's home | The boundary has failed. Assume the honeypot host is compromised and rebuild. |
| `service_down` | `cowrie.service` not active for 5 minutes | The honeypot is collecting nothing. |
| `ssh_no_banner` | Port 22 accepts TCP but sends no SSH banner within 10s | The reactor is wedged. Observed in testing after an unbounded `find /`; the host looks healthy to a port check while recording nothing. |
| `disk_critical` | Filesystem ≥ 92% full | Captured files are about to stop being written. |
| `canary_leak` | Any canary value found outside the emulated filesystem | Synthetic content escaped, or real content was copied in. |

## Priority 2 — notify during working hours

| Event key | Condition | Notes |
|---|---|---|
| `session_accepted` | A `cowrie.login.success` event | One of the highest-signal events: someone got in. Includes a link to the session recording. |
| `file_upload` | A file captured via SCP/SFTP | Always worth a look. The file is quarantined, never executed. |
| `repeated_login_attempts` | ≥ 5 `cowrie.login.failed` from one source IP within 300 s | Correlate before acting. Applies to *failed* attempts; a single connection never triggers anything. |
| `sensitive_command` | Any pattern from `identity.yaml: alerts.sensitive_command_patterns` | Keyed on command *shape*. Recorded, not acted on. |
| `quarantine_warn` | Captured files total ≥ 2 GB | Storage policy is working; this is the early warning. |
| `disk_warn` | Filesystem ≥ 80% full | |
| `log_stale` | No event written for 24 h | On a public IP this almost always means the service is broken, not that the internet went quiet. |
| `service_restart_loop` | More than 3 restarts in 15 minutes | Cowrie's reactor can be wedged into a state where it ignores SIGTERM; repeated restarts usually mean that. |

## Priority 3 — digest only

| Event key | Condition |
|---|---|
| `new_source_asn` | A source IP from an ASN not seen in the last 30 days |
| `new_credential_pair` | A username/password combination not seen before |
| `long_session` | Session duration > 30 minutes |
| `outbound_unexpected` | Outbound connection observed while the shipper is idle |

---

## Thresholds

Thresholds live in `realism/identity.yaml` under `alerts:` so they are versioned
with the identity they describe:

```yaml
alerts:
  repeated_login_attempts:
    count: 5
    window_seconds: 300
  disk_growth:
    download_dir_warn_mb: 2048
    download_dir_critical_mb: 4096
    filesystem_warn_percent: 80
    filesystem_critical_percent: 92
```

---

## Do not auto-ban, do not auto-report

This is a deliberate restriction, not an oversight.

**Do not automatically block source IPs.** Honeypot traffic is routinely:

* scanners with no operator behind them,
* researchers, including people testing *your* honeypot deliberately,
* compromised third-party hosts whose real owner is also a victim,
* NAT and CGNAT egress points shared by thousands of unrelated users,
* and your own future testing, which an auto-ban will lock out.

Blocking on a single connection turns the honeypot into a source of outages for
innocent third parties and destroys your ability to study the traffic.

**Do not automatically report IPs to abuse feeds.** The same list above applies,
and automatic reporting from a honeypot that accepts weak credentials
manufactures false positives at scale. It also burns the honeypot's cover.

**Do this instead.** Treat every alert as a pointer to evidence, then
correlate:

1. Read the session recording (`docs/07-session-playback.md`).
2. Check the same source against your other sensors — is the behaviour
   consistent across them, or is this one connection an outlier?
3. Check the source's ASN and whether it is a known scanner range.
4. Ask whether the observed behaviour is *distinctive* — real tooling, real
   post-authentication activity — or whether it is a generic credential sweep
   that every internet-facing host sees.

Only after correlation should a human decide whether blocking or reporting is
warranted, and that decision should be recorded with its justification.

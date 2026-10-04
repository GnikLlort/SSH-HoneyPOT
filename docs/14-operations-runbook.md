# 14 — Operations runbook

Day-to-day operation: what runs automatically, what to check, and what to do
when something is wrong.

Related: `ops/alerts/rules.md` (thresholds and response), `docs/11` (rollback
and rebuild), `deploy/aws/security-groups.md` (boundary verification).

---

## 1. What runs without you

| Timer | Every | Runs | What it does |
|---|---|---|---|
| `cowrie-logship.timer` | 5 min | `ops/quarantine_sync.sh` | Ships log, recordings and captures to the evidence bucket, manifest first, prunes only after a verified copy |
| `cowrie-healthcheck.timer` | 5 min | `ops/healthcheck.sh` | Service, SSH banner, log staleness, disk, outbound, isolation |
| `logrotate` (system cron) | daily | `ops/logrotate/cowrie` | Rotates `cowrie.log` and `cowrie.json` with `copytruncate` |
| `logrotate` → `prune_local.sh` | daily | `ops/prune_local.sh` | Prunes local evidence older than `RETENTION_DAYS_LOCAL` |

`copytruncate` is required, not a preference: Cowrie holds its log files open,
and a rotate-and-move would leave the process writing to a file that the
rotator has already moved away.

---

## 2. Daily

```bash
# Any alerts in the last day?
sudo tail -50 /var/log/cowrie-alerts.log

# Is evidence still leaving?
aws s3 ls --recursive s3://<bucket>/<prefix>/ | tail -5

# Anything unusual in authentication?
sudo jq -r 'select(.eventid=="cowrie.login.success") | "\(.timestamp) \(.src_ip) \(.username)"' \
    /opt/cowrie/var/log/cowrie/cowrie.json | tail -20
```

**What "normal" looks like:** a lot of `cowrie.login.failed`, very few
`cowrie.login.success`, and a steady trickle of objects into the evidence
bucket. Successful logins are the interesting ones precisely because they are
rare — that is what the credential policy is for.

---

## 3. Weekly

```bash
# Health check history
sudo grep -c ALERT /var/log/cowrie-healthcheck.log

# Disk
df -h /opt/cowrie

# Quarantine size against the configured caps
du -sh /opt/cowrie/var/lib/cowrie/downloads
grep QUARANTINE /etc/cowrie-logship.env

# Canary check — nothing synthetic should be on the real filesystem
sudo /usr/local/sbin/canary_scan.sh

# Isolation boundary (all of these should fail)
sudo -u cowrie nc -vz -w 3 10.0.0.10 443
curl -s -m 3 http://169.254.169.254/latest/meta-data/
```

**The canary scan is the one that matters.** A canary value on the real
filesystem means either an escape or contamination, and both need investigating
before anything else.

---

## 4. Reviewing a session

1. Start the playback UI:

   ```bash
   sudo systemctl start cowrie-playback
   ```

2. Port-forward over SSM (`docs/07` §1) and open `http://127.0.0.1:8081`.

3. Review: terminal replay, command transcript, file transfers. Secrets are
   masked by default; `?unmask=1` reveals them, deliberately.

4. Stop it when you are done:

   ```bash
   sudo systemctl stop cowrie-playback
   ```

It is not enabled at boot. A viewer with access to captured credentials should
not be sitting on the host the rest of the time.

---

## 5. Alert response

Full thresholds are in `ops/alerts/rules.md`. Summary:

| Severity | Examples | Response |
|---|---|---|
| **P1** | Captured-file volume critical; service not answering; unexpected outbound traffic; canary found on the real filesystem; isolation check succeeded | Investigate now. For any isolation finding, fix the boundary before anything else |
| **P2** | Service restarted; log shipping failed; disk above warn; repeated authentication failures above threshold | Same day |
| **P3** | First successful login in a period; new upload hash; a sensitive command pattern | Review within a week, in context |

**A successful login is P3, not P1.** The honeypot is built for attackers to
succeed occasionally — that is what produces the best telemetry. Treating it as
an emergency teaches you to ignore alerts.

---

## 6. Common problems

| Symptom | Diagnosis | Action |
|---|---|---|
| Port bound, TCP accepted, no SSH banner | **Wedged reactor** — a pathological command hung the Twisted reactor. The health check detects this | `sudo systemctl kill -s SIGKILL cowrie`, then `start`. Preserve evidence first if it happened during something interesting |
| `systemctl stop` does not return | Same cause; the process ignores `SIGTERM` | `systemctl kill -s SIGKILL`, `rm -f /opt/cowrie/var/run/cowrie.pid`, then start |
| No events for hours | Listener or security group | `ss -ltnp \| grep :22`; check the inbound rule from outside |
| `twistd --umask=0022: Unknown command: cowrie` | Stale Twisted plugin cache | `/opt/cowrie/venv/bin/python /opt/cowrie/build/cowrie/bin/regen-dropin.cache` |
| Commands answer `Exec format error` | `txtcmds_path` missing or under the wrong section — it belongs to `[honeypot]` | Check `/opt/cowrie/share/txtcmds` exists and is populated |
| Log shipping fails | Credentials, bucket policy, or outbound rule | Run `quarantine_sync.sh` by hand as `cowrie` and read the error. Check the allow-list still permits tcp/443 to the endpoint |
| Disk filling | Upload flood, or shipping failing so pruning never qualifies | Check `/var/log/cowrie-alerts.log`; confirm shipping succeeds — pruning only runs after a verified ship |
| `ps` or `free` output looks wrong | Overlay not loaded, or a patch fell back to stock | `journalctl -u cowrie \| grep -i overlay`. Check the two environment lines in the unit. `free` should still be safe: the bind-mount masks the real memory either way |
| Conformance suite fails after a profile edit | Manifest and generated artefacts out of step | Rebuild the profile, reinstall, restart (`docs/04` §1) |

---

## 7. Routine maintenance

| Task | Cadence | Note |
|---|---|---|
| Apply OS security updates | Monthly | `apt-get upgrade`, then restart. Record it |
| Refresh the honeypot profile | Quarterly | A pinned point release that never ages is itself a signal (`docs/10` §6). Edit `realism/identity.yaml`, rebuild, restart, re-run the suite |
| Review the credential policy | Quarterly | Decide whether the account is still reachable by the passwords you intend |
| Verify the evidence export | Monthly | Restore a manifest and confirm the hashes match. An unverified backup is a hope |
| Rotate SSH host keys | On any suspicion | A reused host key is a fingerprint and a link |
| Review access to the evidence bucket | Quarterly | Who can read captured credentials and other people's files |
| Re-read `docs/02` | Yearly | The threat model is a claim about the world. The world changes |

---

## 8. Incident: suspected honeypot compromise

1. **Preserve evidence first.** `sudo -u cowrie /usr/local/sbin/quarantine_sync.sh`
   — before restarting, before investigating, before anything.
2. **Note the time and what you observed.** Get it into the record while it is
   fresh.
3. **Isolate the host.** Remove the inbound tcp/22 rule. Do not "fix" the host.
4. **Check the boundary.** Was anything reachable that should not have been?
   `deploy/aws/security-groups.md` §6. The answer determines whether this is a
   honeypot problem or a much bigger one.
5. **Export and verify.** `deploy/rebuild.sh --export-only --verify`.
6. **Terminate, do not repair.** A honeypot host that has been interacted with
   is not trustworthy (`docs/11` §2). Rebuild on a new instance with fresh host
   keys.
7. **Assume the evidence bucket is intact but verify it** — and if it was in the
   same account as the host, treat its integrity as unproven and say so in the
   record.
8. **Write it up** while it is still fresh. What was the signal, what did you
   check, what did you find, what changed as a result.

---

## 9. Turning it off

```bash
sudo ./deploy/uninstall.sh --stop                  # stop, keep everything
sudo ./deploy/uninstall.sh --remove \
     --i-understand-this-destroys-evidence         # delete everything
```

Then **remove the inbound tcp/22 rule**. A host with no honeypot and an open
SSH port is just an unmanaged server.

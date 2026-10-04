# 11 — Rollback and rebuild

Two different operations, and confusing them destroys evidence.

| Operation | Command | What happens to evidence |
|---|---|---|
| **Rollback** — undo the deployment, keep everything | `deploy/uninstall.sh --stop` | Preserved on disk and in the evidence bucket |
| **Rebuild** — replace the host, keep the evidence | `deploy/rebuild.sh --export-only` then install fresh | Exported and verified *before* the old host is destroyed |
| **Destroy** — remove the honeypot and its captures | `deploy/uninstall.sh --remove` | **Irreversibly deleted** |

---

## 1. Rollback: stop the honeypot, keep the data

```bash
sudo ./deploy/uninstall.sh --stop
```

**What it does:** stops and disables `cowrie.service`, `cowrie-healthcheck.timer`
and `cowrie-logship.timer`. Nothing is deleted.

**Effect on the server:** the port stops listening. `/opt/cowrie` — logs,
recordings, captured files, generated profile — is untouched. The service
account, the config and the systemd units remain, so `systemctl enable --now
cowrie` brings it straight back.

**No AWS changes.** The security group, the routing and the evidence bucket are
not modified. **You must remove the inbound tcp/22 rule yourself** if you want
the instance to stop attracting traffic — the uninstaller deliberately does not
touch AWS.

### Reverting the realism overlay only

If you suspect the overlay is causing a problem, disable it without touching
anything else:

```bash
sudo systemctl edit cowrie    # add: [Service] Environment=COWRIE_REALISM_OVERLAY=0
sudo systemctl daemon-reload && sudo systemctl restart cowrie
```

Cowrie then behaves exactly as the pinned upstream release. Three of the
realism fixes are lost (`ps`, `free`, `service`), but **the synthetic
`/proc/meminfo` bind-mount stays in force**, so the `free` leak remains closed.
That separation is deliberate: `docs/04` §3.

### Reverting the credential policy

Replace `<state>/etc/userdb.txt` with a stricter version and restart. Deleting
all but the first `deploy` line leaves the account reachable only with its
synthetic password.

### Rolling the profile back

Every build is reproducible from `realism/identity.yaml` plus the Cowrie pin:

```bash
git -C /opt/cowrie/share/pkg log --oneline -1 realism/identity.yaml
sudo /opt/cowrie/venv/bin/python /opt/cowrie/share/pkg/realism/build_profile.py \
    --identity /opt/cowrie/share/pkg/realism/identity.yaml \
    --out /opt/cowrie/build/profile
sudo systemctl restart cowrie
```

Rebuild is deterministic apart from timestamps; pass `--now` to pin the build
time and make it fully reproducible.

---

## 2. Rebuild: replace the host, preserve the evidence

The documented recovery path when a host is suspected compromised, when a
version pin changes, or when the profile is edited.

**The rule that makes this safe: export first, verify, and only then destroy.**
A honeypot host that has been interacted with is not trustworthy — you rebuild
on a **new instance**, never in place.

### Step 1 — export everything

```bash
sudo /opt/cowrie/share/pkg/deploy/rebuild.sh --export-only
```

**What it does:** runs the same shipping path as the 5-minute timer, but
synchronously and without pruning. Logs, recordings and captured files go to the
evidence bucket, with a SHA-256 manifest written first.

### Step 2 — verify the export

```bash
sudo /opt/cowrie/share/pkg/deploy/rebuild.sh --export-only --verify
```

**What it does:** uploads, then confirms the objects exist and the manifest
matches. **Do not continue until this passes.** Check by hand too:

```bash
aws s3 ls --recursive s3://<bucket>/honeypot/<sensor>/ | wc -l
aws s3 cp s3://<bucket>/honeypot/<sensor>/<latest>/manifest.txt - | head
```

### Step 3 — record what you are destroying

Before terminating anything, write down:

* instance ID, public IP, availability zone;
* the Cowrie version and commit, and the `realism/identity.yaml` hash;
* the evidence bucket prefix and the export timestamp;
* why you are rebuilding (suspected compromise, pin change, profile change);
* your name and the date.

This is the record that makes the loss of the host auditable.

### Step 4 — terminate the old instance

Terminate it; do not stop it and do not reuse it. A stopped instance retains its
disk, its host keys and its state.

```bash
aws ec2 terminate-instances --instance-ids i-xxxxxxxxxxxxxxxxx
```

### Step 5 — build the replacement

Follow `docs/03-install-ubuntu-ec2.md` from the top, on a **new** instance.

Two things to carry over deliberately:

* **Generate fresh SSH host keys.** Do not reuse them. A reused host key is a
  strong fingerprint and, if the old host was compromised, a link between the
  two.
* **Point at the same evidence bucket but a new sensor prefix,** so the old
  evidence is not overwritten and the two eras stay distinguishable.

### Step 6 — confirm the replacement

```bash
sudo /opt/cowrie/venv/bin/python tests/test_conformance.py \
    --expect build/profile/expectations.json --host 127.0.0.1 --port 22
sudo -u cowrie /usr/local/sbin/quarantine_sync.sh
aws s3 ls s3://<bucket>/honeypot/<new-sensor>/
```

Then run the isolation checks in `deploy/aws/security-groups.md` §6. **All of
them should fail.**

---

## 3. Destroy: remove everything

```bash
sudo ./deploy/uninstall.sh --remove --i-understand-this-destroys-evidence
```

**What it does:** stops the service, then deletes the state directory — logs,
recordings, **and every captured file** — and removes the service account.

**The guard exists because this is irreversible.** `--remove` prints what it
will delete and refuses to proceed without the explicit flag. Captured files are
evidence, and they may be the only record of an attempted intrusion.

**And the path itself is checked before anything is removed.** `STATE_DIR` is a
variable, and it is overridable in `/etc/cowrie-logship.env` — so the script
refuses to delete a path unless it is the default `/opt/cowrie` or looks like a
honeypot state directory (`var/lib/cowrie`, `etc/cowrie.cfg` or
`venv/bin/cowrie`), and it never deletes `/`, a system directory, a symlink, a
mount point or the current working directory. `--force-path` overrides only the
first of those checks. If you see a refusal and do not recognise the path it
names, do not force it: that message is the guard doing its job.

Before running it, be able to answer yes to both:

1. Has everything been exported and verified? (`rebuild.sh --export-only --verify`)
2. Is the retention obligation on this material satisfied — policy, incident, or
   legal?

**The evidence bucket is not touched.** Removing it is a separate, deliberate
action in the evidence account, and Object Lock may prevent it within the
retention window. That is by design.

Afterwards, remove the inbound tcp/22 rule from the security group. An instance
with no honeypot and an open SSH port is just an unmanaged server.

---

## 4. Emergency: the service will not stop

**Symptom:** the session hangs, the port stays bound, `systemctl stop cowrie`
does not return.

**Cause:** the wedged-reactor failure mode, documented in `docs/10` §2.4. The
process ignores `SIGTERM`.

```bash
sudo systemctl kill -s SIGKILL cowrie
sudo systemctl status cowrie --no-pager
```

If it still will not die:

```bash
sudo systemctl stop cowrie
ps -eo pid,comm,args | grep -i twistd
sudo kill -9 <pid>
sudo rm -f /opt/cowrie/var/run/cowrie.pid
sudo systemctl start cowrie
```

Then **preserve what is still on disk before restarting**, if the wedge happened
during something interesting:

```bash
sudo -u cowrie /usr/local/sbin/quarantine_sync.sh
```

Removing the pid file is sometimes necessary because a `SIGKILL`ed process
leaves it behind.

---

## 5. Recovering from a lost or unreachable host

If the instance is gone and the evidence bucket is intact, you have lost at most
the last 5 minutes of activity (the shipping interval) plus anything written
since the last successful ship. To rebuild:

1. Confirm the evidence bucket's contents in the separate account.
2. If the bucket was in the *same* account as the host, treat its integrity as
   suspect and say so in the record — an attacker who reached the host's
   principal may have been able to reach the bucket.
3. Follow step 5 of §2 above.

**If the bucket is gone too,** the deployment produced no lasting record. That
is the failure this whole evidence design exists to prevent: it is why the
bucket belongs in a separate account, with versioning, Object Lock and a policy
that denies deletion to the honeypot.

---

## 6. Rolling back a version pin

`deploy/versions.env` is the single place a version is written down.

```bash
# In the repository:
$EDITOR deploy/versions.env          # change COWRIE_COMMIT to the previous pin
git commit -am "pin cowrie back to <previous>"
# On the honeypot, from the source checkout (docs/03 creates it at
# /root/honeypot-src; /opt/cowrie/share/pkg has no .git and is not a checkout
# you can pull):
cd /root/honeypot-src
sudo git fetch origin && sudo git checkout <the commit with the older pin>
sudo ./deploy/install.sh --apply
sudo systemctl restart cowrie
```

`deploy/update.sh --apply` does the same thing with a dry run, a dirty-tree
check and a recorded rollback path; `docs/17` is the whole procedure, including
what an update overwrites and what it never touches.

`install.sh` is idempotent: it checks out the new commit, reinstalls into the
existing virtualenv and reinstalls the generated profile. The overlay is
version-guarded, so if the new pin does not match the release it was validated
against, `verify_targets()` refuses to load and Cowrie runs stock — degraded
realism, not a broken service.

Then re-run the conformance suite. A pin change that is not followed by the
suite passing is an untested change.

# 17 — Updating an installed deployment

How to put a different branch, tag or commit on a host that is already running,
without losing evidence and without guessing what changed.

The rule that makes this safe: **the installer is idempotent, and an update is
just the installer run again.** `deploy/install.sh` checks each stage, refreshes
what it owns, and leaves the evidence directory alone. `deploy/update.sh` wraps
that with the pre-flight checks, a record of what it replaced, and the rollback
command.

Rollback and rebuild are different operations, and `docs/11` covers those;
this page is the one you want for "there is a new branch, put it on the
sensor".

---

## 1. What an update touches, and what it does not

| Path | On update |
|---|---|
| `/opt/cowrie/build/cowrie` (the Cowrie checkout) | **refreshed** — fetched and re-checked-out at the pin in `deploy/versions.env` |
| `/opt/cowrie/venv` | Cowrie and its dependencies reinstalled |
| `/opt/cowrie/build/profile` | **regenerated** from `realism/identity.yaml` |
| `/opt/cowrie/etc/cowrie.cfg`, `etc/userdb.txt` | **overwritten** from the repository |
| `/opt/cowrie/etc/profile.cfg`, `var/lib/cowrie/fs.pickle`, `cmdoutput.json`, `share/txtcmds/` | **overwritten** from the regenerated profile |
| `/opt/cowrie/share/pkg` | **overwritten** from the source checkout |
| `/etc/systemd/system/cowrie*.service`, `*.timer` | **overwritten** from the repository; `daemon-reload` and restart follow |
| `/opt/cowrie/var/log/cowrie/*` | untouched |
| `/opt/cowrie/var/lib/cowrie/tty/*`, `downloads/*` | untouched |
| `/opt/cowrie/DEPLOYMENT.txt`, `UPDATE-LOG.txt` | rewritten / appended |
| `/etc/cowrie-logship.env` | untouched (the installer never writes it) |

Two consequences worth reading twice:

* **`etc/cowrie.cfg` and `etc/userdb.txt` are files the installer owns.** If you
  edit them on the host, the next update discards the edit. Make the change in
  the repository (`config/cowrie.cfg`, `config/userdb.txt`), commit it, and let
  the update carry it — that is also the only version of the change that is
  recorded anywhere.
* **Nothing under `var/` is touched.** Recordings, captured files and the event
  log survive an update, a failed update and a rollback. If you want them
  somewhere else before you start, that is `ops/quarantine_sync.sh`, and
  `deploy/rebuild.sh --export-only --verify` is the version that refuses to
  continue until the copy is verified.

---

## 2. The normal case: update to a branch

On the honeypot, from the checkout the installer was run from — `docs/03`
creates it at `/root/honeypot-src`:

```bash
cd /root/honeypot-src
sudo git fetch origin
sudo git checkout <branch>          # or: git checkout --detach <commit>
sudo ./deploy/update.sh --apply     # add --ref <branch> instead of checking out by hand
```

`deploy/update.sh` does this, in order, and stops at the first thing that is
wrong:

1. finds the source checkout (`--source`, `$HONEYPOT_SOURCE`, the script's own
   directory, then `/root/honeypot-src`);
2. fetches, resolves `--ref`, and prints the commits it is about to apply;
3. refuses a **dirty working tree** — the installer copies the tree as it is on
   disk, so uncommitted edits would be deployed while `DEPLOYMENT.txt` names a
   commit that does not contain them. `--force-dirty-tree` overrides that,
   deliberately and loudly;
4. refuses a host with no `/opt/cowrie/etc` (nothing installed here), and warns
   if the health check was already failing or the disk is under 2 GB free;
5. runs `deploy/install.sh --apply`;
6. restarts `cowrie.service` and the health check timer, and says so plainly if
   the unit does not come back;
7. appends the update to `/opt/cowrie/UPDATE-LOG.txt`, including the commit it
   replaced.

Dry run first — it prints the plan and changes nothing:

```bash
./deploy/update.sh --ref <branch>
```

See what is available before choosing:

```bash
./deploy/update.sh --list
```

### Updating by hand

The wrapper is a convenience, not a requirement. The equivalent, and what to do
if the wrapper itself is broken:

```bash
cd /root/honeypot-src
sudo git fetch origin && sudo git checkout <ref>
sudo ./deploy/install.sh                    # read the plan
sudo ./deploy/install.sh --apply
sudo systemctl restart cowrie.service cowrie-healthcheck.timer
```

`install.sh` is dry-run by default and prints every command with the reason for
it. Read the plan the first time; it tells you which stages will actually do
work this run.

### Changing the Cowrie pin

The pin is a two-line change in `deploy/versions.env`
(`COWRIE_VERSION` and `COWRIE_COMMIT`). An update picks it up because stage 4
re-checks-out the build tree and re-installs into the existing virtualenv.

The realism overlay is version-guarded: if the new pin does not match the
release the overlay was validated against, `verify_targets()` refuses to load
and Cowrie runs stock. That is a degraded-realism outcome, not a broken
service — but it is also the reason to re-run the conformance suite after any
pin change (`docs/11` §6).

---

## 3. What to check afterwards

```bash
systemctl status cowrie --no-pager
sudo -u cowrie /usr/local/sbin/healthcheck.sh
journalctl -u cowrie -n 40 --no-pager
```

Then the suite that says whether the emulated host still is what it claims:

```bash
cd /root/honeypot-src
python3 tests/test_conformance.py \
    --expect /opt/cowrie/build/profile/expectations.json \
    --host 127.0.0.1 --port 22
```

Expected result is the one in the README table: 197/198 with zero actionable
failures (the one `info` line is the `paramiko` interop probe, which says
"paramiko is not installed" if it is not). A pin change that is not followed by
the suite passing is an untested change.

Finally, confirm from outside that the sensor still behaves as a host:

```bash
ssh -o StrictHostKeyChecking=no -p 22 deploy@<host> 'uname -a; uptime'
```

---

## 4. Rolling back

Every update records what it replaced, so rollback is one command:

```bash
sudo ./deploy/update.sh --rollback --apply
```

That reads `previous-commit:` from `/opt/cowrie/UPDATE-LOG.txt`, checks it out
in the source tree and runs the installer again. To go somewhere else:

```bash
sudo ./deploy/update.sh --ref <commit-or-tag> --apply
cat /opt/cowrie/UPDATE-LOG.txt        # the whole update history
```

Rollback restores code, configuration and the generated profile. It does not
and cannot undo anything a visitor did while the new version was running:
evidence written during that window stays where it is, which is the point.

If the service does not come back after a rollback, treat it as the wedged
reactor case in `docs/11` §4 before anything else.

---

## 5. Updating the monitoring host

The dashboard is a separate installation with its own installer
(`docs/16` §3):

```bash
cd <checkout>
sudo git fetch origin && sudo git checkout <ref>
sudo ./deploy/install-dashboard.sh --apply
```

It re-copies the package, reinstalls the units and restarts the service. The
store, its accounts, the audit trail and every ingested bundle are untouched —
which also means that a change to the *store schema* would not be applied by
this. There is nothing in this package that migrates a store; a schema change
means a new store directory and re-ingesting the bundles, and it would be
called out in the release notes for the change.

---

## 6. Updating many hosts, and other shapes

* **`--stage N`** runs one stage of `install.sh`. Stage 5 is the package copy,
  stage 8 the units, stage 7 the profile. Filtered runs skip the version check
  and print a warning about it; that is expected, and it is why filtered runs
  are for diagnosis rather than for deployment.
* **First install on a new host** is `docs/03`, not this page. This page
  assumes `/opt/cowrie` already exists.
* **A host you no longer trust is not updated, it is rebuilt.** `docs/11` §2:
  export, verify, terminate, build fresh. An update in place is for pin
  changes, branch changes and configuration changes on a host that has behaved.
* **Branches are not environments.** `git checkout` on the sensor is a deploy:
  `DEPLOYMENT.txt` is rewritten with the new pin at install time, and the
  branch name is recorded only in `UPDATE-LOG.txt`. If you need to know what a
  host runs, read `DEPLOYMENT.txt` and `git -C /root/honeypot-src rev-parse HEAD`.

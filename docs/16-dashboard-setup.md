# 16 — Getting the dashboard working

A complete, copy-paste walkthrough for the off-host monitoring dashboard: two
hosts, one direction, and a working sign-in at the end.

`docs/15` explains what the dashboard *is* — its roles, its guarantees, and the
things it structurally cannot do. This page is the installation and first-run
procedure, in the order that actually works. It assumes nothing is installed on
either host yet.

If you only have one host and want to look at the interface, do that under
"One host, for a look" in §7. Do not deploy that way.

---

## 0. The shape of it

```
HONEYPOT HOST                            MONITORING HOST
/opt/cowrie                              /opt/honeypot-dashboard
  var/log/cowrie/cowrie.json               pkg/            ← the code
  var/lib/cowrie/tty/*                     run/
  var/lib/cowrie/downloads/*             /var/lib/honeypot-store
        │                                    store.sqlite3
        │ export_bundle.sh                   recordings/
        ▼                                    quarantine/     ← only if you
   S3: .../<sensor>/bundles/<stamp>/         manifests/         ship captures
        │                                    dashboard.sock  ← the UI
        │ aws s3 cp (read-only)                 ▲
        └──────────────────────────────►  /var/spool/honeypot-export ── ingest.py
```

Three separate programs, and the separation is the design:

| Program | Runs on | Job |
|---|---|---|
| `ops/export_bundle.sh` | honeypot | pack the state directory into a bundle and ship it |
| `dashboard/ingest.py` | monitoring host | read a bundle, write the store. The only writer |
| `dashboard/server.py` | monitoring host | the read-only web interface over that store |

The dashboard has no address, credential or socket for the honeypot and never
opens a captured file (`docs/15` §3). Data moves one way, as bundles.

---

## 1. What you need

**On the honeypot host** — already installed by `docs/03`:

* the package at `/opt/cowrie/share/pkg` (this contains `dashboard/bundle.py`,
  which `export_bundle.sh` calls);
* `EVIDENCE_BUCKET` set in `/etc/cowrie-logship.env`;
* the `aws` CLI, which `ops/quarantine_sync.sh` already depends on.

**On the monitoring host** — a separate instance:

* Ubuntu 22.04/24.04 LTS, Python 3.11 or newer with `hashlib.scrypt`
  (the installer checks both), `rsync`;
* nothing else. The dashboard is standard library only: there is no pip
  install, no virtualenv, no daemon to compile;
* read access to the evidence bucket, ideally through an instance profile.
  The honeypot's role should be write-only and this one read-only, and they
  should not be the same role.

**On your workstation**: the `aws` CLI with SSM permissions, or a VPN.

The examples below use the defaults everywhere. Every path is overridable; see
`./deploy/install-dashboard.sh --help`.

---

## 2. On the honeypot: start shipping bundles

`install.sh` installs the bundle shipper but deliberately does **not** enable
it — it is a second egress path, and choosing where evidence goes is the
operator's decision, not an installer's.

```bash
# on the honeypot
sudo systemctl enable --now cowrie-bundle-ship.timer
sudo systemctl start cowrie-bundle-ship.service     # don't wait 15 minutes
journalctl -u cowrie-bundle-ship -n 30 --no-pager   # what happened
```

A good run ends with:

```
bundle built: /opt/cowrie/var/spool/bundle/20261004T150900Z/bundle.tar.gz (12K, sha256 4c1e...)
shipped: s3://<bucket>/honeypot/<sensor>/bundles/20261004T150900Z/bundle.tar.gz
staging cleared (use --keep to keep the local copy)
```

If `EVIDENCE_BUCKET` is unset the script stops at its first line and says so;
it never ships anywhere by default.

**What is in the bundle:** the event log (`cowrie.json`), every recording
(`tty/`), the health log, a `SENSOR` file and a manifest with a SHA-256 per
file. **Captured uploads are excluded by default** (`--no-downloads`), because
the dashboard shows them by metadata and hash and never opens them — shipping
the bytes would put captured malware on the reviewer host for no functional
gain. Add `--with-downloads` only if you have decided the monitoring host is a
place you are willing to keep captures.

**Schedule:** every 15 minutes, from `cowrie-bundle-ship.timer`. Fifteen rather
than five because a bundle is a review artefact, not the evidence of record;
`quarantine_sync.sh` is still shipping the raw evidence every five minutes and
is still the thing the retention policy applies to.

**Cost:** a bundle is a re-readable copy of the event log. On a busy honeypot
that is the single biggest recurring S3 cost in this design. Watch it for a
week before you leave it unattended, and prune the `bundles/` prefix with a
lifecycle rule when you know the rate.

---

## 3. On the monitoring host: install

```bash
# as root, from a checkout of this repository
sudo ./deploy/install-dashboard.sh                    # prints the plan, changes nothing
sudo ./deploy/install-dashboard.sh --apply
```

It is dry-run by default, like the honeypot installer. `--apply` does five
things, and prints what it is doing as it goes:

1. verifies this is not the honeypot host, and that Python has `scrypt`;
2. creates the `hpmon` service account and `/opt/honeypot-dashboard`,
   `/var/lib/honeypot-store`, `/var/spool/honeypot-export`;
3. copies the repository to `/opt/honeypot-dashboard/pkg` (read-only to the
   service account);
4. installs and starts `honeypot-dashboard.service` and
   `honeypot-dashboard-ingest.timer`;
5. creates the store if it does not exist, and ingests anything already in the
   spool.

It refuses to run on a host with `/opt/cowrie/var/lib/cowrie` or an installed
`cowrie.service`, because the reviewer does not belong on the host it reviews.
`--allow-on-honeypot` overrides that, and prints a warning naming what it gives
up.

Re-running the installer is the update path: the package is re-copied, the
units reinstalled, and the store, its accounts and its evidence are left alone.

### The one thing you have to fetch yourself

The dashboard does not talk to S3 and has no AWS credentials. Something has to
put a bundle in the spool. The straightforward version:

```bash
# on the monitoring host, as the service account (it must be able to read and
# then delete what it fetched)
sudo -u hpmon aws s3 cp --recursive \
    s3://<bucket>/honeypot/<sensor>/bundles/ /tmp/incoming/
sudo -u hpmon bash -c '
    for t in /tmp/incoming/*/bundle.tar.gz; do
        d=/var/spool/honeypot-export/$(basename "$(dirname "$t")")
        mkdir -p "$d" && tar -xzf "$t" -C "$d" --strip-components=1
        sha256sum -c <(sed "s|bundle.tar.gz$|$t|" "$t.sha256") || exit 1
    done'
sudo systemctl start honeypot-dashboard-ingest.service
```

Two things matter in that snippet: the `.sha256` beside the archive is checked
before anything is ingested (a bundle that changed in transit is refused rather
than indexed under the wrong name), and the extraction goes into the spool
where the timer will pick it up.

`ingest.py` removes what it has ingested once it succeeds. If it fails, it
leaves the bundle in place — a broken ingest is retried, never swallowed.

If you would rather pull than push, the same commands work from a cron entry or
a small unit on the monitoring host; nothing in the dashboard cares how the
directory was filled.

### Ingest is idempotent

Every row is keyed on Cowrie's own event identity, so re-ingesting an
overlapping bundle adds nothing. That is deliberate: bundles are packed while
the honeypot is still writing, so the last bundle and the next one always
overlap. Ingest the same bundle twice and the second run reports
`events +0 (dup N)`.

---

## 4. Create the account you will sign in with

There is no self-service path and no email reset. An administrator creates
accounts out of band, and the action is audited.

```bash
sudo -u hpmon python3 /opt/honeypot-dashboard/pkg/dashboard/manage.py \
    --store /var/lib/honeypot-store adduser --username alice --role admin
```

It prompts twice (the password is never an argument — argv is visible in the
process table and in shell history), then prints the TOTP secret **once**:

```
created alice with role admin

  Authenticator secret (add this to your authenticator app):
    LT37VO6OZFYBREOSVUGC4T2P5NGGKKDE

  otpauth URI:
    otpauth://totp/Honeypot%20Dashboard:alice?secret=LT37...&issuer=Honeypot%20Dashboard

  Current code, to check the enrolment: 462182
```

Put the secret into an authenticator app now. If you lose it before scanning
it, `manage.py totp --username alice` issues a new one; if you lose it
afterwards, that same command is the recovery path, and it revokes every
existing session for the account.

**Password rules** (enforced, and the CLI says which one failed): at least 12
characters, at least three of lower/upper/digit/symbol, and not one of the
well-known defaults.

**No terminal?** An SSM run-command, a provisioning script or a container build
has no TTY, and `manage.py` says so rather than raising a traceback. Use
`--password-stdin`:

```bash
printf '%s\n' "$DASHBOARD_PASSWORD" | sudo -u hpmon python3 \
    /opt/honeypot-dashboard/pkg/dashboard/manage.py \
    --store /var/lib/honeypot-store adduser --username alice --role admin \
    --password-stdin
```

This is still not a `--password` flag, for the reason above: the value arrives
on a pipe, not in the process table.

### Roles

| Role | Can |
|---|---|
| `viewer` | read events, sessions, transfers, health; watch recordings with captured secrets masked |
| `analyst` | everything a viewer can, plus reveal captured secrets and export evidence — both audited |
| `admin` | everything an analyst can, plus manage dashboard accounts |

Create the smallest number of `admin` accounts you can live with, and give
day-to-day reviewers `analyst`.

### The other account commands

```bash
S=/var/lib/honeypot-store
M="python3 /opt/honeypot-dashboard/pkg/dashboard/manage.py --store $S"

$M list                                # who exists, their role, MFA, last login
$M passwd   --username alice           # set a password; revokes their sessions
$M totp     --username alice           # new authenticator secret; revokes sessions
$M role     --username bob --role analyst
$M disable  --username bob             # or: enable
$M unlock   --username alice           # clear a lockout, keep the password
$M audit    --limit 40                 # recent audit entries
```

`unlock` exists because five failed sign-ins lock an account for 15 minutes and
the lock is keyed on the account, not the source address — anyone who can reach
the login page can keep an administrator locked out. An unlock is audited as
`user.unlock`.

---

## 5. Reach the interface

The interface shows captured credentials and session recordings. It is
designed to be reached over a management path, and it will not bind a
non-loopback address without an explicit flag that must not be used in a
service.

### Option A — UNIX socket (default, strongest)

The service listens on `/run/honeypot-dashboard/dashboard.sock` with mode
0660, in a runtime directory only root and the service group can enter. Over
SSM:

```bash
# 1. on the monitoring host: bridge the socket to loopback TCP, for this
#    session only. It is a foreground process: ^C closes it again.
sudo socat TCP-LISTEN:8443,bind=127.0.0.1,reuseaddr,fork \
    UNIX-CONNECT:/run/honeypot-dashboard/dashboard.sock

# 2. on your workstation: forward that port to you
aws ssm start-session --target <monitoring-instance-id> \
    --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["8443"],"localPortNumber":["8443"]}'

# 3. browse to http://127.0.0.1:8443
```

Nothing is listening on TCP when you are not reviewing, which is the point.

### Option B — loopback TCP

For a review station inside a VPN, or when you do not want `socat` in the
pathway:

```bash
sudo ./deploy/install-dashboard.sh --apply --listen 127.0.0.1:8443
```

The installer patches the unit to allow `AF_INET` as well as `AF_UNIX`, and
warns while doing it. Reach it with the SSM port-forwarding session above
without step 1.

### Option C — SSH port forwarding

If you have SSH to the monitoring host on a management network:

```bash
ssh -N -L 8443:127.0.0.1:8443 <user>@<monitoring-host>
```

**TLS.** The program does not do TLS; confidentiality comes from the
management path. If you put a reverse proxy in front of it, read the
request-smuggling note in `AUDIT.md` (F-10) first, and keep the proxy on the
same host so the loopback assumption stays true.

---

## 6. First sign-in

1. Browse to `http://127.0.0.1:8443` and enter the username, password and the
   six-digit code from your authenticator app.
2. You land on **Overview**: sessions and failed logins for the last 24 hours,
   a 14-day timeline, top sources, top usernames, recent events.
3. **Events** and **Sessions** are where a review actually happens; both take
   filters, and a filter that cannot be parsed returns an error rather than
   quietly returning everything.
4. **Sessions** → a session → the recording player. `docs/15` §6 explains why
   one session can have several recordings; read it before concluding that
   something is missing.
5. **Audit** shows your own sign-in and every action since.

If the sign-in is refused, the page tells you why (invalid credentials, locked
account, MFA failure) and the attempt is recorded in the audit trail. Nothing
about a refusal is silent.

---

## 7. One host, for a look

For local evaluation only — read what it gives up before doing it:

```bash
sudo ./deploy/install-dashboard.sh --apply --allow-on-honeypot --listen 127.0.0.1:8443
```

Now the reviewer is on the host under review, which is exactly the separation
`docs/15` §1 describes as the design. Use it to read the screens, then move it
to its own instance before it holds anything you did not capture yourself.

You can also run it with no installation at all, straight from a checkout:

```bash
python3 dashboard/manage.py --store /tmp/hs init
python3 dashboard/manage.py --store /tmp/hs adduser --username me --role admin
python3 dashboard/ingest.py --store /tmp/hs --bundle /path/to/a/bundle
python3 dashboard/server.py --store /tmp/hs --listen 127.0.0.1:8443
```

---

## 8. What "empty" means

An empty dashboard is almost always one of these, in this order:

| Symptom | Cause | Check |
|---|---|---|
| `error: no store at /var/lib/.../store.sqlite3` | no bundle has ever been ingested | `manage.py init` for an empty store, or ingest a bundle |
| Overview shows zeros, Health shows no rows | the bundle never arrived, or `ingest.py` has not run | `ls /var/spool/honeypot-export/`, `journalctl -u honeypot-dashboard-ingest` |
| Events present, sessions show `none` for recording | the recording was not in the bundle, or Cowrie reported it as `duplicate` | `docs/15` §6; `jq '.skipped' BUNDLE.json` on the honeypot |
| Sign-in page loads, sign-in always fails | wrong TOTP code, or an account that was never created | `manage.py list`; `manage.py unlock --username <name>` |
| `Errno 13` from the socket | the bridge is not running as a user in the socket's group | `/run/honeypot-dashboard` is `0750`; run the bridge as root or as `hpmon` |

`ingest.py` exits `0` for success, `1` for ingested-with-warnings, `2` for
"could not ingest at all" — a timer does not tell you the difference, so check
`journalctl` after the first run rather than assuming.

---

## 9. Routine operation

| Task | Command |
|---|---|
| Ingest whatever is waiting | `sudo systemctl start honeypot-dashboard-ingest.service` (also every 5 minutes) |
| Fetch new bundles | the `aws s3 cp` block in §3 — from cron, or your own unit |
| Back up the store | `sqlite3 /var/lib/honeypot-store/store.sqlite3 ".backup /backup/store-$(date +%F).sqlite3"` — the database is the index; `recordings/` and `quarantine/` are the payload |
| Read the audit trail | `manage.py audit --limit 200`, or the Audit page |
| Change a password | `manage.py passwd --username <name>` (revokes that account's sessions) |
| Clear a lockout | `manage.py unlock --username <name>` |
| Update the dashboard | re-run `deploy/install-dashboard.sh --apply` |

The store is a single SQLite file with a single writer. There is no replication
and none is planned: the workload is one administrator reviewing evidence.
Copying `store.sqlite3` while the timer might be writing is safe only through
`.backup`, not `cp`.

---

## 10. Where the rest is written down

* `docs/15` — what the dashboard guarantees, and what it cannot do
* `docs/06` — handling a captured file once you have decided to analyse it
* `docs/14` — alert response and incident handling
* `docs/17` — updating an installed deployment, including rollback
* `AUDIT.md` — the adversarial record behind the security claims

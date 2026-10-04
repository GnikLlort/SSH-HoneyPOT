# 03 — Installing on a dedicated Ubuntu LTS EC2 instance

**Read this whole page before running anything.** Every command that changes a
server is marked `[CHANGES SERVER]` with a plain description of its effect.

The installer is dry-run by default. You will run it twice: once to read the
plan, once to apply it.

---

## 0. Before you start

### Confirm this is the right instance

Answer all four. If any answer is "no" or "unsure", stop.

1. Is this instance **new, disposable, and dedicated** to the honeypot — no
   other service, no other data, nothing you would miss if it were destroyed
   today?
2. Does it have **no network route** to any production system, and is it in its
   own VPC (or at minimum its own subnets and route table) rather than sharing
   one with something real?
3. Have you confirmed with whoever owns your AWS account that operating an
   SSH honeypot is allowed here, and that it is lawful in your jurisdiction?
4. Have you read `docs/02-threat-model.md`, in particular the section on what
   an attacker can still do to this system?

### What you need

* AWS console or CLI access, with permission to create VPC, EC2, IAM and S3
  resources.
* A separate AWS account for the evidence bucket. If you do not have one, read
  `deploy/aws/security-groups.md` section 1 first — you can substitute a
  separate KMS key and Object Lock, but it is weaker and you should make that
  choice knowingly.
* This repository, on the instance or copied to it.
* Roughly an hour.

### What this guide does not do

* It does not create a second AWS account for you. Do that in the console
  first; it is a five-minute, one-time task and it is the strongest control in
  the whole design.
* It does not open a firewall port. Network exposure is a separate, deliberate
  step (step 9) because it is the point of no return.

---

## 1. Create the instance

`[CHANGES AWS — creates resources]`

Use the values from `deploy/aws/security-groups.md` section 1. Summary:

| Setting | Value | Why |
|---|---|---|
| AMI | Ubuntu Server 24.04 LTS (x86_64) | Ships Python 3.12, which meets Cowrie 3.1.0's minimum of 3.11 with no third-party interpreter |
| Instance type | `t3.small` | The emulated profile advertises 2 vCPU / 4 GB. A smaller instance than the profile claims is a mismatch worth avoiding |
| VPC | New, dedicated, e.g. `10.90.0.0/16` | No peering, no transit gateway, no VPN attachment |
| Subnet | Public, `10.90.1.0/24` | The honeypot must be reachable from the internet |
| Auto-assign public IP | Enabled | |
| IAM instance profile | **None** | An attacker who reaches the host inherits no AWS credentials |
| Storage | 40 GB gp3, encrypted | Matches the emulated `df` profile; encryption is free |
| Termination protection | Disabled | You want to be able to destroy this quickly |
| Detailed monitoring | Off | Not useful for a honeypot |

Do **not** attach a key pair you use elsewhere. The honeypot has no inbound
management port; you administer it through Session Manager.

### Instance metadata

`[CHANGES AWS — changes instance settings]`

Require IMDSv2 and prevent metadata responses leaving the instance:

```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-xxxxxxxxxxxxxxxxx \
    --http-tokens required \
    --http-put-response-hop-limit 1 \
    --http-endpoint enabled
```

**Effect:** IMDSv1 requests are rejected, and anything running on the instance
cannot read metadata through a proxy or forwarding hop. SSH will still work.
Session Manager will still work.

---

## 2. Confirm you can administer it without an open port

`[NO CHANGE — verification only]`

```bash
aws ssm start-session --target i-xxxxxxxxxxxxxxxxx
```

**Effect:** opens an interactive shell over the SSM control plane. No inbound
port, no bastion, and every session is recorded in CloudTrail and S3.

If this does not work, fix it now. You are about to make the instance
unreachable by any other means, and you must not add an inbound management
rule as a workaround.

---

## 3. Prepare the host

`[CHANGES SERVER — installs packages, creates an account, installs the service]`

Inside the SSM session:

```bash
sudo -i
apt-get update -qq
apt-get install -y --no-install-recommends git
git clone https://github.com/GnikLlort/SSH-HoneyPOT.git /root/honeypot-src
cd /root/honeypot-src
```

**Effect of each line:** refreshes the package index; installs `git` and
nothing else; clones the deployment package to `/root/honeypot-src`. Nothing
else on the system is touched.

### 3a. Read the plan

```bash
bash deploy/install.sh
```

**Effect: none.** `install.sh` is dry-run unless given `--apply`. It prints
every command it *would* run, with a one-line reason for each. Read it. In
particular check that the target is `/opt/cowrie` and that the Cowrie pin
matches `deploy/versions.env`.

The script refuses to run against a host that looks like it has a life:
if something is already listening on the honeypot port, or the state directory
already contains what looks like production data, it stops and says so.

### 3b. Apply it

```bash
sudo ./deploy/install.sh --apply
```

**Effect, stage by stage.** Each stage is idempotent — re-running skips work
already done.

| Stage | What it changes on the server |
|---|---|
| 1 | Verifies Python ≥ 3.11 and that the host looks disposable. Changes nothing. |
| 2 | `apt-get install`s the build and runtime dependencies (Python venv/dev, build-essential, libffi, libssl, git, ca-certificates, rsync, jq). Installs no upgrades and runs no autoremove, to keep the host minimal. |
| 3 | Creates the system account `cowrie` with `/usr/sbin/nologin` and home `/opt/cowrie`, and the state directory tree under it. |
| 4 | Clones Cowrie at the pinned commit into `/opt/cowrie/build/cowrie`, creates `/opt/cowrie/venv`, installs Cowrie into it, and refreshes Twisted's plugin cache. |
| 5 | Creates the log, recordings, uploads and run directories under `/opt/cowrie/var`. |
| 6 | Generates the synthetic host profile from `realism/identity.yaml` into `/opt/cowrie/build/profile`. Fails loudly if any consistency invariant is violated. |
| 7 | Installs the generated filesystem, process table, command outputs and config fragment; the credential allow-list; the operator config; the realism overlay; and a read-only copy of this package at `/opt/cowrie/share/pkg`. Also installs the playback server and its unit (**not enabled**). |
| 8 | Installs and enables `cowrie.service`, `cowrie-healthcheck.timer`, `cowrie-logship.timer`. |
| 9 | Installs the operational helpers into `/usr/local/sbin` and the logrotate policy. |
| 10 | Writes `/opt/cowrie/DEPLOYMENT.txt` (audit and rollback record). |

At no point does the installer:

* open a firewall port,
* create or modify any AWS resource,
* install anything from an unpinned source,
* copy data from any other machine.

### 3c. Confirm it is listening

```bash
systemctl status cowrie --no-pager
ss -ltnp | grep ':22\b'
grep -c . /opt/cowrie/build/profile/BUILD-REPORT.txt
```

**Effect: none.** Confirms the service is running and bound to tcp/22 on all
interfaces, and that the profile build report exists.

---

## 4. Configure the evidence destination

`[CHANGES SERVER — adds a config file containing no credentials]`

Create the bucket first, in the **separate account**, with versioning, Object
Lock and default SSE-KMS encryption. The bucket policy in
`deploy/aws/security-groups.md` section 4 denies unencrypted uploads and denies
deletion to everything except your evidence administrator role.

Then, on the honeypot:

```bash
sudo install -m 0640 -o root -g cowrie \
    /opt/cowrie/share/pkg/deploy/cowrie-logship.env.example \
    /etc/cowrie-logship.env
sudoedit /etc/cowrie-logship.env
```

**Effect:** installs the documented template with permissions that let the
`cowrie` account read it and nobody else. It contains no secrets — it names the
destination and the alert webhook. Set at minimum:

```
EVIDENCE_BUCKET=<your evidence bucket>
ALERT_WEBHOOK=<your HTTPS webhook, or leave empty>
```

Leave `HONEYPOT_PORT=22`, `STATE_DIR=/opt/cowrie` and the retention defaults as
shipped unless you have a reason.

### Rehearse the ship before trusting it

`[NO CHANGE — writes only to a scratch bucket]`

Point the script at a scratch bucket and run it by hand once:

```bash
sudo -u cowrie env EVIDENCE_BUCKET=my-scratch-bucket \
    /usr/local/sbin/quarantine_sync.sh
aws s3 ls --recursive s3://my-scratch-bucket/honeypot/
```

**Effect:** copies the current log, recordings and captured files to the
scratch bucket and writes a manifest of SHA-256 hashes. It prunes local copies
only after a verified successful copy, so it cannot destroy evidence. Confirm
the manifest and a few objects are present, then point
`EVIDENCE_BUCKET` at the real bucket.

---

## 5. Verify the isolation boundary

`[NO CHANGE — verification only, all of these should fail]`

From the SSM session on the honeypot:

```bash
# Production must be unreachable.
nc -vz -w 3 10.0.0.10 443          # expect: timeout or refused
nc -vz -w 3 172.16.0.10 22         # expect: timeout or refused

# Metadata must not be usable.
curl -s -m 3 http://169.254.169.254/latest/meta-data/    # expect: no output
curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/

# There must be no AWS credentials on the host.
ls -la ~/.aws 2>/dev/null; env | grep -i aws             # expect: nothing

# The service account must not be able to read host files.
sudo -u cowrie cat /etc/shadow     # expect: Permission denied
sudo -u cowrie ls /root            # expect: Permission denied
```

**Effect: none.** If any of these *succeeds*, stop and fix the network boundary
before exposing the port. A honeypot that can reach production is a liability,
not an asset.

---

## 6. Run the conformance suite

`[CHANGES SERVER — nothing; it only connects to the local honeypot]`

```bash
cd /root/honeypot-src
sudo /opt/cowrie/venv/bin/python tests/test_conformance.py \
    --expect build/profile/expectations.json \
    --host 127.0.0.1 --port 22
```

**Effect:** connects to the honeypot over SSH from the host itself, runs
ordinary discovery commands, and checks that the answers agree with the
profile. It creates real sessions, so they will appear in the logs and in the
playback UI — that is expected, and they are useful as a known-good baseline.

Expected result: **197 of 198 checks pass, with zero failures above `info`
severity.** The one remaining `info` check is a documented paramiko interop
quirk; see `docs/09-test-results.md` and `docs/10`.

If you edited `realism/identity.yaml`, regenerate the profile first:

```bash
sudo /opt/cowrie/venv/bin/python realism/build_profile.py \
    --identity realism/identity.yaml --out build/profile
sudo /opt/cowrie/venv/bin/python realism/build_profile.py \
    --identity realism/identity.yaml --out /opt/cowrie/build/profile
sudo systemctl restart cowrie
```

---

## 7. Set up the security group

`[CHANGES AWS — this is the step that exposes the honeypot to the internet]`

Follow `deploy/aws/security-groups.md` section 2. In short:

* **Inbound:** exactly one rule — TCP 22 from `0.0.0.0/0` (and `::/0` if the
  subnet has IPv6).
* **Outbound:** deny by default, then permit tcp/443 to the evidence endpoint
  and to the OS update mirrors only. **No outbound tcp/22.**

Remove the PyPI egress rule once installation is complete.

Until you add the inbound rule, the honeypot is unreachable and harmless.

---

## 8. Watch it for the first hour

`[NO CHANGE — observation only]`

```bash
# Live event stream, structured.
sudo tail -f /opt/cowrie/var/log/cowrie/cowrie.json | jq -c '{t:.timestamp,e:.eventid,ip:.src_ip,u:.username}'

# Health check result and any alerts.
sudo cat /var/log/cowrie-healthcheck.log
sudo cat /var/log/cowrie-alerts.log

# Confirm evidence is leaving the host.
aws s3 ls --recursive s3://<evidence-bucket>/honeypot/ | tail
```

What to look for in the first hour:

* `cowrie.session.connect` events arriving within minutes. If nothing arrives
  after an hour, the security group or the listener is wrong — not "no
  attackers today".
* `cowrie.login.failed` dominating. Successful logins should be rare; a flood
  of `cowrie.login.success` means the credential policy is too permissive.
* Health check log lines every 5 minutes with no `ALERT`.
* Objects appearing in the evidence bucket within ~10 minutes.

---

## 9. Afterwards

* **Start the playback UI only when you need it.** It is read-only and bound to
  loopback, and you reach it over SSM — see `docs/07-session-playback.md`.
  Stop it when you are done reviewing.
* **Rotate the SSH host keys before deployment if you ever ran the honeypot
  somewhere reachable.** A reused host key is a strong fingerprint.
* **Never enable Cowrie's LLM mode** without completing
  `docs/13-llm-mode-review.md`.
* **Record what you built.** `/opt/cowrie/DEPLOYMENT.txt` is written by the
  installer; add the instance ID, the evidence bucket and the date.

---

## Updating an installed sensor

An update is the installer run again from the source checkout, which is
idempotent. `deploy/update.sh` wraps it with a dry run, a dirty-tree check and
a recorded rollback path:

```bash
cd /root/honeypot-src
sudo git fetch origin
sudo ./deploy/update.sh --ref <branch-or-commit>            # dry run
sudo ./deploy/update.sh --ref <branch-or-commit> --apply
```

`docs/17` is the full procedure: what an update overwrites, what it never
touches, how to verify it and how to roll back.

To feed the off-host monitoring dashboard from this host, enable the bundle
shipper (installed but not enabled) and follow `docs/16`:

```bash
sudo systemctl enable --now cowrie-bundle-ship.timer
```

---

## Uninstall / roll back

See `docs/11-rollback-and-rebuild.md`. Two commands, and the difference between
them matters:

```bash
sudo ./deploy/uninstall.sh --stop      # stop the service, keep all evidence
sudo ./deploy/uninstall.sh --remove    # delete the account and every capture
```

`--remove` prints what it will delete and requires
`--i-understand-this-destroys-evidence`. Export first.

---

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `twistd --umask=0022: Unknown command: cowrie` | Twisted's plugin cache is stale after install | `/opt/cowrie/venv/bin/python /opt/cowrie/build/cowrie/bin/regen-dropin.cache` |
| `cowrie start` fails; `twistd` not found | The venv `bin/` is not on `PATH` | `cowrie start` calls `os.execvp("twistd", …)`; run it as the unit does, with the venv on `PATH` |
| `DuplicateSectionError: section 'ssh' already exists` | `cowrie init` wrote the full 49 KB template and a section was appended to it | Ship the minimal override in `config/cowrie.cfg` instead; never start from `cowrie init` output |
| Commands answer `cannot execute binary file: Exec format error` | `txtcmds_path` is under the wrong section, or points at a missing directory | It belongs to `[honeypot]`. Check `<state>/share/txtcmds` exists and is populated |
| Port 22 already in use | Another SSH service is running | The installer refuses to continue. This host is not disposable — use a different one |
| Sessions hang and the service ignores `SIGTERM` | A pathological command wedged the Twisted reactor | Known limitation, documented in `docs/10`. `systemctl kill -s SIGKILL cowrie`, then restart |
| Nothing in the logs after an hour | Security group, listener binding, or DNS | `ss -ltnp \| grep :22`, then check the inbound rule from outside |

# 05 — Isolation and the network boundary

The honeypot's safety does not come from Cowrie. Cowrie is a Python program
that emulates a shell — it parses commands, it does not run them. The controls
on this page exist for the case where that assumption is wrong, and for the case
where an operator makes a configuration mistake.

**The concrete security group, route table, IAM policy and bucket policy are in
[`deploy/aws/security-groups.md`](../deploy/aws/security-groups.md).** This page
explains the reasoning behind them and the checks that prove they hold.

---

## 1. The three boundaries

### Boundary A — internet to the honeypot service

**Open:** tcp/22, from anywhere. This is the point of the deployment.

**Everything else is closed**, and each closure is deliberate:

* **No management port.** Administration is over AWS Systems Manager Session
  Manager, which needs no inbound rule at all. The obvious alternative — an
  inbound tcp/22 rule from the office CIDR "just for admin" — is impossible
  here, because the honeypot already owns tcp/22 on this host. Anything else
  connecting to it is either the honeypot working or a mistake.
* **No tcp/2222.** Cowrie's default port. A host answering SSH on both 22 and
  2222 is a honeypot mid-configuration. The service is moved to 22 and only 22
  is exposed.
* **No ICMP.** The instance does not answer pings. A hardened host that exposes
  only SSH and ignores ICMP is normal; responding to ICMP is one more way to
  confirm the instance exists.
* **No tcp/80 or tcp/443.** See §2 — this is a realism decision, not just a
  network one.

### Boundary B — honeypot to everything else

**Closed by default.** The allow-list is: tcp/443 to the evidence endpoint, to
the OS update mirrors, and (during installation only) to PyPI. Remove the PyPI
rule when installation is finished.

Three rules carry most of the weight:

1. **No outbound tcp/22.** Cowrie's `ssh`, `scp`, `wget`, `curl`, `nc`, `tftpget`
   and `ftpget` commands emulate their protocols in-process and must never reach
   a real host. An outbound tcp/22 rule would turn a successful lure into a real
   outbound attack capability, launched from your AWS account. **This is the
   single most important egress rule.**
2. **No route to private ranges.** The VPC's own `local` route covers only its
   CIDR. There is no peering, no transit gateway, no VPN, no Direct Connect. So
   `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16` outside the honeypot VPC
   are simply not routable.
3. **No IAM instance profile.** An attacker who achieves code execution on the
   honeypot inherits an instance with no AWS API access at all. If an instance
   profile is unavoidable, scope it to `s3:PutObject` on the evidence prefix
   with a `aws:kms` encryption condition, and grant no `GetObject`,
   `ListBucket` or `DeleteObject` — the honeypot must not be able to read or
   erase its own evidence history.

**Instance metadata** is IMDSv2-only with a response hop limit of 1, so the
metadata service cannot return credentials through a forwarding hop. Cowrie
never makes that request on a visitor's behalf — the emulated `curl` and `wget`
speak to a fake socket — but the block means a future bug cannot become a
credential leak.

### Boundary C — honeypot to the evidence store

One direction only: upload. The bucket lives in a **separate AWS account** with
Object Lock, versioning, SSE-KMS using a customer-managed key, and a bucket
policy that denies `s3:DeleteObject` except to the evidence administrator role.

The reasoning: an attacker who takes over the honeypot must not be able to erase
the record of how they got there. A same-account bucket with a careful IAM
policy is weaker, because whoever compromises the honeypot's principal may also
be able to reach the bucket policy.

---

## 2. The 80/443 question

The generated profile advertises a build server, and `/etc/passwd`, `df` output
and the service list are consistent with that story. A scanner that probes
tcp/443 and gets a refused connection sees a contradiction: an internet-reachable
server with only SSH open is unusual for anything but a purpose-built appliance.

There are two coherent answers, and **you must pick one deliberately**:

**Option A — remove the web services from the profile.** Take nginx and any web
service out of the planted service list and the installed-package list, so the
advertised services and the observed ones agree. This is the default, and it is
what `realism/identity.yaml` produces today: a minimal internal box with SSH
only.

**Option B — respond.** Open 80/443 to a static responder that returns a
generic page or a plain 404, and keep the web service in the profile. More
realistic for a "public-facing" story, but it adds two more listeners to audit
and a new emulated service to keep consistent.

**What is not acceptable is the mismatch** — advertising nginx and refusing
443. `docs/10` lists this as a known detection signal for exactly that reason.

---

## 3. Host-level isolation

The service runs as `cowrie`, an unprivileged system account with
`/usr/sbin/nologin` and no sudo. systemd confines it:

| Directive | Effect |
|---|---|
| `ProtectSystem=strict` | Entire filesystem read-only except `ReadWritePaths` |
| `ReadWritePaths=/opt/cowrie/var` | The only writable tree |
| `ReadOnlyPaths=/opt/cowrie/etc /opt/cowrie/share` | Config and package readable, never writable |
| `ProtectHome=yes` | Cannot see `/home`, `/root` or `/run/user` |
| `PrivateTmp=yes`, `PrivateDevices=yes` | Private `/tmp` and no access to host devices |
| `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` | The only capability it holds, needed to bind port 22 |
| `NoNewPrivileges=yes` | Cannot gain privileges via setuid |
| `RestrictNamespaces`, `LockPersonality`, `RestrictSUIDSGID`, `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock` | Reduce kernel-level attack surface |
| `MemoryMax`, `CPUQuota`, `TasksMax` | Bound resource consumption |
| `BindReadOnlyPaths=…/meminfo:/proc/meminfo` | Masks the real host's memory layout (see `docs/04`) |

**Verify the filesystem confinement actually holds:**

```bash
sudo -u cowrie cat /etc/shadow     # expect: Permission denied
sudo -u cowrie ls /root            # expect: Permission denied
sudo -u cowrie touch /etc/x       # expect: Permission denied
```

---

## 4. Verifying the boundary

Run these after every change to the network configuration. **All of them should
fail.**

```bash
# From an SSM session on the honeypot.

# 1. Production is unreachable.
nc -vz -w 3 10.0.0.10 443          # expect: timeout / refused
nc -vz -w 3 172.16.0.10 22         # expect: timeout / refused
nc -vz -w 3 192.168.1.1 22         # expect: timeout / refused

# 2. Metadata is not usable.
curl -s -m 3 http://169.254.169.254/latest/meta-data/                 # expect: nothing
curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/
TOKEN=$(curl -s -m 3 -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
curl -s -m 3 -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/                         # expect: nothing

# 3. There are no credentials on the host.
ls -la ~/.aws 2>/dev/null; env | grep -i aws                         # expect: nothing
curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 4. The service account cannot read host files.
sudo -u cowrie cat /etc/shadow                                       # expect: denied
sudo -u cowrie ls /root                                              # expect: denied

# 5. Outbound is denied except for the allow-list.
curl -s -m 5 -o /dev/null -w '%{http_code}\n' https://example.com/   # expect: 000
```

From **outside** AWS, confirm only one port is reachable:

```bash
nmap -Pn -p- --min-rate 2000 <public-ip>    # expect: 22/tcp open, all else closed|filtered
```

**Record the output in the deployment record.** A boundary that has not been
tested is an assumption, and this deployment's entire safety argument rests on
this one.

---

## 5. What isolation does not cover

| Not covered | Why, and what to do |
|---|---|
| A Cowrie vulnerability giving code execution as `cowrie` | Accepted. The instance is disposable, has no credentials and no route to anything real. That is the mitigation. |
| The evidence bucket's own account being compromised | A different threat model. Follow your normal AWS account hygiene there. |
| Someone installing this on the wrong instance | `install.sh` refuses when the target port is already in use or the host looks lived-in, and `ops/canary_scan.sh` detects honeypot content on a real filesystem. But no script can tell you whether an instance matters. |
| VPC CIDR overlap with production | If you reuse an existing VPC, verify its CIDR does not overlap a network you care about. `deploy/aws/security-groups.md` section 3 covers this. |
| Volumetric DDoS | An AWS-level concern; the honeypot has no part in it. |
| Legal and policy questions | Out of scope, and yours. Confirm honeypot operation is lawful where you are and permitted by your provider's terms and your organisation's policy. |

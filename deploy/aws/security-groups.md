# AWS isolation: security groups, routing and IAM

The honeypot's safety does not come from Cowrie. It comes from the network and
IAM boundary around it. Cowrie is an emulator: it parses attacker input in
Python and never executes it. The controls below exist for the case where that
assumption is wrong.

Everything here is guidance to apply deliberately. `deploy/install.sh` changes
nothing in AWS — network exposure is a decision, not an installer side effect.

---

## 1. Isolation model

```
                    Internet
                        │
                        │  tcp/22  (the honeypot service, and nothing else)
                        ▼
        ┌───────────────────────────────────────────────┐
        │  VPC: honeypot-vpc          10.90.0.0/16      │
        │  NO peering, NO transit gateway, NO VPN       │
        │  NO route to any production CIDR              │
        │                                               │
        │  ┌─────────────────────────────────────────┐  │
        │  │  subnet: honeypot-public  10.90.1.0/24  │  │
        │  │  route table: 0.0.0.0/0 -> IGW          │  │
        │  │                                         │  │
        │  │  ┌───────────────────────────────────┐  │  │
        │  │  │  EC2: cowrie-hp-01                │  │  │
        │  │  │  t3.small, Ubuntu 24.04 LTS       │  │  │
        │  │  │  IMDSv2 required, hop limit 1     │  │  │
        │  │  │  no IAM instance profile  (1)     │  │  │
        │  │  └───────────────────────────────────┘  │  │
        │  └─────────────────────────────────────────┘  │
        │                                               │
        │  ┌─────────────────────────────────────────┐  │
        │  │  subnet: honeypot-admin  10.90.2.0/24   │  │
        │  │  no route to the internet               │  │
        │  │                                         │  │
        │  │  ┌───────────────────────────────────┐  │  │
        │  │  │  VPC endpoints:                   │  │  │
        │  │  │    - ssm, ssmmessages, ec2messages│  │  │
        │  │  │    - s3 (gateway)                 │  │  │
        │  │  └───────────────────────────────────┘  │  │
        │  └─────────────────────────────────────────┘  │
        └───────────────────────────────────────────────┘
                        │
                        │  evidence only, one direction
                        ▼
        ┌───────────────────────────────────────────────┐
        │  Separate AWS account (2): evidence store     │
        │  S3: SSE-KMS, versioned, Object Lock,         │
        │      no delete permission for the honeypot    │
        │  KMS key: separate account, separate admins   │
        └───────────────────────────────────────────────┘
```

**(1) No instance profile.** The honeypot host holds no AWS credentials. If
Cowrie is fully compromised the attacker inherits a machine with no API access.
Evidence shipping uses a dedicated role assumed over SSM, or is done by a pull
from the evidence account. The weaker alternative — an instance profile with an
`s3:PutObject`-only policy — is documented at the end, with its trade-offs.

**(2) Separate account.** The strongest single control available. An attacker
who reaches the honeypot cannot reach the evidence. If a second account is not
available, use a separate KMS key with a key policy that the honeypot's
principal cannot modify, and enable Object Lock in compliance mode.

---

## 2. Security groups

### `sg-honeypot-ssh` — attached to the EC2 instance

**Inbound** — exactly one rule:

| Type | Protocol | Port | Source | Purpose |
|---|---|---|---|---|
| Custom TCP | TCP | 22 | `0.0.0.0/0` | The honeypot service. This is the only intended exposure. |

Plus, if IPv6 is enabled on the subnet:

| Type | Protocol | Port | Source | Purpose |
|---|---|---|---|---|
| Custom TCP | TCP | 22 | `::/0` | Same, over IPv6. |

Deliberately **absent**:

* No ICMP rule. The instance does not answer pings; a host that replies to ICMP
  but exposes only SSH is a normal hardened server, and the silence removes one
  way to confirm the instance is a honeypot.
* No tcp/2222. Cowrie's default port is 2222. Exposing both 22 and 2222 doubles
  the fingerprinting surface and makes the instance look like a honeypot to a
  port scan. Move the service to 22 (as `config/cowrie.cfg` does) and expose
  only that.
* No UDP rules of any kind.
* No tcp/443 or tcp/80. If the profile advertises nginx (it does, in
  `/etc/passwd`, `df`, `ps` and the service list), a scanner that probes 443
  and gets a refused connection sees a contradiction. Either open 80/443 to a
  static "nothing here" responder, or remove nginx from the profile so the
  advertised services and the observed ones agree. **Choose one and be
  consistent** — this is a realism decision, not just a network one. See
  `docs/10-assumptions-limitations-detection.md`.

**Outbound** — deny by default, then allow only what is listed:

| Type | Protocol | Port | Destination | Purpose |
|---|---|---|---|---|
| HTTPS | TCP | 443 | `<evidence-endpoint>` | Log and evidence shipping |
| HTTPS | TCP | 443 | `archive.ubuntu.com`, `security.ubuntu.com` | OS updates only |
| HTTPS | TCP | 443 | `pypi.org`, `files.pythonhosted.org` | Only during initial install; remove afterwards |
| Custom TCP | TCP | 443 | VPC endpoint ENIs | SSM Session Manager; omit if using an S3 gateway endpoint |

Do **not** add a rule for `0.0.0.0/0` on any port. In particular, do not add an
outbound allow for tcp/22: Cowrie's SSH client commands (`ssh`, `scp`,
`wget`, `curl`, `nc`, `tftp`, `ftpget`) emulate their protocol inside the
honeypot and must never be able to reach a real host. An outbound tcp/22 rule
would turn a successful lure into an outbound attack capability.

### `sg-honeypot-admin` — for Session Manager

If Session Manager endpoints are reached over the VPC rather than an interface
endpoint, this group allows tcp/443 from the endpoints' prefix list only:

| Type | Protocol | Port | Source |
|---|---|---|---|
| HTTPS | TCP | 443 | `pl-<region>-ssm` (managed prefix list) |

Attach it **only** while an administrative session is open if you prefer a
tighter posture; the trade-off is that you must attach it before you need it.

---

## 3. Route tables

| Subnet | Route | Target | Note |
|---|---|---|---|
| `honeypot-admin` | `10.90.0.0/16` | local | |
| `honeypot-public` | `10.90.0.0/16` | local | |
| `honeypot-public` | `0.0.0.0/0` | Internet Gateway | inbound honeypot traffic and the pinned outbound allows |

Explicitly **absent** from both tables:

* No route to `10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16`. A `local`
  route only covers this VPC's CIDR (`10.90.0.0/16`), so private ranges
  elsewhere are already unreachable — confirm this holds if you reuse an
  existing VPC with a broader CIDR.
* No VPC peering, Transit Gateway attachment, VPN or Direct Connect.
* No second VPC in the same account with a route in.

### Blocking instance metadata

The instance metadata service is a real risk: `http://169.254.169.254/` can
return instance identity, the instance profile's credentials, and user data.

Cowrie never makes this request on a visitor's behalf — the emulated `curl` and
`wget` speak to a fake socket — but block it anyway so a future bug cannot
become a credential leak:

```
aws ec2 modify-instance-metadata-options \
    --instance-id i-xxxxxxxxxxxxxxxxx \
    --http-tokens required \
    --http-put-response-hop-limit 1 \
    --http-endpoint enabled
```

* `--http-tokens required` forces IMDSv2 and rejects IMDSv1 requests.
* `--http-put-response-hop-limit 1` stops the metadata response leaving the
  instance.
* Alternatively `--http-endpoint disabled` removes the service entirely. Only
  do this after confirming Session Manager still works: SSM's agent does not
  require IMDS if the instance is registered as a managed instance by other
  means, but this varies. `--http-tokens required` is the safer default.

---

## 4. IAM

### The honeypot instance

* **Preferred:** no instance profile at all. Administer via Session Manager
  using a role assumed by a human, and pull evidence from the evidence account.
* **If an instance profile is unavoidable**, scope it to the minimum that can
  still ship evidence, and accept that a compromised honeypot can now write
  arbitrary objects into the evidence bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ShipEvidenceOnly",
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::REPLACE-evidence-bucket/honeypot/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}
      }
    },
    {
      "Sid": "SessionManagerOnly",
      "Effect": "Allow",
      "Action": [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      "Resource": "*"
    }
  ]
}
```

Note what is **not** granted: `s3:GetObject`, `s3:ListBucket`, `s3:DeleteObject`
(so the honeypot cannot erase evidence it already shipped), and any `ec2:*`
action.

### The evidence bucket

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::REPLACE-evidence-bucket/*",
      "Condition": {
        "StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}
      }
    },
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::REPLACE-evidence-bucket",
        "arn:aws:s3:::REPLACE-evidence-bucket/*"
      ],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    },
    {
      "Sid": "DenyDeletionEvenByHoneypot",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
      "Resource": "arn:aws:s3:::REPLACE-evidence-bucket/*",
      "Condition": {
        "StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::REPLACE-EVIDENCE-ACCOUNT:role/evidence-administrator"}
      }
    }
  ]
}
```

Plus, on the bucket itself: versioning enabled, Object Lock enabled (compliance
mode for the retention period if your obligations require it), and default
encryption set to `aws:kms` with a customer-managed key.

---

## 5. Administration

### Prefer Session Manager

```
aws ssm start-session --target i-xxxxxxxxxxxxxxxxx
```

Session Manager gives you a shell without an inbound management port, without a
bastion, and with an auditable record of every keystroke and every command in
CloudTrail and S3.

### Do not expose the management interface

* No inbound tcp/22 from an office CIDR "just for admin". The honeypot owns
  port 22 on this host; anything else connecting to it is either the honeypot
  doing its job or a mistake.
* The session playback interface (`playback/server.py`) binds to `127.0.0.1`
  and is reached over an SSM port-forward. Never bind it to `0.0.0.0`.

```
# Playback UI, reached from your workstation over SSM only:
aws ssm start-session \
    --target i-xxxxxxxxxxxxxxxxx \
    --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["8081"],"localPortNumber":["8081"]}'
# then browse to http://127.0.0.1:8081
```

---

## 6. Verification

Run these after every change to the boundary. Each one should fail.

```bash
# 1. Production is unreachable from the honeypot.
#    (Run from an SSM session on the honeypot host.)
nc -vz -w 3 10.0.0.10 443      # expect: timeout / refused
nc -vz -w 3 172.16.0.10 22     # expect: timeout / refused

# 2. Metadata is not usable.
curl -s -m 3 http://169.254.169.254/latest/meta-data/    # expect: no output
TOKEN=$(curl -s -m 3 -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60")   # expect: empty
curl -s -m 3 -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/  # expect: empty

# 3. There are no credentials on the host.
curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ ; \
ls -la ~/.aws 2>/dev/null ; env | grep -i aws    # expect: nothing

# 4. The service account cannot read host files.
sudo -u cowrie cat /etc/shadow                   # expect: Permission denied
sudo -u cowrie ls /root                          # expect: Permission denied

# 5. Only one port is open to the internet.
#    (From outside AWS.)
nmap -Pn -p- --min-rate 2000 <public-ip>         # expect: 22/tcp open, all else closed|filtered
```

Record the output of these in the deployment record. A boundary that has not
been tested is an assumption.

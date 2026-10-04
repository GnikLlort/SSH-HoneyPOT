# 12 — QEMU high-interaction mode (design)

**Status: design only. Not implemented, not tested, not part of the deployed
package.** This page records what the optional high-interaction mode would need
so that the decision can be made deliberately rather than by accident.

Emulated-shell mode remains the **safe fallback**: if the guest pool is
unavailable, the honeypot degrades to a recorder, not to nothing.

---

## 1. Why you would want it

Emulated mode has a hard ceiling. `docs/10` §2.2 and §2.3 explain the two
problems it cannot solve: `/proc` is not backed by a real filesystem, and there
is no real scheduler, so timing gives the emulation away.

A guest VM has neither problem. It runs a real kernel, has a real `/proc`, real
processes and real timings — because it *is* a real system. An attacker gets a
genuinely convincing Linux host, which means:

* the telemetry is richer — real `strace`, real package behaviour, real
  persistence attempts that actually work;
* the malware they upload runs, so you learn what it does.

**And that is exactly the danger.** In emulated mode nothing a visitor sends is
executed. In high-interaction mode, it is. Every requirement below exists
because of that inversion.

---

## 2. The control that makes it safe

**One clean guest per session, reverted after the session ends.**

Not one guest serving many sessions. Not a guest cleaned up after a session. A
guest booted from a **read-only golden image**, dedicated to a single session,
and **destroyed** when that session ends — not reverted, not snapshotted back,
destroyed, and a fresh one created for the next visitor.

Reverting is the weaker option: it assumes the revert is complete. Anything the
guest wrote outside the reverted volume, anything in memory shared with the
host, anything it managed to persist, survives. A guest that is destroyed and
recreated from an immutable base cannot carry state forward because nothing is
carried forward.

---

## 3. Required controls

### 3.1 Isolation from the host and everything real

| Control | Detail |
|---|---|
| No shared folders | No virtiofs, no 9p, no shared directories, ever |
| No host devices | No USB or PCI passthrough, no GPU, no `/dev/kvm` inside the guest |
| No clipboard or spice agent | No spice-vdagent, no clipboard channel |
| No host credentials | No SSH keys, no cloud-init credentials, no metadata service |
| No production routes | Guest network is a dedicated bridge with **no route** to the host's networks or to production |
| Guest metadata service | Do **not** expose `169.254.169.254`. If the emulated host is an EC2 instance, serve a fake metadata endpoint rather than proxying the real one |
| QEMU hardening | `-nodefaults`, seccomp sandbox, a dedicated unprivileged user per guest, no monitor socket on a shared path |

**The metadata service is the one people get wrong.** An attacker inside the
guest who reaches the *host's* metadata endpoint obtains the host instance's IAM
credentials — which is a route straight out of the isolation boundary.

### 3.2 Resource limits

Per guest, enforced by QEMU and by cgroup:

| Resource | Suggested | Why |
|---|---|---|
| vCPU | 2, pinned | Matches the advertised hardware; prevents the guest from starving the host |
| Memory | 4 GiB, no ballooning to the host | Matches the advertised `MemTotal` |
| Disk | 40 GiB copy-on-write overlay, thin | Matches the advertised `df` |
| Wall-clock lifetime | Hard cap, then destroy | An unattended guest is an unattended foothold |
| Network bandwidth | Rate-limited | Prevents the guest being used for outbound abuse |
| Process count | Bounded | Prevents fork bombs from affecting the host |

**Every one of these must be enforced from outside the guest.** A limit the
guest can raise is not a limit.

### 3.3 Egress: deny by default

The guest must not be able to reach anything except a documented sink.

* Default deny on the guest bridge.
* Allow only the sink address — a controlled analysis network where traffic is
  captured, or a fake service that satisfies the malware and records what it
  tries.
* **No outbound tcp/22, ever.** An attacker's first instinct after landing is to
  use the box to reach somewhere else, and a high-interaction guest is a
  functional Linux host, so this is a real capability, not an emulated one.
* Log everything that is denied. The denied destinations are themselves
  intelligence — they are what the malware wanted to contact, and they are how
  you would find out that your isolation has a hole.

### 3.4 Capture and teardown

* The guest's console, disk and network traffic are recorded for the session.
* On teardown, the guest's disk overlay is exported to the quarantine path and
  hashed, then the guest is destroyed.
* The exported image is treated exactly like an uploaded file: **never mounted
  on the honeypot or a workstation.** See `docs/06`.
* Teardown must be verified — confirm the process is gone and the overlay is
  released before the next session starts. A leaked guest is a guest that can be
  reused.

### 3.5 Routing sessions to guests

Something has to decide which incoming connection gets a guest and which gets
the emulated shell. Options, weakest first:

1. **Forward everything.** Simplest, and the most dangerous: every scanner
   gets a real VM, and resource exhaustion is trivial.
2. **Forward after a trigger.** Emulated by default; allocate a guest when a
   visitor authenticates successfully, or runs a command above a threshold, or
   uploads a file. The emulated session replays into the guest. More complex,
   far better resource behaviour.
3. **Forward only for allow-listed sources.** A controlled analysis network, or
   specific source addresses, for deliberate research. The safest, and the
   natural starting point.

**Start with option 3.** Pool mode is a research capability, not a default.

---

## 4. Why this is not implemented

Stated plainly, so the decision is visible:

1. **It inverts the central safety property.** Emulated mode's guarantee is
   "attacker code never runs". Guest mode's guarantee is "attacker code runs,
   but only inside a disposable boundary". The second is a much harder claim to
   keep true, and it needs continuous verification, not a one-time review.
2. **The isolation is only as good as the hypervisor.** QEMU escape
   vulnerabilities are not hypothetical. Keeping this safe means tracking QEMU,
   the kernel and the guest image, and patching quickly — a standing operational
   commitment.
3. **The evidence-handling burden grows sharply.** Guest disk images are
   attacker-controlled artefacts, potentially large and potentially malicious,
   and `docs/06`'s controls must extend to them.
4. **It is not needed for the stated goal.** The package exists to collect
   telemetry that withstands careful fingerprinting. Emulated mode does that for
   the overwhelming majority of traffic, safely. Guest mode buys realism against
   the small number of operators who would find the emulation anyway.

**If you build it, build it on a separate instance in a separate VPC.** Do not
add guest hosting to the honeypot host. The whole point is that compromising one
must not reach the other, and a QEMU escape on a host that also runs the
recorder takes the evidence with it.

---

## 5. Reading list, if you build this

* `docs/02-threat-model.md` — the threat model guest mode changes
* `docs/06-evidence-handling.md` — extends to guest images unchanged
* `docs/10-assumptions-limitations-detection.md` §2.2, §2.3 — the two problems
  guest mode exists to solve
* Cowrie's own `ssh_proxy` mode, which is the upstream starting point for
  forwarding a session to a real backend

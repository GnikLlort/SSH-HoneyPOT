# 13 — LLM mode: privacy and containment review

**Status: disabled and closed by default.** `[llm] backend = shell` in
`config/cowrie.cfg`. This page is the review that must be completed *before*
enabling it, and the record of why it is off.

---

## 1. What enabling it would do

Cowrie 3.1.0 can answer an unrecognised command by asking a language model
instead of returning an error. With `backend = llm`:

```
visitor types a command
    → Cowrie transmits it, in context, to a third-party model provider
    → the provider returns generated text
    → Cowrie returns that text to the visitor as shell output
```

That is the whole mechanism, and every consequence below follows from it.

---

## 2. Why it is off

### 2.1 Captured attacker input leaves the boundary

Every command a visitor types is transmitted to a commercial service. That
includes commands, paths, usernames, file names, and — routinely — credentials,
because attackers type passwords into command lines
(`mysql -u root -pSecret`, `curl -u user:pass`, exports of environment
variables).

The deployment requirements are explicit that captured usernames, passwords,
commands and uploads are sensitive evidence: restrict access, encrypt storage,
define retention, and **never send them to a public LLM or third party by
default**. Enabling this would do exactly that, continuously, by design.

### 2.2 It reveals that you run a honeypot

The traffic tells the provider that a honeypot exists at your address, and
roughly how much attention it attracts. That is information about your
defensive posture, disclosed to a third party you cannot audit.

### 2.3 LLM output cannot be kept consistent

The entire realism design rests on one manifest from which every observable is
derived, so that two answers to the same question cannot disagree
(`docs/04` §1). A language model's output is non-deterministic and is not
derived from `realism/identity.yaml`. It will produce paths that do not exist,
versions that contradict the banner, and timestamps that disagree with
`/proc/uptime`.

**Inconsistency is precisely what a careful operator looks for.** Enabling LLM
mode would trade the property the honeypot is built to have for a marginal gain
in plausibility on commands nobody runs.

### 2.4 It adds a network path

The honeypot's egress is deny-by-default with a narrow allow-list
(`docs/05` §1). LLM mode requires opening tcp/443 to a model provider — a new
outbound path from a host that an attacker is actively trying to influence, with
the provider's response being fed back to that attacker as shell output.

---

## 3. Preconditions for enabling it

All of these, not a selection. If any cannot be met, do not enable it.

| # | Precondition | Why |
|---|---|---|
| 1 | **A written decision that captured data may leave your boundary**, from whoever owns that data. It is not a technical choice. | §2.1 |
| 2 | **A self-hosted model, or a provider under a contract with no training on submitted data and a defined retention window.** A public consumer API does not qualify. | §2.1 |
| 3 | **A dedicated outbound rule** to the model endpoint only — not a general tcp/443 allow — and an alert on unexpected outbound traffic. | §2.4 |
| 4 | **Redaction before transmission.** Run the same masking the playback UI uses (`playback/server.py`, `mask_sensitive`) over every prompt, so typed credentials do not reach the provider. Test it with a session that types a password. | §2.1 |
| 5 | **A cost and rate limit.** A visitor can generate unbounded tokens. Cap it per session and per hour, and alert on the cap. | Resource exhaustion |
| 6 | **A kill switch** that reverts to `backend = shell` without editing config on a live host — e.g. an `EnvironmentFile` value plus a restart. | Operability |
| 7 | **A note in the deployment record** saying LLM mode is on, why, and who decided. | Audit |

---

## 4. Containment requirements if it is enabled

The model must be treated as **untrusted output from a system an attacker is
actively trying to steer**. Prompt injection is the expected case here, not an
edge case: the visitor controls the input, and their goal is to make the model
say something useful to them.

**The integration must have:**

* **No tools.** No function calling, no code execution, no plugin access.
* **No shell access.** The output is text returned to the visitor. It is never
  evaluated, never passed to a shell, never used to construct a command.
* **No network access** beyond the single model endpoint.
* **No file access.** No reading, no writing, no path resolution. Nothing the
  model emits may be used as a filename.
* **No secrets.** The prompt must contain no API keys, no host details, no
  real network information, no credentials of any kind.
* **No host-changing ability.** No system state, no config, no service control.
* **Output treated as untrusted text** — length-capped, stripped of terminal
  control sequences, and passed through the same escaping the playback UI uses
  before it reaches any terminal. **An attacker who can make the model emit
  escape sequences is attacking the visitor's own terminal through your
  honeypot.**

The last point deserves emphasis. The model output goes *to the attacker*, so
the attacker gaining control of it is mostly self-harm — but the same code path
often ends up in the logs and in the reviewer's interface. Escape-strip it on
the way in, and treat it as untrusted everywhere downstream.

---

## 5. The recommended path instead

If the goal is a more plausible answer for an unrecognised command, there are
cheaper and safer options, in order:

1. **Add the command to the profile.** `realism/build_profile.py` generates
   `txtcmds` from the manifest. If attackers keep running something the
   honeypot answers badly — `du` is the standing example, `docs/10` §2.5 —
   implement it once, consistently, with no network dependency and no
   non-determinism.
2. **Add the command to the overlay**, following the fallback rule in
   `docs/04` §4: every patched entry point wrapped so it degrades to stock
   output rather than raising.
3. **Return a plausible error.** A real Debian host does not have every
   command either. `bash: foo: command not found` is a correct answer, and it
   costs nothing.

Steps 1–3 keep the honeypot deterministic, keep captured data inside the
boundary, and keep the egress allow-list as small as it is. **None of them send
a visitor's password to a third party.**

---

## 6. If you enable it anyway

Do this, in this order:

1. Complete the precondition table in §3. Put it in the deployment record with
   names and dates.
2. Apply the containment list in §4 and write a test for each item — especially
   redaction and output escaping. `tests/test_playback.py` shows the shape of
   those tests.
3. Enable it on a **lab instance first**, with no internet exposure, and drive a
   session that deliberately types a password and tries to inject an instruction
   into the model. Confirm the password did not leave and the injection changed
   nothing but the text on screen.
4. Only then point real traffic at it, with the kill switch tested and the
   alerting in place.

**Then revisit the decision periodically.** The data that would leave is
somebody's credential, the provider's terms will change, and the realism gain is
real but small. This is a choice worth re-making, not a setting worth setting
once.

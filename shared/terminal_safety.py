"""
Shared, security-critical primitives used by every component that displays
attacker-controlled data.

WHY THIS MODULE EXISTS
    Two programs render recorded attacker input: the on-host single-session
    viewer (`playback/server.py`) and the off-host monitoring dashboard
    (`dashboard/`). Both must strip terminal escape sequences and mask captured
    secrets, and both must do it *identically*.

    Duplicating these functions would mean a fix in one and not the other.
    Worse, it would mean a redaction bug in one is invisible from the other.
    So the sanitizers live here once, and a test asserts that both consumers
    produce the same output for a corpus of hostile input
    (`tests/test_dashboard.py::TestSanitizerParity`).

THREAT MODEL
    A recording, an event field, or a filename is UNTRUSTED INPUT. It is
    produced by whoever connected to the honeypot, and they may be attacking the
    administrator who later reviews it. The functions here exist to make that
    impossible: nothing attacker-controlled reaches a browser, a terminal, or a
    log line without passing through them first.
"""

from __future__ import annotations

import html
import re

__all__ = [
    "ANSI_RE",
    "CONTROL_RE",
    "BIDI_RE",
    "SENSITIVE_PATTERNS",
    "REDACTED",
    "strip_escapes",
    "strip_terminal_control",
    "mask_sensitive",
    "safe_text",
    "safe_html",
    "safe_field",
    "safe_log_value",
]

# ---------------------------------------------------------------------------
# Escape sequences
# ---------------------------------------------------------------------------
ANSI_RE = re.compile(
    r"""
    \x1b\[[0-?]*[ -/]*[@-~]              # CSI: colour, cursor movement, erase
  | \x1b\][^\x07\x1b]*(?:\x07|\x1b\\)    # OSC: window title, clipboard (OSC 52)
  | \x1b[PX^_][^\x1b]*(?:\x1b\\)?        # DCS / SOS / PM / APC strings
  | \x1b[@-Z\\-_]                         # two-byte escapes
  | \x9b[0-?]*[ -/]*[@-~]                # 8-bit CSI
  | \x1b.                                  # anything else beginning with ESC
    """,
    re.VERBOSE,
)

# Control characters that can drive a terminal or a browser. Newline and tab are
# deliberately excluded here; carriage return is handled at render time.
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Bidirectional overrides reorder displayed text, which can make "rm -rf /"
# render as something harmless-looking.
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069\ufeff]")

# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
# Each pattern captures the label in group 1 and the secret in group 2, so the
# label survives and only the value is replaced. Patterns without a group are
# replaced wholesale.
SENSITIVE_PATTERNS: list[re.Pattern[str]] = [
    # Cowrie writes the credential into a plain sentence as well as into
    # structured fields:
    #     login attempt [deploy/Sunrise-Ledger-1972] succeeded
    # The structured `password` field is masked separately, so without this
    # pattern the *same secret* walks straight past redaction in the `message`
    # column. Verified live: a viewer holding no unmask permission could read
    # captured passwords in cleartext from the events table.
    #
    # The trailing bracket is a lookahead rather than a captured group so the
    # pattern has exactly two groups, which is what the replacer below expects,
    # and so the username stays visible -- it is useful and already logged
    # separately. `[^\]]*` rather than `\S+` so a password containing a space
    # is masked whole.
    re.compile(r"(?i)(\blogin attempt \[[^\]\n]*/)([^\]\n]*)(?=\])"),
    # Cowrie's own wording for a failed authentication, when a sensor or a
    # older version spells it out instead of using the bracket form.
    re.compile(r"(?i)(\b(?:authentication|login) (?:attempt|failed) for [^\s/]+/)(\S+)"),
    # Cowrie logs the credential it accepted. That is the visitor's password
    # and it must not be on screen unless an administrator asks for it.
    re.compile(r"(?i)(\b(?:password|passwd|pwd|passphrase)\b\s*[:=]\s*)(\S+)"),
    re.compile(r"(?i)(['\"]?(?:password|passwd|pwd|secret|token|api_?key)['\"]?\s*:\s*)(['\"]?)([^'\",\s}]+)"),
    re.compile(r"(?i)(\b(?:mysqldump|mysql)\b[^\n]*?\s-p)(\S+)"),
    re.compile(r"(?i)(-pass(?:in|out)?\s+)(\S+)"),
    re.compile(r"(?i)(\bcurl\b[^\n]*?\s-u\s+)(\S+)"),
    re.compile(r"(?i)(\bwget\b[^\n]*?--(?:user|password)=)(\S+)"),
    re.compile(r"(ssh-(?:rsa|ed25519|dss)\s+)(AAAA[A-Za-z0-9+/=]{16,})"),
    re.compile(r"(?i)(\b(?:authorization|bearer)\b\s*:?\s*)([A-Za-z0-9._\-]{16,})"),
    re.compile(r"\b((?:AKIA|ASIA))([0-9A-Z]{16})\b"),
    re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"),
]

REDACTED = "[REDACTED]"


def strip_escapes(raw: str) -> str:
    """
    Remove escape sequences and bidirectional overrides, but KEEP the
    line-editing control characters (backspace, Ctrl-C, Ctrl-U).

    Two stages matter. A transcript needs the editing characters to know what
    the visitor deleted or aborted; display needs them gone. Stripping
    everything in one pass silently breaks both: a corrected command looks like
    one long command, and an aborted one merges into the next.
    """
    return BIDI_RE.sub("", ANSI_RE.sub("", raw))


def strip_terminal_control(raw: str) -> str:
    """Remove escape sequences and all remaining control characters."""
    return CONTROL_RE.sub("", strip_escapes(raw))


def mask_sensitive(text: str) -> str:
    """
    Redact captured secrets for display.

    Applied to the *displayed* copy only. The stored recording and the stored
    event row are never modified: they are evidence, and evidence that has been
    rewritten is not evidence.
    """
    for pattern in SENSITIVE_PATTERNS:
        if pattern.groups >= 3:
            text = pattern.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
        elif pattern.groups == 2:
            text = pattern.sub(lambda m: m.group(1) + REDACTED, text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


def safe_text(raw: str, mask: bool = True, limit: int = 0) -> str:
    """
    Turn untrusted bytes into something safe to place in a page.

    Order matters. Escape sequences are stripped *first*, then secrets are
    masked. Reversing it would let an escape sequence split a secret so the
    masker missed it -- "pass\\x1b[0mword=hunter2" would survive.

    Returns plain text. Callers that build HTML must use safe_html(), not this.
    """
    if limit and len(raw) > limit:
        raw = raw[:limit] + "\n[truncated by the viewer]"
    text = strip_terminal_control(raw)
    if mask:
        text = mask_sensitive(text)
    return text


def safe_html(raw: str, mask: bool = True, limit: int = 0) -> str:
    """
    Untrusted text, sanitised and HTML-escaped, for embedding in a page.

    This is the only function that should be used to put attacker-controlled
    text into HTML. Note that the renderer still uses textContent wherever
    possible; escaping is the second line of defence, not the first.
    """
    return html.escape(safe_text(raw, mask=mask, limit=limit), quote=True)


def safe_field(raw: object, mask: bool = True, limit: int = 256) -> str:
    """
    Sanitise a single event field for display.

    Event fields are structurally safer than recordings -- a username or an
    event id is short and not a terminal stream -- but they are still chosen by
    the attacker, so they get the same treatment. Length-limited, because a
    "filename" can be 4 MB of junk.
    """
    if raw is None:
        return ""
    text = str(raw)
    if limit and len(text) > limit:
        text = text[:limit] + "\u2026"
    text = strip_terminal_control(text)
    if mask:
        text = mask_sensitive(text)
    return text


def safe_log_value(raw: object, limit: int = 200) -> str:
    """
    Sanitise a value before writing it to a log line.

    Log forging is the risk: an attacker who can put a newline in a field can
    fabricate additional log entries, which is how a real intrusion gets hidden
    behind fake noise. Newlines, carriage returns and escape sequences are
    removed rather than escaped, so a field can never span two log lines.
    """
    if raw is None:
        return ""
    text = strip_terminal_control(str(raw))
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    # Collapse runs of whitespace so a padded field cannot push real data off
    # the end of a fixed-width view in a terminal.
    text = re.sub(r"\s{2,}", " ", text).strip()
    if limit and len(text) > limit:
        text = text[:limit] + "\u2026"
    return text

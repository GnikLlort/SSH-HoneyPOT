"""
Cowrie session-recording (ttylog) parsing and command-transcript derivation.

Shared by the on-host viewer and the off-host dashboard so that both decode a
recording identically. See `shared/terminal_safety.py` for the display-side
sanitizers.

FORMAT
    Cowrie writes a sequence of records, each a fixed header followed by a
    payload of the declared length:

        struct "<iLiiLL" -> (op, tty, length, direction, sec, usec)

    OP_OPEN / OP_CLOSE / OP_WRITE / OP_EXEC are 1, 2, 3, 4.
    Direction values are TYPE_INPUT / TYPE_OUTPUT / TYPE_INTERACT = 1, 2, 3.

TWO TRAPS, both of which silently corrupt the output rather than failing:
    1. The direction constants start at 1, not 0. Reading them as 0/1 turns
       every keystroke into displayed output.
    2. Cowrie renames a finished recording to the SHA-256 of the visitor's
       input and DELETES it when an identical recording already exists. A
       recording is therefore identified by hash, not by session id, and
       `cowrie.log.closed` carries `shasum` and `duplicate` to say so. Anything
       that looks up recordings by session id finds nothing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone

from terminal_safety import REDACTED, mask_sensitive, strip_escapes, strip_terminal_control

__all__ = [
    "TTYSTRUCT",
    "TTYSTRUCT_SIZE",
    "OP_OPEN",
    "OP_CLOSE",
    "OP_WRITE",
    "OP_EXEC",
    "TYPE_INPUT",
    "TYPE_OUTPUT",
    "TYPE_INTERACT",
    "MAX_RECORDING_BYTES",
    "Chunk",
    "parse_ttylog_bytes",
    "derive_transcript",
    "parse_ts",
    "parse_ts_epoch",
]

TTYSTRUCT = "<iLiiLL"
TTYSTRUCT_SIZE = struct.calcsize(TTYSTRUCT)
OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3

DIRECTION_BY_TYPE = {
    TYPE_INPUT: "in",       # raw keystrokes, need line assembly
    TYPE_OUTPUT: "out",     # host -> visitor
    TYPE_INTERACT: "cmd",   # a complete command delivered as one record
}

# Refuse to load a recording larger than this into memory. A recording is
# attacker-controlled input; parsing one must not be able to exhaust the
# reviewer's machine.
MAX_RECORDING_BYTES = 64 * 1024 * 1024


@dataclass
class Chunk:
    """One timed piece of terminal traffic."""
    offset_ms: int
    direction: str      # "in" | "out" | "cmd"
    text: str


def parse_ttylog_bytes(data: bytes, source: str = "") -> list[Chunk]:
    """
    Parse a Cowrie ttylog into timed chunks.

    Tolerant by design: a hard kill can leave a truncated final record, and a
    partially recorded session is still worth reviewing. Parsing stops at the
    last complete record rather than raising.
    """
    if len(data) > MAX_RECORDING_BYTES:
        return [Chunk(0, "out",
                      f"[recording exceeds the {MAX_RECORDING_BYTES // (1024 * 1024)} MB "
                      f"view limit{(' in ' + source) if source else ''}]")]

    chunks: list[Chunk] = []
    first_ts: float | None = None
    pos = 0
    while pos + TTYSTRUCT_SIZE <= len(data):
        try:
            op, _tty, length, direction, sec, usec = struct.unpack(
                TTYSTRUCT, data[pos:pos + TTYSTRUCT_SIZE]
            )
        except struct.error:
            break
        pos += TTYSTRUCT_SIZE
        ts = sec + usec / 1_000_000.0
        if first_ts is None:
            first_ts = ts
        if length < 0 or pos + length > len(data):
            break                       # truncated final record
        payload = data[pos:pos + length]
        pos += length
        if op != OP_WRITE:
            continue
        kind = DIRECTION_BY_TYPE.get(direction)
        if kind is None:
            continue                    # unknown direction: skip rather than guess
        chunks.append(
            Chunk(
                offset_ms=int((ts - first_ts) * 1000),
                direction=kind,
                text=payload.decode("utf-8", "replace"),
            )
        )
    return chunks


def derive_transcript(chunks: list[Chunk], mask: bool = True) -> list[dict]:
    """
    Reconstruct the command transcript from a recording.

    This is a reconstruction of what the terminal carried, not a record of what
    executed. Cowrie's own `cowrie.command.input` events in cowrie.json are
    authoritative for that; the dashboard shows both so a reviewer can compare
    the two, and a disagreement is itself interesting.

    Escape sequences are stripped BEFORE line assembly. Doing it after would
    leave the *parameters* behind as literal text -- "\\x1b[2J" would become a
    command named "[2J" -- which both invents commands the visitor never typed
    and lets an attacker fabricate plausible transcript lines with a cursor
    sequence.
    """
    out: list[dict] = []
    buffer = ""
    offset = 0

    def emit(text: str, at: int) -> dict:
        command = text.strip()
        if not command:
            return {"command": "", "offset_ms": at, "masked": False}
        displayed = strip_terminal_control(command)
        masked = mask_sensitive(displayed) if mask else displayed
        return {
            "offset_ms": at,
            "command": masked,
            # Flagged so the UI can say "this line contained a masked value"
            # instead of silently showing something the visitor did not type.
            "masked": masked != displayed,
        }

    for chunk in chunks:
        text = strip_escapes(chunk.text)
        if chunk.direction == "cmd":
            # Exec channel: the command arrived as one complete record.
            out.append(emit(buffer, offset))      # flush any partial line
            buffer = ""
            offset = chunk.offset_ms
            out.append(emit(text, chunk.offset_ms))
            continue
        if chunk.direction != "in":
            continue
        offset = chunk.offset_ms
        for ch in text:
            if ch in ("\r", "\n"):
                out.append(emit(buffer, offset))
                buffer = ""
            elif ch in ("\x7f", "\b"):
                buffer = buffer[:-1]
            elif ch in ("\x03", "\x15", "\x04"):   # Ctrl-C, Ctrl-U, Ctrl-D
                buffer = ""
            elif ord(ch) >= 32:
                buffer += ch
    out.append(emit(buffer, offset))
    return [row for row in out if row["command"]]


def parse_ts(value: object) -> datetime | None:
    """Parse a Cowrie ISO-8601 timestamp, returning None if unusable."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_ts_epoch(value: object) -> float | None:
    """Parse a Cowrie ISO-8601 timestamp into epoch seconds."""
    parsed = parse_ts(value)
    return parsed.timestamp() if parsed else None


def iso(epoch: float | None) -> str:
    """Format epoch seconds as an ISO-8601 UTC string."""
    if epoch is None:
        return ""
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

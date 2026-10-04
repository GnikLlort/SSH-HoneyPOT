#!/usr/bin/env python3
"""
Administrator-only session playback interface for the honeypot.

WHAT THIS IS
    A read-only web viewer over Cowrie's own artefacts:
      * var/log/cowrie/cowrie.json   the event record
      * var/lib/cowrie/tty/*         the raw session recordings
      * var/lib/cowrie/downloads/*   files captured from uploads

    It reconstructs each session as a timestamped list of terminal chunks so a
    reviewer can play, pause, seek, step through, change speed, search the
    derived command transcript, and jump from a file-transfer event to the
    moment it happened. The original Cowrie recording is never modified.

WHAT THIS IS NOT
    It is not an emulator and not a replayer. Recorded bytes are only ever
    decoded to text for display. Nothing the visitor sent is executed,
    interpreted as a command, or passed to a shell - not by this process and
    not by the browser.

SECURITY MODEL
    1. Bound to 127.0.0.1 by default. Reach it through SSM Session Manager port
       forwarding or a VPN. Binding to anything else requires the explicit
       --i-know-this-exposes-evidence flag: the recordings contain captured
       credentials.
    2. No authentication of its own. It relies entirely on the network
       boundary. Do not put it behind a public load balancer.
    3. Read-only. No endpoint writes, deletes or executes anything.
    4. Attacker-controlled strings are stripped of terminal control sequences,
       masked and then rendered with textContent (never innerHTML), and the
       page is served under a per-start CSP nonce with no 'unsafe-inline'. A
       recording therefore cannot inject script, emit escape sequences that
       reach the reviewer's terminal, or reorder text with bidirectional
       overrides to disguise what was sent.
    5. Captured passwords and secrets are masked by default. Unmasking is an
       explicit query parameter, so the default view is safe to screen-share.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import secrets
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# The security-critical primitives live in shared/ so that this viewer and the
# off-host dashboard cannot drift apart. Find the directory whether this file is
# run from a repository checkout or from an installed copy under a state
# directory. A missing shared/ is a hard stop: silently falling back to a local
# copy is how a redaction fix ends up applied in only one place.
def _locate_shared() -> Path:
    here = Path(__file__).resolve().parent
    # The last candidate is the installed host's copy (deploy/install.sh
    # stage 8); HONEYPOT_STATE_DIR overrides the default state directory.
    _state = Path(os.environ.get("HONEYPOT_STATE_DIR") or "/opt/cowrie")
    for candidate in (here.parent / "shared",
                      here / "shared",
                      _state / "share" / "pkg" / "shared"):
        if (candidate / "terminal_safety.py").is_file():
            return candidate
    raise SystemExit(
        "playback: cannot find shared/terminal_safety.py.\n"
        "This viewer will not run without the sanitizers it shares with the\n"
        "dashboard: falling back to a private copy is how a redaction bug gets\n"
        "fixed in one place and not the other."
    )


sys.path.insert(0, str(_locate_shared()))

# -- Cowrie recording format -------------------------------------------------
# cowrie/core/ttylog.py
#   TTYSTRUCT = "<iLiiLL"  -> (op, tty, length, direction, sec, usec)
#   OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TTYSTRUCT = "<iLiiLL"
TTYSTRUCT_SIZE = struct.calcsize(TTYSTRUCT)
OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
# NOTE: these start at 1. An interactive session records keystrokes as
# TYPE_INPUT and host replies as TYPE_OUTPUT; an exec channel records the whole
# command once as TYPE_INTERACT and its output as TYPE_OUTPUT. Getting this
# wrong silently turns every keystroke into displayed output.
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3
DIRECTION_BY_TYPE = {
    TYPE_INPUT: "in",       # raw keystrokes, need line assembly
    TYPE_OUTPUT: "out",     # host -> visitor
    TYPE_INTERACT: "cmd",   # a complete command, delivered as one record
}
# Marker records carry no payload.
OP_WRITE_OP = OP_WRITE

MAX_RECORDING_BYTES = 64 * 1024 * 1024
MAX_DISPLAY_CHUNK = 64 * 1024


# =============================================================================
# Terminal safety
# =============================================================================
# The sanitizers now live in shared/terminal_safety.py so that this on-host
# viewer and the off-host monitoring dashboard cannot drift apart: a redaction
# fix made in one place must apply to both. They are re-exported here under the
# names the tests and the renderer use.
from terminal_safety import (  # noqa: E402,F401
    REDACTED,
    mask_sensitive,
    safe_html,
    safe_text,
    strip_escapes,
    strip_terminal_control,
)

# =============================================================================
# Artefact loading
# =============================================================================
# Chunk, the ttylog parser and the transcript deriver come from shared/ so the
# dashboard decodes a recording identically. Note Chunk.direction is one of
# "in" / "out" / "cmd" -- "cmd" is an exec-channel command delivered whole.
from ttylog import (  # noqa: E402
    Chunk,
    derive_transcript,
    parse_ttylog_bytes,
    parse_ts_epoch as _parse_ts_epoch_shared,
)


@dataclass
class Transfer:
    """A file-transfer event related to a session."""
    timestamp: str
    event: str
    filename: str = ""
    sha256: str = ""
    size: str = ""
    url: str = ""
    quarantined: bool = False
    offset_ms: int = -1     # position in the recording, for seek-on-click


@dataclass
class Session:
    session_id: str
    source_ip: str = ""
    source_port: str = ""
    username: str = ""
    login_result: str = "unknown"
    started: str = ""
    ended: str = ""
    duration_ms: int = 0
    recorded: bool = False
    # Cowrie renames a finished ttylog to the SHA-256 of its input, and deletes
    # it outright when an identical recording already exists. So the recording
    # is identified by hash, not by session id, and several sessions may share
    # one file.
    ttylog_path: str = ""
    ttylog_sha256: str = ""
    ttylog_duplicate: bool = False
    ttylog_size: int = 0
    client_version: str = ""
    chunks: list[Chunk] = field(default_factory=list)
    transfers: list[Transfer] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        return self.duration_ms / 1000.0


def parse_ts(value: str) -> float | None:
    """Parse a Cowrie ISO-8601 timestamp into epoch seconds."""
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned).timestamp()
    except ValueError:
        return None


class EvidenceStore:
    """Read-only view over a honeypot state directory."""

    def __init__(self, state_dir: Path) -> None:
        self.state = state_dir
        self.log_dir = state_dir / "var/log/cowrie"
        self.tty_dir = state_dir / "var/lib/cowrie/tty"
        self.dl_dir = state_dir / "var/lib/cowrie/downloads"
        self._sessions: dict[str, Session] = {}
        self._loaded = False

    # -- reading -----------------------------------------------------------
    def _json_events(self) -> list[dict]:
        events: list[dict] = []
        if not self.log_dir.is_dir():
            return events
        for path in sorted(self.log_dir.glob("cowrie.json*")):
            try:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            # A truncated final line after a hard kill is
                            # normal; skip it rather than failing the page.
                            continue
            except OSError:
                continue
        return events

    def load(self, force: bool = False) -> None:
        if self._loaded and not force:
            return
        sessions: dict[str, Session] = {}

        for ev in self._json_events():
            sid = ev.get("session", "")
            if not sid:
                continue
            s = sessions.setdefault(sid, Session(session_id=sid))
            eid = ev.get("eventid", "")
            ts = str(ev.get("timestamp", ""))

            if eid == "cowrie.session.connect":
                s.source_ip = ev.get("src_ip", s.source_ip)
                s.source_port = str(ev.get("src_port", s.source_port))
                s.started = ts
            elif eid == "cowrie.client.version":
                version = str(ev.get("version", ""))
                if version:
                    s.client_version = version
            elif eid == "cowrie.login.success":
                s.username = ev.get("username", s.username)
                s.login_result = "accepted"
            elif eid == "cowrie.login.failed":
                if s.login_result != "accepted":
                    s.login_result = "rejected"
                s.username = s.username or ev.get("username", "")
            elif eid == "cowrie.session.closed":
                s.ended = ts
                s.duration_ms = int(ev.get("duration_ms", 0) or 0)
            elif eid == "cowrie.log.closed":
                # Authoritative source for the recording location. `ttylog` is
                # a path relative to the state directory; `shasum` is the
                # SHA-256 of the visitor's input; `duplicate` means this
                # session's recording was byte-identical to an earlier one and
                # is therefore stored under that earlier hash.
                s.ttylog_path = str(ev.get("ttylog", ""))
                s.ttylog_sha256 = str(ev.get("shasum", ""))
                s.ttylog_duplicate = bool(ev.get("duplicate", False))
                s.ttylog_size = int(ev.get("size", 0) or 0)
                if not s.duration_ms:
                    s.duration_ms = int(ev.get("duration_ms", 0) or 0)
                s.recorded = True
            elif eid == "cowrie.log.open" and not s.ttylog_path:
                s.ttylog_path = str(ev.get("ttylog", ""))
            elif eid in ("cowrie.session.file_upload", "cowrie.session.file_download"):
                is_upload = eid.endswith("file_upload")
                s.transfers.append(
                    Transfer(
                        timestamp=ts,
                        event="upload" if is_upload else "download",
                        filename=str(ev.get("filename", "")),
                        sha256=str(ev.get("shasum", "")),
                        size=str(ev.get("size", "")),
                        url=str(ev.get("url", "")),
                        quarantined=is_upload,
                    )
                )
            elif eid == "cowrie.log.open":
                s.recorded = True
            elif eid == "cowrie.session.params" and not s.started:
                s.started = ts

        # Resolve and read each recording.
        for s in sessions.values():
            path = self._resolve_ttylog(s)
            if path is not None:
                s.chunks = self._read_ttylog(path)
                if not s.duration_ms and s.chunks:
                    s.duration_ms = s.chunks[-1].offset_ms
                if not s.ttylog_size:
                    try:
                        s.ttylog_size = path.stat().st_size
                    except OSError:
                        pass
            elif s.ttylog_duplicate:
                # Cowrie deleted this session's file because an identical
                # recording was already stored. It is not missing data.
                s.recorded = True
            # Give each transfer a position in the recording so the UI can seek
            # to it. Falls back to no seek when timestamps are unusable.
            start_epoch = parse_ts(s.started)
            if start_epoch is not None:
                for t in s.transfers:
                    t_epoch = parse_ts(t.timestamp)
                    if t_epoch is not None:
                        t.offset_ms = max(0, int((t_epoch - start_epoch) * 1000))

        self._sessions = sessions
        self._loaded = True

    def _resolve_ttylog(self, s: Session) -> Path | None:
        """
        Find the recording file for a session.

        Candidates, in order:
          1. the path Cowrie reported in cowrie.log.closed / cowrie.log.open
          2. <tty dir>/<sha256>
          3. <tty dir>/<session id>   (older Cowrie versions)

        Every candidate is confined to the tty directory. The path strings
        come from Cowrie's own log, but they are treated as untrusted anyway:
        a log line is derived from data that passed through an attacker-facing
        service, and a traversal in a filename must not let the viewer read an
        arbitrary file on the host.
        """
        tty_root = self.tty_dir.resolve()
        candidates: list[Path] = []

        if s.ttylog_path:
            raw = Path(s.ttylog_path)
            candidates.append(raw if raw.is_absolute() else (self.state / raw))
        if s.ttylog_sha256:
            candidates.append(self.tty_dir / s.ttylog_sha256)
        if s.session_id:
            candidates.append(self.tty_dir / s.session_id)

        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if not resolved.is_relative_to(tty_root):
                continue
            if resolved.is_file():
                return resolved
        return None

    @staticmethod
    def _read_ttylog(path: Path) -> list[Chunk]:
        """
        Parse a Cowrie ttylog into timed chunks.

        Delegates to shared/ttylog.py so the dashboard decodes the same file the
        same way. Tolerant of a truncated final record, which a hard kill
        leaves behind and which is still worth reviewing.
        """
        try:
            if path.stat().st_size > MAX_RECORDING_BYTES:
                return [Chunk(0, "out",
                              f"[recording exceeds the {MAX_RECORDING_BYTES // (1024 * 1024)} MB "
                              f"viewer limit]")]
            data = path.read_bytes()
        except OSError:
            return []
        return parse_ttylog_bytes(data)

    # -- accessors ---------------------------------------------------------
    def sessions(self) -> list[Session]:
        self.load()
        return sorted(self._sessions.values(), key=lambda s: s.started or "", reverse=True)

    def session(self, sid: str) -> Session | None:
        self.load()
        return self._sessions.get(sid)

    def transcript(self, s: Session, mask: bool = True) -> list[dict]:
        """
        Derive a command transcript from the recording.

        Delegates to shared/ttylog.py. This is a reconstruction of what the
        terminal carried, not a record of what executed: Cowrie's own
        `cowrie.command.input` events in cowrie.json are authoritative. Both
        views are offered so a reviewer can compare them.
        """
        return derive_transcript(s.chunks, mask=mask)

    @staticmethod
    def _emit(buffer: str, offset: int, mask: bool) -> dict:
        command = buffer.strip()
        if not command:
            return {"command": "", "offset_ms": offset, "masked": False}
        displayed = safe_text(command, mask=mask)
        return {
            "offset_ms": offset,
            "command": displayed,
            # Flag so the UI can say "this line contained a masked value"
            # instead of silently showing something different from what the
            # visitor typed.
            "masked": displayed != strip_terminal_control(command),
        }


# =============================================================================
# HTTP layer
# =============================================================================
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Cowrie session playback</title>
<style>
 :root { --bg:#12151a; --panel:#1a1f27; --fg:#d6dbe3; --dim:#7d8794;
         --accent:#5aa9e6; --in:#e6c07b; --out:#a8d08d; --warn:#e06c75; }
 * { box-sizing: border-box; }
 body { margin:0; background:var(--bg); color:var(--fg);
        font:14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
 header { padding:12px 16px; background:var(--panel); border-bottom:1px solid #2a313c;
          display:flex; gap:16px; align-items:center; flex-wrap:wrap; }
 header h1 { font-size:15px; margin:0; font-weight:600; }
 .badge { padding:2px 8px; border-radius:10px; font-size:12px; background:#2a313c; }
 .badge.mask { background:#3a3320; color:#e6c07b; }
 .badge.unmask { background:#40202a; color:#e06c75; }
 main { display:grid; grid-template-columns: 300px 1fr; height: calc(100vh - 58px); }
 aside { border-right:1px solid #2a313c; overflow:auto; background:var(--panel); }
 aside input { width:100%; padding:8px; background:#12151a; border:0; border-bottom:1px solid #2a313c;
               color:var(--fg); font:inherit; }
 .sess { padding:8px 12px; border-bottom:1px solid #222831; cursor:pointer; }
 .sess:hover { background:#222831; }
 .sess.active { background:#243040; }
 .sess .ip { color:var(--accent); }
 .sess .meta { color:var(--dim); font-size:12px; }
 section { display:flex; flex-direction:column; min-width:0; }
 .toolbar { padding:8px 12px; background:var(--panel); border-bottom:1px solid #2a313c;
            display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
 button { background:#2a313c; color:var(--fg); border:1px solid #39414f; border-radius:4px;
          padding:5px 10px; font:inherit; cursor:pointer; }
 button:hover { background:#333c4a; }
 input[type=range] { flex:1; min-width:140px; }
 input[type=text], select { background:#12151a; color:var(--fg); border:1px solid #39414f;
          border-radius:4px; padding:4px 8px; font:inherit; }
 .time { color:var(--dim); font-size:12px; min-width:120px; }
 .term { flex:1; overflow:auto; padding:12px 16px; white-space:pre-wrap; word-break:break-word;
         background:#0e1116; }
 .term .in { color:var(--in); }
 .term .out { color:var(--out); }
 .empty { color:var(--dim); padding:24px; }
 .tabs { display:flex; gap:8px; padding:8px 12px; background:var(--panel);
         border-bottom:1px solid #2a313c; align-items:center; }
 .tabs button.active { background:#243040; border-color:var(--accent); }
 .pane { flex:1; overflow:auto; padding:12px 16px; display:none; }
 .pane.shown { display:block; }
 table { border-collapse:collapse; width:100%; }
 th, td { text-align:left; padding:6px 10px; border-bottom:1px solid #222831; font-size:13px;
          vertical-align:top; }
 th { color:var(--dim); font-weight:500; }
 tbody tr:hover { background:#1a1f27; cursor:pointer; }
 .hash { color:var(--dim); font-size:12px; word-break:break-all; }
 .masked-note { color:var(--warn); font-size:11px; }
 .lede { padding:10px 16px; background:#3a3320; color:#e6c07b; font-size:12px; }
</style>
</head>
<body>
<header>
  <h1>Cowrie session playback</h1>
  <span class="badge" id="count"></span>
  <span class="badge __MASKCLASS__">__MASKTEXT__</span>
  <span style="color:var(--dim);font-size:12px">
    read-only &middot; recordings are displayed, never executed &middot; control sequences escaped
  </span>
</header>
<main>
  <aside>
    <input id="filter" type="text" placeholder="filter by IP, user or session id" autocomplete="off">
    <div id="list"></div>
  </aside>
  <section>
    <div class="toolbar">
      <button id="play">Play</button>
      <button id="step">Step</button>
      <button id="back">&minus;5s</button>
      <button id="fwd">+5s</button>
      <span class="time" id="clock">0.0s / 0.0s</span>
      <input type="range" id="seek" min="0" max="1000" value="0">
      <label style="color:var(--dim)">speed
        <select id="speed">
          <option>0.25</option><option>0.5</option>
          <option selected>1</option><option>2</option>
          <option>4</option><option>8</option>
        </select>
      </label>
    </div>
    <div class="tabs">
      <button data-tab="term" class="active">Terminal</button>
      <button data-tab="transcript">Command transcript</button>
      <button data-tab="transfers">File transfers</button>
      <input type="text" id="cmdfilter" placeholder="search commands" autocomplete="off" style="margin-left:auto;width:220px">
    </div>
    <div id="tab-term" class="term pane shown"></div>
    <div id="tab-transcript" class="pane"></div>
    <div id="tab-transfers" class="pane"></div>
  </section>
</main>
<script nonce="__NONCE__">
"use strict";
// The session index is embedded as JSON. The server escapes <, >, & and the JS
// line separators, so the data cannot close this script element or break out of
// the string context.
const SESSIONS = __SESSIONS__;

let current = null, chunks = [], timer = null, pos = 0, lastTick = 0;
const $ = (id) => document.getElementById(id);

function fmt(sec) {
  if (!isFinite(sec)) return "0.0s";
  const m = Math.floor(sec / 60), s = sec - m * 60;
  return (m > 0 ? m + "m " : "") + s.toFixed(1) + "s";
}
function totalMs() { return current ? Math.max(1, current.duration_ms || 1) : 1; }

function renderList(filter) {
  const list = $("list");
  list.textContent = "";
  const f = (filter || "").toLowerCase();
  let shown = 0;
  SESSIONS.forEach((s, i) => {
    const hay = (s.source_ip + " " + s.username + " " + s.session_id).toLowerCase();
    if (f && hay.indexOf(f) === -1) return;
    shown++;
    const div = document.createElement("div");
    div.className = "sess" + (current && current.session_id === s.session_id ? " active" : "");
    const ip = document.createElement("div");
    ip.className = "ip";
    ip.textContent = s.source_ip || "unknown source";
    const meta = document.createElement("div");
    meta.className = "meta";
    // textContent throughout: nothing from a recording is ever parsed as HTML.
    meta.textContent = (s.username || "?") + " \\u00b7 " + s.login_result +
                       " \\u00b7 " + fmt((s.duration_ms || 0) / 1000) +
                       (s.recorded ? "" : " \\u00b7 no recording");
    div.appendChild(ip);
    div.appendChild(meta);
    div.addEventListener("click", () => loadSession(i));
    list.appendChild(div);
  });
  $("count").textContent = shown + " session" + (shown === 1 ? "" : "s");
}

function loadSession(idx) {
  stop();
  current = SESSIONS[idx];
  chunks = current.chunks || [];
  pos = 0;
  $("seek").max = String(totalMs());
  $("seek").value = "0";
  $("cmdfilter").value = "";
  renderTranscript();
  renderTransfers();
  renderTerminalUpTo(0);
  renderList($("filter").value);
  updateClock();
}

function updateClock() {
  $("clock").textContent = fmt(pos / 1000) + " / " + fmt(totalMs() / 1000);
  $("seek").value = String(Math.round(pos));
}

function renderTerminalUpTo(ms) {
  const term = $("tab-term");
  term.textContent = "";
  if (!chunks.length) {
    const d = document.createElement("div");
    d.className = "empty";
    d.textContent = (current && current.recorded)
      ? "Recording is empty."
      : "No session recording was captured for this session.";
    term.appendChild(d);
    return;
  }
  let shown = 0;
  for (const c of chunks) {
    if (c.offset_ms > ms) break;
    const span = document.createElement("span");
    span.className = c.direction === "in" ? "in" : "out";
    span.textContent = c.text;   // textContent: no HTML is ever parsed.
    term.appendChild(span);
    shown++;
  }
  if (!shown) {
    const d = document.createElement("div");
    d.className = "empty";
    d.textContent = "Nothing yet \\u2014 press Play or Step.";
    term.appendChild(d);
  }
  term.scrollTop = term.scrollHeight;
}

function renderTranscript() {
  const host = $("tab-transcript");
  host.textContent = "";
  const query = ($("cmdfilter").value || "").toLowerCase();
  const all = current ? (current.transcript || []) : [];
  const rows = query ? all.filter((r) => !r.masked && r.command.toLowerCase().indexOf(query) !== -1) : all;
  if (!rows.length) {
    const d = document.createElement("div");
    d.className = "empty";
    d.textContent = all.length
      ? "No command matches that search."
      : "No interactive commands found in this session (exec-only sessions appear in the event log, not the recording).";
    host.appendChild(d);
    return;
  }
  const note = document.createElement("div");
  note.className = "lede";
  note.textContent = "Derived from the recording. Cowrie's cowrie.command.input events in cowrie.json " +
                     "are authoritative. Click a row to seek the terminal to that moment.";
  host.appendChild(note);
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const hr = document.createElement("tr");
  ["t", "command"].forEach((h) => { const th = document.createElement("th"); th.textContent = h; hr.appendChild(th); });
  thead.appendChild(hr);
  table.appendChild(thead);
  const tb = document.createElement("tbody");
  for (const r of rows) {
    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    td1.textContent = fmt(r.offset_ms / 1000);
    td1.style.color = "var(--dim)";
    const td2 = document.createElement("td");
    td2.textContent = r.command;
    if (r.masked) {
      const n = document.createElement("span");
      n.className = "masked-note";
      n.textContent = "  (contained a masked value)";
      td2.appendChild(n);
    }
    tr.appendChild(td1);
    tr.appendChild(td2);
    tr.addEventListener("click", () => {
      stop();
      pos = r.offset_ms;
      renderTerminalUpTo(pos);
      updateClock();
      showTab("term");
    });
    tb.appendChild(tr);
  }
  table.appendChild(tb);
  host.appendChild(table);
}

function renderTransfers() {
  const host = $("tab-transfers");
  host.textContent = "";
  const rows = current ? (current.transfers || []) : [];
  if (!rows.length) {
    const d = document.createElement("div");
    d.className = "empty";
    d.textContent = "No file transfers recorded for this session.";
    host.appendChild(d);
    return;
  }
  const note = document.createElement("div");
  note.className = "lede";
  note.textContent = "Captured bytes are quarantined off-host and are never opened or executed here. " +
                     "Click a row to seek the terminal to that moment.";
  host.appendChild(note);
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const hr = document.createElement("tr");
  ["time", "event", "file", "size", "sha256"].forEach((h) => {
    const th = document.createElement("th"); th.textContent = h; hr.appendChild(th);
  });
  thead.appendChild(hr);
  table.appendChild(thead);
  const tb = document.createElement("tbody");
  for (const r of rows) {
    const tr = document.createElement("tr");
    const cells = [
      r.timestamp,
      r.event + (r.quarantined ? " (quarantined, not executed)" : ""),
      r.filename || r.url || "-",
      r.size || "-",
      r.sha256 || "-",
    ];
    cells.forEach((v, i) => {
      const td = document.createElement("td");
      td.textContent = v === undefined || v === null ? "" : String(v);
      if (i === 4) td.className = "hash";
      tr.appendChild(td);
    });
    if (typeof r.offset_ms === "number" && r.offset_ms >= 0) {
      tr.addEventListener("click", () => {
        stop();
        pos = Math.min(totalMs(), r.offset_ms);
        renderTerminalUpTo(pos);
        updateClock();
        showTab("term");
      });
    }
    tb.appendChild(tr);
  }
  table.appendChild(tb);
  host.appendChild(table);
}

// -- playback ---------------------------------------------------------------
function step() {
  // Advance by wall-clock time scaled by the chosen speed, then snap to the
  // next recorded chunk boundary so output arriving in a burst is not skipped.
  const speed = parseFloat($("speed").value) || 1;
  const now = performance.now();
  const delta = (now - lastTick) * speed;
  lastTick = now;
  pos = Math.min(totalMs(), pos + delta);
  const next = chunks.find((c) => c.offset_ms > pos);
  if (next) pos = Math.min(totalMs(), next.offset_ms);
  renderTerminalUpTo(pos);
  updateClock();
  if (pos >= totalMs()) stop();
}

function play() {
  if (timer) return;
  lastTick = performance.now();
  timer = setInterval(step, 100);
  $("play").textContent = "Pause";
}
function stop() {
  if (timer) { clearInterval(timer); timer = null; }
  $("play").textContent = "Play";
}
function jump(deltaMs) {
  stop();
  lastTick = performance.now();
  pos = Math.max(0, Math.min(totalMs(), pos + deltaMs));
  renderTerminalUpTo(pos);
  updateClock();
}
function showTab(which) {
  document.querySelectorAll(".tabs button").forEach((x) =>
    x.classList.toggle("active", x.dataset.tab === which));
  ["term", "transcript", "transfers"].forEach((t) => {
    $("tab-" + t).classList.toggle("shown", t === which);
  });
}

$("play").addEventListener("click", () => { timer ? stop() : play(); });
$("step").addEventListener("click", () => { stop(); lastTick = performance.now(); step(); });
$("back").addEventListener("click", () => jump(-5000));
$("fwd").addEventListener("click", () => jump(5000));
$("seek").addEventListener("input", (e) => {
  stop();
  lastTick = performance.now();
  pos = parseInt(e.target.value, 10) || 0;
  renderTerminalUpTo(pos);
  updateClock();
});
$("filter").addEventListener("input", (e) => renderList(e.target.value));
$("cmdfilter").addEventListener("input", renderTranscript);
document.querySelectorAll(".tabs button").forEach((b) => {
  b.addEventListener("click", () => showTab(b.dataset.tab));
});

renderList("");
if (SESSIONS.length) loadSession(0);
</script>
</body>
</html>
"""


def build_payload(store: EvidenceStore, mask: bool) -> str:
    if not store.sessions():
        return "[]"
    payload = []
    for s in store.sessions():
        payload.append({
            "session_id": s.session_id,
            "source_ip": s.source_ip,
            "source_port": s.source_port,
            "username": s.username,
            "login_result": s.login_result,
            "started": s.started,
            "ended": s.ended,
            "duration_ms": int(s.duration_ms),
            "recorded": s.recorded,
            "recording_sha256": s.ttylog_sha256,
            "recording_shared": s.ttylog_duplicate,
            "recording_bytes": s.ttylog_size,
            "client_version": s.client_version,
            "chunks": [
                {
                    "offset_ms": c.offset_ms,
                    "direction": c.direction,
                    "text": safe_text(c.text, mask=mask),
                }
                for c in s.chunks
            ],
            "transcript": store.transcript(s, mask=mask),
            "transfers": [
                {
                    "timestamp": t.timestamp,
                    "event": t.event,
                    "filename": t.filename,
                    "sha256": t.sha256,
                    "size": t.size,
                    "url": t.url,
                    "quarantined": t.quarantined,
                    "offset_ms": t.offset_ms,
                }
                for t in s.transfers
            ],
        })
    # json.dumps escapes non-ASCII by default; additionally escape the
    # characters that can terminate a <script> element or a JS string, so
    # embedding this payload in the page is safe.
    raw = json.dumps(payload)
    return (raw.replace("<", "\\u003c").replace(">", "\\u003e")
               .replace("&", "\\u0026").replace("\u2028", "\\u2028")
               .replace("\u2029", "\\u2029"))


class Handler(BaseHTTPRequestHandler):
    server_version = "cowrie-playback"
    sys_version = ""
    store: EvidenceStore
    nonce: str = ""
    # Default posture: refuse to be framed, because a framed playback UI can be
    # clickjacked. --allow-framing relaxes this for local UI previews only and
    # prints a warning; it must not be used on a real deployment.
    allow_framing: bool = False

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        # Keep visitor-controlled data (query strings, paths) out of the log.
        sys.stderr.write("[playback] %s\n" % fmt.replace("%s", "<redacted>"))

    def _send(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Defence in depth. The page's own script carries the nonce, so
        # 'unsafe-inline' is not needed: even a successful markup injection
        # could not execute script.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-%s'; "
            "img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors %s; object-src 'none'"
            % (self.nonce, "*" if self.allow_framing else "'none'"),
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        if not self.allow_framing:
            self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        # Unmasking is explicit and off by default, so the default view is safe
        # to screen-share or project during a review.
        mask = "unmask=1" not in query

        if path in ("/", "/index.html"):
            self.store.load()
            payload = build_payload(self.store, mask)
            page = (PAGE
                    .replace("__NONCE__", self.nonce)
                    .replace("__SESSIONS__", payload)
                    .replace("__MASKCLASS__", "mask" if mask else "unmask")
                    .replace("__MASKTEXT__",
                             "secrets masked &mdash; append ?unmask=1 to reveal"
                             if mask else "SECRETS UNMASKED"))
            self._send(page.encode("utf-8"))
            return
        if path == "/healthz":
            self._send(b"ok\n", ctype="text/plain; charset=utf-8")
            return
        self._send(b"not found\n", status=404, ctype="text/plain; charset=utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Administrator-only Cowrie session playback interface.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--state", default="/opt/cowrie", help="honeypot state directory")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; reach it over SSM or a VPN)")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--i-know-this-exposes-evidence", action="store_true",
                    help="required to bind to anything other than 127.0.0.1")
    ap.add_argument("--allow-framing", action="store_true",
                    help="permit the page to be embedded in an iframe; for local "
                         "UI previews only, never on a real deployment")
    args = ap.parse_args()

    if args.allow_framing:
        print("warning: --allow-framing disables X-Frame-Options and permits "
              "framing.\n         Use this only to preview the local UI. A real "
              "deployment must keep the\n         default so the playback view "
              "cannot be clickjacked.", file=sys.stderr)

    if args.host not in ("127.0.0.1", "::1", "localhost") and not args.i_know_this_exposes_evidence:
        print(
            "refusing to bind to %s.\n"
            "This interface serves captured credentials and session recordings with no\n"
            "authentication of its own. Reach it through AWS SSM port forwarding:\n"
            "  aws ssm start-session --target <instance> \\\n"
            "      --document-name AWS-StartPortForwardingSession \\\n"
            "      --parameters '{\"portNumber\":[\"%d\"],\"localPortNumber\":[\"%d\"]}'\n"
            "If you truly intend to expose it, pass --i-know-this-exposes-evidence."
            % (args.host, args.port, args.port),
            file=sys.stderr,
        )
        return 2

    state = Path(args.state)
    if not (state / "var/log/cowrie").is_dir():
        print(f"warning: {state}/var/log/cowrie does not exist; the viewer will show nothing",
              file=sys.stderr)

    Handler.store = EvidenceStore(state)
    Handler.nonce = secrets.token_urlsafe(16)
    Handler.allow_framing = args.allow_framing
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"playback UI on http://{args.host}:{args.port}  (state: {state})")
    print("read-only; recordings are displayed, never executed.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
HTML rendering for the dashboard.

RULES FOR THIS MODULE
    1. Attacker-controlled text goes through `shared/terminal_safety.py`
       (sanitise + mask) and then `html.escape`. Both steps, always.
    2. Client-side rendering uses `textContent`, never `innerHTML`. The escaping
       in (1) is the second line of defence, not the first.
    3. No external stylesheets, fonts, scripts or images. The page is one
       response with a per-start CSP nonce and `default-src 'none'`, so nothing
       loaded from the network can influence it.
    4. No inline event handlers (`onclick=...`). They would need
       `unsafe-inline` in the CSP, which is exactly the protection that stops a
       malicious recording from running script.
"""

from __future__ import annotations

import html
import os
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# shared/ sits beside the package in a checkout and under
# $STATE_DIR/share/pkg/ in an installed host (deploy/install.sh stage 8).
_state = Path(os.environ.get("HONEYPOT_STATE_DIR") or "/opt/cowrie")
for _cand in (_HERE.parent / "shared", _state / "share" / "pkg" / "shared"):
    if (_cand / "terminal_safety.py").is_file():
        sys.path.insert(0, str(_cand))
        break

from terminal_safety import REDACTED, safe_html, safe_text  # noqa: E402

STYLE = """
:root{
  --bg:#0e1116; --panel:#161b22; --panel2:#1c2230; --line:#252d3a; --fg:#d7dde6;
  --dim:#7b8794; --accent:#4d9de0; --ok:#4caf7d; --warn:#d8a657; --crit:#e06c75;
  --in:#d8a657; --out:#8fbf7f; --mask:#b58ee0; --link:#6fb3e0;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
header.top{background:var(--panel);border-bottom:1px solid var(--line);
  padding:0 16px;display:flex;align-items:center;gap:20px;height:52px;position:sticky;top:0;z-index:10}
header.top .brand{font-weight:600;color:var(--fg)}
nav.main{display:flex;gap:2px;flex:1}
nav.main a{padding:6px 12px;border-radius:4px;color:var(--dim)}
nav.main a:hover{background:var(--panel2);color:var(--fg);text-decoration:none}
nav.main a.active{background:var(--panel2);color:var(--fg)}
.who{color:var(--dim);font-size:12px;display:flex;align-items:center;gap:10px}
.role{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:1px 8px;font-size:11px}
main{padding:18px 20px 60px;max-width:1600px}
h1{font-size:17px;margin:0 0 4px} h2{font-size:14px;margin:22px 0 8px;color:var(--dim);
  text-transform:uppercase;letter-spacing:.06em;font-weight:600}
.sub{color:var(--dim);font-size:12px;margin-bottom:16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:8px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px}
.card .n{font-size:22px;font-weight:600} .card .l{color:var(--dim);font-size:11px;
  text-transform:uppercase;letter-spacing:.05em}
.card.accent .n{color:var(--accent)} .card.ok .n{color:var(--ok)} .card.crit .n{color:var(--crit)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:14px}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);
  vertical-align:top;font-size:13px}
th{color:var(--dim);font-weight:500;font-size:11px;text-transform:uppercase;
  letter-spacing:.05em;position:sticky;top:52px;background:var(--panel);z-index:5}
tbody tr:hover{background:var(--panel2)}
td.mono{font-family:inherit}
.nowrap{white-space:nowrap}
.trunc{max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}
.muted{color:var(--dim)} .small{font-size:12px}
.badge{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;
  background:var(--panel2);border:1px solid var(--line)}
.badge.ok{color:var(--ok);border-color:#274b38} .badge.rej{color:var(--crit);border-color:#4b2727}
.badge.unk{color:var(--dim)} .badge.up{color:var(--warn);border-color:#4b4027}
.badge.dl{color:var(--accent);border-color:#274060}
.badge.crit{color:var(--crit);border-color:#4b2727} .badge.warn{color:var(--warn);border-color:#4b4027}
.badge.info{color:var(--accent)}
.redacted{color:var(--mask);font-style:italic}
form.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;
  background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px;margin-bottom:14px}
.field{display:flex;flex-direction:column;gap:3px}
.field label{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
input,select{background:var(--bg);border:1px solid var(--line);border-radius:4px;color:var(--fg);
  padding:5px 8px;font:inherit;font-size:13px;min-width:0}
input[type=text],input[type=password],input[type=date],input[type=search]{width:150px}
input.wide{width:230px}
button{background:var(--panel2);color:var(--fg);border:1px solid var(--line);
  border-radius:4px;padding:6px 12px;font:inherit;cursor:pointer}
button:hover{background:#242c3a} button.primary{background:#1d4banon}
button.primary{background:#1d4a75;border-color:#2c6ea8}
button:disabled{opacity:.45;cursor:default}
.pager{display:flex;gap:10px;align-items:center;margin-top:10px;color:var(--dim);font-size:12px}
.empty{color:var(--dim);padding:26px;text-align:center;border:1px dashed var(--line);border-radius:6px}
.term{background:#080a0e;border:1px solid var(--line);border-radius:6px;
  padding:12px 14px;height:420px;overflow:auto;white-space:pre-wrap;
  word-break:break-word;font-size:13px}
.term .in{color:var(--in)} .term .out{color:var(--out)} .term .cmd{color:var(--accent)}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0}
.toolbar input[type=range]{flex:1;min-width:160px;padding:0}
.clock{color:var(--dim);font-size:12px;min-width:120px}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:14px 0 0}
.tabs button{background:none;border:none;border-bottom:2px solid transparent;
  border-radius:0;padding:8px 12px;color:var(--dim)}
.tabs button.active{color:var(--fg);border-bottom-color:var(--accent)}
.tabpane{display:none;padding-top:12px} .tabpane.shown{display:block}
.kv{display:grid;grid-template-columns:180px 1fr;gap:4px 14px;font-size:13px}
.kv .k{color:var(--dim)} .kv .v{word-break:break-word}
.sig{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-bottom:1px solid var(--line)}
.sig:last-child{border-bottom:none}
.sig .dot{width:8px;height:8px;border-radius:50%;margin-top:6px;flex:none}
.dot.ok{background:var(--ok)} .dot.warn{background:var(--warn)} .dot.crit{background:var(--crit)}
.notice{border-radius:6px;padding:10px 14px;margin-bottom:14px;font-size:13px;border:1px solid}
.notice.crit{background:#2a1418;border-color:#4b2727;color:#f0b0b5}
.notice.warn{background:#2a2414;border-color:#4b4027;color:#e8d49a}
.notice.info{background:#141c2a;border-color:#274060;color:#bcd6ef}
.notice.ok{background:#132218;border-color:#274b38;color:#a8d8b8}
.loginwrap{max-width:400px;margin:8vh auto}
.loginwrap h1{font-size:19px;margin-bottom:6px}
.loginwrap .panel{padding:20px}
.loginwrap label{display:block;font-size:11px;color:var(--dim);text-transform:uppercase;
  letter-spacing:.05em;margin:12px 0 4px}
.loginwrap input{width:100%} .loginwrap button{width:100%;margin-top:18px;padding:9px}
.masked-note{color:var(--mask);font-size:11px}
.bar{height:6px;background:var(--panel2);border-radius:3px;overflow:hidden;margin-top:4px}
.bar span{display:block;height:100%;background:var(--accent)}
.chart{display:flex;align-items:flex-end;gap:3px;height:90px;padding:6px 0}
.chart .col{flex:1;display:flex;flex-direction:column;justify-content:flex-end;gap:1px;min-width:8px}
.chart .col .f{background:var(--crit);min-height:1px} .chart .col .a{background:var(--ok);min-height:1px}
.chart .lbl{color:var(--dim);font-size:10px;text-align:center;margin-top:4px}
code{background:var(--panel2);padding:1px 5px;border-radius:3px;font-size:12px}
.hash{font-size:11px;color:var(--dim);word-break:break-all}
footer{color:var(--dim);font-size:11px;padding:20px;text-align:center}
"""

# Shared playback engine. Used by the session detail page.
# Everything that renders recorded bytes uses textContent: a recording is
# attacker-controlled input and must never be parsed as HTML.
PLAYBACK_JS = r"""
"use strict";
const DATA = window.__SESSION_DATA__ || {chunks:[],transcript:[],transfers:[]};
const $ = (id) => document.getElementById(id);
let timer = null, pos = 0, lastTick = 0;

function fmt(sec){
  if(!isFinite(sec)) return "0.0s";
  const m = Math.floor(sec/60), s = sec - m*60;
  return (m>0 ? m+"m " : "") + s.toFixed(1) + "s";
}
function fmtBytes(n){
  if(n===null||n===undefined||n==="") return "";
  n = Number(n); if(!isFinite(n)) return "";
  const u=["B","KiB","MiB","GiB"]; let i=0;
  while(n>=1024 && i<u.length-1){n/=1024;i++;}
  return (i===0? n : n.toFixed(1))+" "+u[i];
}
function totalMs(){ return Math.max(1, (DATA.chunks.length? DATA.chunks[DATA.chunks.length-1].offset_ms : 1)); }

function renderTerminalUpTo(ms){
  const term = $("term");
  term.textContent = "";
  if(!DATA.chunks.length){
    const d = document.createElement("div");
    d.className = "empty";
    d.textContent = DATA.recorded
      ? "The recording for this session is empty."
      : "No recording was captured for this session.";
    term.appendChild(d); return;
  }
  let shown = 0;
  for(const c of DATA.chunks){
    if(c.offset_ms > ms) break;
    const span = document.createElement("span");
    span.className = c.direction;
    span.textContent = c.text;
    term.appendChild(span); shown++;
  }
  if(!shown){
    const d = document.createElement("div");
    d.className = "empty";
    d.textContent = "Nothing yet \u2014 press Play or Step.";
    term.appendChild(d);
  }
  term.scrollTop = term.scrollHeight;
}
function updateClock(){
  $("clock").textContent = fmt(pos/1000)+" / "+fmt(totalMs()/1000);
  $("seek").value = String(Math.round(pos));
}
function step(){
  const speed = parseFloat($("speed").value)||1;
  const now = performance.now();
  pos = Math.min(totalMs(), pos + (now-lastTick)*speed);
  lastTick = now;
  const next = DATA.chunks.find((c)=>c.offset_ms > pos);
  if(next) pos = Math.min(totalMs(), next.offset_ms);
  renderTerminalUpTo(pos); updateClock();
  if(pos >= totalMs()) stop();
}
function play(){
  if(timer) return;
  lastTick = performance.now();
  timer = setInterval(step, 100);
  $("play").textContent = "Pause";
}
function stop(){
  if(timer){clearInterval(timer); timer=null;}
  $("play").textContent = "Play";
}
function jump(delta){
  stop(); lastTick = performance.now();
  pos = Math.max(0, Math.min(totalMs(), pos+delta));
  renderTerminalUpTo(pos); updateClock();
}
function seekTo(ms){
  stop(); lastTick = performance.now();
  pos = Math.max(0, Math.min(totalMs(), ms));
  renderTerminalUpTo(pos); updateClock(); showTab("term");
}
function showTab(which){
  document.querySelectorAll(".tabs button").forEach((b)=>
    b.classList.toggle("active", b.dataset.tab === which));
  document.querySelectorAll(".tabpane").forEach((p)=>
    p.classList.toggle("shown", p.id === "tab-"+which));
}
function renderTranscript(){
  const host = $("tab-transcript");
  host.textContent = "";
  const query = ($("cmdfilter").value||"").toLowerCase();
  const rows = DATA.transcript.filter((r)=>
    !query || r.command.toLowerCase().indexOf(query) !== -1);
  const note = document.createElement("div");
  note.className = "sub";
  note.textContent = "Derived from the recording. Cowrie's cowrie.command.input events, "
    + "listed below, are authoritative. Click a row to seek the terminal.";
  host.appendChild(note);
  if(!rows.length){
    const d = document.createElement("div"); d.className="empty";
    d.textContent = DATA.transcript.length ? "No command matches that search."
      : "No interactive commands in this recording (an exec-only session has none).";
    host.appendChild(d); return;
  }
  const t = document.createElement("table");
  const head = document.createElement("thead");
  const hr = document.createElement("tr");
  ["t","command"].forEach((h)=>{const th=document.createElement("th");th.textContent=h;hr.appendChild(th);});
  head.appendChild(hr); t.appendChild(head);
  const tb = document.createElement("tbody");
  rows.forEach((r)=>{
    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    td1.textContent = fmt(r.offset_ms/1000); td1.className="nowrap muted";
    const td2 = document.createElement("td");
    td2.textContent = r.command;
    if(r.masked){
      const n = document.createElement("span");
      n.className = "masked-note";
      n.textContent = "  (contained a masked value)";
      td2.appendChild(n);
    }
    tr.appendChild(td1); tr.appendChild(td2);
    tr.style.cursor = "pointer";
    tr.addEventListener("click", ()=> seekTo(r.offset_ms));
    tb.appendChild(tr);
  });
  t.appendChild(tb); host.appendChild(t);
}
function renderTransfers(){
  const host = $("tab-transfers");
  host.textContent = "";
  if(!DATA.transfers.length){
    const d = document.createElement("div"); d.className="empty";
    d.textContent = "No file transfers recorded for this session.";
    host.appendChild(d); return;
  }
  const note = document.createElement("div");
  note.className="sub";
  note.textContent = "Captured files are quarantined and are shown by metadata only. "
    + "Nothing here opens, previews or downloads a captured file. Click a row to seek.";
  host.appendChild(note);
  const t = document.createElement("table");
  const head = document.createElement("thead");
  const hr = document.createElement("tr");
  ["time","event","file","size","sha256"].forEach((h)=>{
    const th=document.createElement("th"); th.textContent=h; hr.appendChild(th);});
  head.appendChild(hr); t.appendChild(head);
  const tb = document.createElement("tbody");
  DATA.transfers.forEach((r)=>{
    const tr = document.createElement("tr");
    const cells = [r.timestamp,
      r.event + (r.quarantined ? " (quarantined, not executed)" : ""),
      r.filename || r.url || "-", fmtBytes(r.size) || "-", r.sha256 || "-"];
    cells.forEach((v,i)=>{
      const td = document.createElement("td");
      td.textContent = (v===null||v===undefined) ? "" : String(v);
      if(i===4) td.className = "hash";
      tr.appendChild(td);
    });
    if(typeof r.offset_ms === "number" && r.offset_ms >= 0){
      tr.style.cursor="pointer";
      tr.addEventListener("click", ()=> seekTo(r.offset_ms));
    }
    tb.appendChild(tr);
  });
  t.appendChild(tb); host.appendChild(t);
}

$("play").addEventListener("click", ()=>{ timer ? stop() : play(); });
$("step").addEventListener("click", ()=>{ stop(); lastTick=performance.now(); step(); });
$("back").addEventListener("click", ()=> jump(-5000));
$("fwd").addEventListener("click", ()=> jump(5000));
$("seek").addEventListener("input", (e)=>{
  stop(); lastTick=performance.now();
  pos = parseInt(e.target.value,10)||0;
  renderTerminalUpTo(pos); updateClock();
});
$("cmdfilter").addEventListener("input", renderTranscript);
document.querySelectorAll(".tabs button").forEach((b)=>
  b.addEventListener("click", ()=> showTab(b.dataset.tab)));

renderTerminalUpTo(0); updateClock(); renderTranscript(); renderTransfers();
"""


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def esc(value: object, mask: bool = True, limit: int = 400) -> str:
    """Escape an untrusted field for HTML output."""
    if value is None:
        return ""
    return safe_html(str(value), mask=mask, limit=limit)


def fmt_ts(value: object) -> str:
    """Render a timestamp compactly. Non-string input is not interpreted."""
    if not value:
        return ""
    text = str(value)
    if len(text) >= 19 and text[4] == "-" and text[10] in ("T", " "):
        return text[0:19].replace("T", " ") + "Z"
    return safe_html(text, limit=40)


def fmt_ago(epoch: float | None, now: float | None = None) -> str:
    if not epoch:
        return ""
    import time
    delta = (now or time.time()) - float(epoch)
    if delta < 0:
        return "in the future"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if delta >= size:
            return f"{int(delta // size)}{unit} ago"
    return f"{int(delta)}s ago"


def fmt_duration(ms: object) -> str:
    try:
        value = float(ms or 0) / 1000.0
    except (TypeError, ValueError):
        return ""
    if value < 60:
        return f"{value:.1f}s"
    minutes, seconds = divmod(int(value), 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def fmt_bytes(value: object) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return ""


def outcome_badge(result: str) -> str:
    mapping = {"accepted": ("ok", "accepted"), "rejected": ("rej", "rejected")}
    css, label = mapping.get(result or "", ("unk", result or "unknown"))
    return f'<span class="badge {css}">{html.escape(label)}</span>'


def secret_cell(value: object, unmasked: bool) -> str:
    """
    Render a captured credential.

    Masked by default. This is not cosmetic: the dashboard is often on a shared
    screen during an incident review, and a captured password displayed without
    being asked for is a disclosure. Unmasking requires the `unmask` permission
    and is audited.
    """
    if value in (None, ""):
        return '<span class="muted">-</span>'
    if not unmasked:
        return f'<span class="redacted">{html.escape(REDACTED)}</span>'
    return f'<span class="redacted">{esc(value, mask=False, limit=120)}</span>'


def page(title: str, body: str, nonce: str, principal=None, active: str = "",
         script: str = "", extra_head: str = "") -> str:
    """
    Full page shell.

    The CSP is `default-src 'none'` with a per-start nonce: no external
    resource can load and no inline script can run unless it carries the nonce
    issued by this process. Even a successful markup injection from a recording
    therefore cannot execute.
    """
    nav_items = [
        ("overview", "/", "Overview"),
        ("events", "/events", "Events"),
        ("sessions", "/sessions", "Sessions"),
        ("transfers", "/transfers", "Transfers"),
        ("health", "/health", "Health"),
    ]
    if principal and principal.can("audit.read"):
        nav_items.append(("audit", "/audit", "Audit"))
    if principal and principal.can("users.read"):
        nav_items.append(("users", "/users", "Users"))

    # Built by concatenation rather than a nested conditional inside an
    # f-string: an f-string expression part cannot contain a backslash before
    # Python 3.12, and an escaped quote here is exactly that.
    nav = "".join(
        f'<a href="{href}" class="{"active" if key == active else ""}">'
        f'{html.escape(label)}</a>'
        for key, href, label in nav_items)

    who = ""
    if principal:
        who = (f'<span class="who">{esc(principal.username, limit=64)}'
               f'<span class="role">{esc(principal.role, limit=16)}</span>'
               f'<form method="post" action="/logout" style="display:inline">'
               f'<input type="hidden" name="csrf" value="{esc(_CSRF_PLACEHOLDER, mask=False)}">'
               f'<button type="submit">Sign out</button></form></span>')
    else:
        who = '<span class="who">not signed in</span>'

    script_tag = (f'<script nonce="{html.escape(nonce)}">{script}</script>'
                  if script else "")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{html.escape(title)} - honeypot monitoring</title>
<style>{STYLE}</style>
{extra_head}
</head>
<body>
<header class="top">
  <span class="brand">honeypot monitoring</span>
  <nav class="main">{nav}</nav>
  {who}
</header>
<main>
{body}
</main>
<footer>
  read-only interface &middot; no shell, no command execution, no access to the honeypot
</footer>
{script_tag}
</body>
</html>"""


_CSRF_PLACEHOLDER = "{{CSRF}}"


def with_csrf(document: str, token: str) -> str:
    """Substitute the CSRF token. Kept explicit so no page can forget it silently."""
    return document.replace(_CSRF_PLACEHOLDER, html.escape(token, quote=True))


def embed_json(payload: object) -> str:
    """
    Serialise for embedding in a <script> block.

    Escapes the characters that can terminate a script element or a JS string
    literal, so attacker-controlled content inside the payload cannot break out
    of its context regardless of CSP.
    """
    raw = json.dumps(payload, default=str)
    for bad, good in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                      ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        raw = raw.replace(bad, good)
    return raw


def login_page(nonce: str, error: str = "", notice: str = "") -> str:
    error_html = f'<div class="notice crit">{esc(error, limit=300)}</div>' if error else ""
    notice_html = f'<div class="notice warn">{esc(notice, limit=400)}</div>' if notice else ""
    return page("Sign in", f"""
<div class="loginwrap">
  <h1>honeypot monitoring</h1>
  <div class="sub">Authorised administrators only. All access is logged.</div>
  {notice_html}
  {error_html}
  <div class="panel">
    <form method="post" action="/login" autocomplete="off">
      <input type="hidden" name="csrf" value="{esc(_CSRF_PLACEHOLDER, mask=False)}">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" autocapitalize="none"
             autocomplete="username" required autofocus>
      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="current-password" required>
      <label for="totp">Authenticator code</label>
      <input id="totp" name="totp" type="text" inputmode="numeric" pattern="[0-9]*"
             maxlength="6" autocomplete="one-time-code" placeholder="6 digits">
      <button class="primary" type="submit">Sign in</button>
    </form>
  </div>
  <div class="sub" style="margin-top:14px">
    This interface shows captured credentials and session recordings.
    It is reachable only over a private management path and is never exposed
    to the public internet.
  </div>
</div>""", nonce)


def filters_form(action: str, fields: list[dict], csrf_token: str,
                 extra_hidden: str = "") -> str:
    """Build a filter bar. Field values come from the query string: escaped."""
    parts = []
    for f in fields:
        name = esc(f["name"], limit=32)
        label = html.escape(f["label"])
        value = esc(f.get("value", ""), limit=200)
        if f.get("options"):
            opts = "".join(
                f'<option value="{esc(o["value"], limit=200)}"'
                f'{" selected" if str(o["value"]) == str(f.get("value","")) else ""}>'
                f'{html.escape(o["label"])}</option>'
                for o in f["options"])
            parts.append(f'<div class="field"><label for="{name}">{label}</label>'
                         f'<select id="{name}" name="{name}">{opts}</select></div>')
        else:
            cls = "wide" if f.get("wide") else ""
            itype = f.get("type", "text")
            parts.append(f'<div class="field"><label for="{name}">{label}</label>'
                         f'<input id="{name}" name="{name}" type="{itype}" class="{cls}" '
                         f'value="{value}" autocomplete="off"></div>')
    return (f'<form class="filters" method="get" action="{html.escape(action)}">'
            f'{extra_hidden}{"".join(parts)}'
            f'<div class="field"><button class="primary" type="submit">Search</button></div>'
            f'<div class="field"><a href="{html.escape(action)}">'
            f'<button type="button">Reset</button></a></div></form>')


def pager(base_query: str, offset: int, limit: int, total: int,
          path: str) -> str:
    """Pagination that preserves the current filters."""
    if total <= limit:
        return f'<div class="pager">{total} result(s)</div>'
    first = offset + 1
    last = min(offset + limit, total)
    prev_link = next_link = ""
    if offset > 0:
        prev_link = (f'<a href="{html.escape(path)}?{base_query}&offset='
                     f'{max(0, offset - limit)}">&larr; previous</a>')
    if last < total:
        next_link = (f'<a href="{html.escape(path)}?{base_query}&offset='
                     f'{offset + limit}">next &rarr;</a>')
    return (f'<div class="pager"><span>{first}&ndash;{last} of {total}</span>'
            f'{prev_link}{next_link}</div>')

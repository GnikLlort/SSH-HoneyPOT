#!/usr/bin/env python3
"""
Read-only honeypot monitoring dashboard.

WHAT THIS IS
    A web interface over the monitoring store: authentication attempts,
    accepted sessions, source IPs, usernames, timestamps, commands, file
    transfers and health, with filtering, session playback and an audit trail.

WHAT IT CANNOT DO
    * It cannot reach the honeypot. There is no host, address, credential or
      socket for the honeypot anywhere in this program. In the recommended
      deployment it has no network capability at all: it listens on a UNIX
      socket and its systemd unit sets RestrictAddressFamilies=AF_UNIX, so it
      literally cannot open a TCP connection to anything.
    * It cannot run a command. There is no shell, no subprocess, no exec, and
      no endpoint that takes a command. A test asserts this by scanning this
      module's source for exactly those facilities.
    * It cannot modify evidence. The store is opened read-only (SQLite
      `mode=ro` plus `PRAGMA query_only`), so a write is rejected by the driver
      rather than by this program's good behaviour.
    * It cannot read a captured file. Uploaded files are shown by metadata and
      hash only; no code path here opens the quarantine directory.

ACCESS
    Loopback or a private management path (SSM port forwarding or a VPN), with
    strong authentication and MFA. An obscure URL is explicitly not treated as
    a control: the default bind is loopback and the CSRF and session controls
    are the same regardless of the path.

Usage:
    python3 server.py --store /var/lib/honeypot-store --listen 127.0.0.1:8443
    python3 server.py --store /var/lib/honeypot-store --listen unix:/run/honeypot-dashboard/dashboard.sock
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import secrets
import socket
import sqlite3
import sys
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlsplit

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
for _cand in (_HERE.parent / "shared", Path("/opt/honeypot-monitor/share")):
    if (_cand / "terminal_safety.py").is_file():
        sys.path.insert(0, str(_cand))
        break

import render as R  # noqa: E402
from auth import Authenticator, AuthError, PermissionDenied  # noqa: E402
from store import (EVENT_TYPES, OUTCOMES, EventFilter, Queries, Store,  # noqa: E402
                   assess_health, iso)
from terminal_safety import REDACTED, safe_log_value  # noqa: E402

COOKIE_NAME = "hpm_session"
MAX_EXPORT_ROWS = 50_000


class Response:
    def __init__(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8",
                 headers: list[tuple[str, str]] | None = None) -> None:
        self.body = body
        self.status = status
        self.ctype = ctype
        self.headers = headers or []


def html_response(document: str, status: int = 200) -> Response:
    return Response(document.encode("utf-8"), status=status)


def redirect(location: str, headers: list[tuple[str, str]] | None = None) -> Response:
    hdrs = [("Location", location), *(headers or [])]
    return Response(b"", status=303, headers=hdrs)


def badge(text: object, css: str) -> str:
    """A badge element. The text is escaped: badge text is often attacker-derived."""
    return f'<span class="badge {css}">{R.esc(text, mask=False, limit=24)}</span>'


def recording_badge(chunk_count: object, duplicate: object) -> str:
    """
    Recording availability for a session row.

    "shared" is not a defect. Cowrie deletes a recording that is byte-identical
    to an earlier one, so several sessions legitimately point at one file.
    """
    out = badge("recording", "info") if chunk_count else badge("none", "unk")
    if duplicate:
        out += " " + badge("shared", "unk")
    return out


def direction_badge(event: object) -> str:
    name = str(event or "")
    return badge(name, "up" if name == "upload" else "dl")


def transfer_links(sensor: object, session_id: object, sha256: object) -> str:
    """
    Build the "session / metadata" link cell for a transfer row.

    Written as a function rather than inline in an f-string: nesting quotes and
    backslashes inside an f-string expression is a syntax error before Python
    3.12, and it is unreadable even where it works.
    """
    bits = []
    if session_id:
        bits.append(f'<a href="/session/{quote(str(sensor))}/'
                    f'{quote(str(session_id))}">session</a>')
    if sha256:
        bits.append(f'<a href="/transfer/{quote(str(sha256))}">metadata</a>')
    return " &middot; ".join(bits)


class Dashboard:
    """Application object: owns the store, the authenticator and the routing."""

    def __init__(self, store_root: Path, audit_file: Path | None = None,
                 idle_timeout: int = 900, hard_timeout: int = 28800,
                 demo_mode: bool = False) -> None:
        # Evidence is opened READ-ONLY. SQLite enforces it (mode=ro plus
        # PRAGMA query_only), so a bug here cannot rewrite or delete evidence --
        # the write is rejected by the driver, not by this program's restraint.
        self.readonly_store = Store(store_root, readonly=True)
        # A second, writable handle for the dashboard's own tables only:
        # administrator accounts, sessions, the audit trail and the export log.
        # The evidence tables are written by ingest.py, never by this process.
        self.auth_store = Store(store_root)
        self.queries = Queries(self.readonly_store)
        self.queries = Queries(self.readonly_store)
        self.auth = Authenticator(self.auth_store, idle_timeout=idle_timeout,
                                  hard_timeout=hard_timeout, audit_file=audit_file,
                                  demo_mode=demo_mode)
        self.demo_mode = demo_mode
        self.nonce = secrets.token_urlsafe(16)
        self.csrf_secret = secrets.token_bytes(32)
        self.started = time.time()

    # -- csrf --------------------------------------------------------------
    def csrf_for(self, token: str) -> str:
        """
        CSRF token bound to the session token.

        Double-submit with a binding to the session, so a token minted for one
        session is useless in another. Combined with SameSite=Strict, and with
        the fact that every state change is a POST.
        """
        import hmac as _hmac
        import hashlib as _hashlib
        return _hmac.new(self.csrf_secret, token.encode(), _hashlib.sha256).hexdigest()

    def check_csrf(self, token: str, supplied: str) -> bool:
        import hmac as _hmac
        return bool(token) and _hmac.compare_digest(self.csrf_for(token), supplied or "")

    # -- filters -----------------------------------------------------------
    @staticmethod
    def filter_from_query(params: dict[str, list[str]]) -> EventFilter:
        def one(key: str, default: str = "") -> str:
            return (params.get(key, [default])[0] or default).strip()[:200]

        def flag(key: str) -> bool:
            return one(key) in ("1", "on", "true", "yes")

        try:
            limit = int(one("limit") or 50)
        except ValueError:
            limit = 50
        try:
            offset = max(0, int(one("offset") or 0))
        except ValueError:
            offset = 0

        event_type = one("event_type")
        if event_type and event_type not in EVENT_TYPES:
            event_type = ""
        outcome = one("outcome")
        if outcome and outcome not in OUTCOMES:
            outcome = ""
        return EventFilter(
            text=one("q"), src_ip=one("src_ip"), username=one("username"),
            session_id=one("session_id"), event_type=event_type,
            eventid=one("eventid"), outcome=outcome, sensor=one("sensor"),
            since=one("since"), until=one("until"), has_transfer=flag("has_transfer"),
            limit=limit, offset=offset)

    @staticmethod
    def query_string(params: dict[str, list[str]], drop: tuple[str, ...] = ()) -> str:
        items: list[tuple[str, str]] = []
        for key, values in params.items():
            if key in drop:
                continue
            for value in values:
                if value:
                    items.append((key, value))
        return urlencode(items)


# =============================================================================
# HTTP layer
# =============================================================================
class Handler(BaseHTTPRequestHandler):
    server_version = "honeypot-dashboard"
    sys_version = ""
    app: Dashboard
    allow_framing: bool = False
    secure_cookies: bool = True
    # SameSite=Strict is the correct value for a dashboard reached by a
    # top-level navigation over SSM, a VPN or a management network: the browser
    # then never attaches the session cookie to a request originating from
    # another site. `--relax-cookie-policy` downgrades it to None, which exists
    # ONLY so this interface can be embedded in a local preview frame. It is
    # never the right setting for a deployment: SameSite=None means any page the
    # administrator visits can cause their browser to send an authenticated
    # request to the dashboard.
    same_site: str = "Strict"
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        # Never log the query string: it can contain a username or an IP that
        # the operator searched for, and paths can carry a session id.
        sys.stderr.write(f"[dashboard] {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
                         f"{self.command} <redacted>\n")

    def _client_ip(self) -> str:
        addr = self.client_address[0] if isinstance(self.client_address, tuple) else ""
        if addr in ("", "0.0.0.0"):
            # UNIX socket: there is no peer address. Say so rather than
            # inventing one; the audit trail records the admin's identity.
            return "unix-socket"
        return addr

    def _cookie_token(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            jar = SimpleCookie()
            jar.load(raw)
        except Exception:  # noqa: BLE001 - a malformed cookie is not fatal
            return ""
        morsel = jar.get(COOKIE_NAME)
        return morsel.value if morsel else ""

    def _set_cookie(self, token: str, max_age: int) -> tuple[str, str]:
        parts = [f"{COOKIE_NAME}={token}", "Path=/", "HttpOnly",
                 f"SameSite={self.same_site}", f"Max-Age={max_age}"]
        if self.secure_cookies:
            parts.append("Secure")
        return ("Set-Cookie", "; ".join(parts))

    def _security_headers(self) -> list[tuple[str, str]]:
        return [
            # No external resource can load, and no script runs without the
            # per-start nonce. `frame-ancestors 'none'` stops clickjacking of a
            # page that displays captured credentials.
            ("Content-Security-Policy",
             "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-%s'; "
             "img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'self'; "
             "frame-ancestors %s; object-src 'none'"
             % (self.app.nonce, "*" if self.allow_framing else "'none'")),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Cache-Control", "no-store, no-cache, must-revalidate"),
            ("Pragma", "no-cache"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
        ]

    def _send(self, response: Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.ctype)
        self.send_header("Content-Length", str(len(response.body)))
        for key, value in self._security_headers():
            self.send_header(key, value)
        if not self.allow_framing:
            self.send_header("X-Frame-Options", "DENY")
        for key, value in response.headers:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and response.body:
            self.wfile.write(response.body)

    # -- request context ---------------------------------------------------
    def _principal(self):
        """Validate the session and, on failure, return None (never raises)."""
        token = self._cookie_token()
        if not token:
            return None
        try:
            return self.app.auth.validate_session(token)
        except sqlite3.Error as exc:
            sys.stderr.write(f"[dashboard] session lookup failed: {safe_log_value(exc, 200)}\n")
            return None

    def _requiring(self, permission: str = "view", target: str = ""):
        """
        Enforce authentication and authorisation, or return a response.

        Returns (principal, None) on success or (None, response) on failure.
        """
        principal = self._principal()
        if principal is None:
            token = self._cookie_token()
            if token:
                # A cookie that no longer resolves is worth recording: it can
                # mean an expired session, or a stolen one being replayed.
                self.app.auth.audit("unknown", "session.invalid",
                                    detail="cookie did not resolve to a live session",
                                    src_ip=self._client_ip())
            return None, redirect("/login")
        try:
            self.app.auth.require(principal, permission, target=target)
        except PermissionDenied as exc:
            return None, html_response(self._forbidden(principal, str(exc)), status=403)
        return principal, None

    def _forbidden(self, principal, message: str) -> str:
        body = (f'<h1>Not permitted</h1>'
                f'<div class="notice crit">{R.esc(message, limit=300)}</div>'
                f'<p class="sub">This attempt has been recorded in the audit trail.</p>')
        doc = R.page("Not permitted", body, self.app.nonce, principal)
        return R.with_csrf(doc, "")

    # -- GET ---------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        try:
            self._route_get()
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to a browser
            self._fail(exc)

    def _route_get(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        params = parse_qs(parts.query, keep_blank_values=False)

        if path == "/healthz":
            self._send(Response(b"ok\n", ctype="text/plain; charset=utf-8"))
            return

        if path == "/login":
            self._send(self._login_page())
            return

        principal, failure = self._requiring()
        if failure:
            self._send(failure)
            return

        if path in ("/", "/overview"):
            self._send(html_response(self._overview(principal)))
        elif path == "/events":
            self._send(html_response(self._events(principal, params)))
        elif path == "/sessions":
            self._send(html_response(self._sessions(principal, params)))
        elif path.startswith("/session/"):
            self._send(self._session_detail(principal, path))
        elif path.startswith("/api/session/"):
            self._send(self._session_api(principal, path))
        elif path == "/transfers":
            self._send(html_response(self._transfers(principal, params)))
        elif path.startswith("/transfer/"):
            self._send(html_response(self._transfer_detail(principal, path)))
        elif path == "/health":
            self._send(html_response(self._health(principal)))
        elif path == "/audit":
            self._send(self._audit(principal, params))
        elif path == "/users":
            self._send(self._users(principal))
        else:
            self._send(Response(b"not found\n", status=404,
                                ctype="text/plain; charset=utf-8"))

    # -- POST --------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        try:
            self._route_post()
        except Exception as exc:  # noqa: BLE001
            self._fail(exc)

    def _read_form(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 1_000_000:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in parsed.items()}

    def _route_post(self) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        form = self._read_form()

        if path == "/login":
            self._do_login(form)
            return

        principal = self._principal()
        if principal is None:
            self._send(redirect("/login"))
            return

        if not self.app.check_csrf(principal.session_token, form.get("csrf", "")):
            # A failed CSRF check is a security event worth recording: it is
            # what a cross-site attempt against a signed-in administrator
            # looks like.
            self.app.auth.audit(principal.username, "csrf.rejected",
                                target=path, detail="missing or invalid CSRF token",
                                role=principal.role, src_ip=self._client_ip())
            self._send(html_response(
                self._forbidden(principal, "CSRF check failed. Reload the page and retry."),
                status=403))
            return

        if path == "/logout":
            self.app.auth.logout(principal)
            self._send(redirect("/login", [self._set_cookie("", 0)]))
        elif path == "/export":
            self._send(self._export(principal, form))
        else:
            self._send(Response(b"not found\n", status=404,
                                ctype="text/plain; charset=utf-8"))

    # -- login -------------------------------------------------------------
    def _do_login(self, form: dict[str, str]) -> None:
        username = (form.get("username") or "").strip()[:128]
        password = form.get("password") or ""
        totp = (form.get("totp") or "").strip()
        src_ip = self._client_ip()

        try:
            principal, token = self.app.auth.login(username, password, totp, src_ip=src_ip)
        except AuthError as exc:
            self._send(html_response(self._login_page(error=str(exc)), status=401))
            return

        idle = self.app.auth.idle_timeout
        self._send(redirect("/", [self._set_cookie(token, idle)]))

    def _login_page(self, error: str = "", notice: str = "") -> Response:
        if not notice and self.app.demo_mode:
            notice = ("DEMONSTRATION MODE: the authenticator step is not enforced. "
                      "This build is for local evaluation only and must not be "
                      "deployed.")
        doc = R.with_csrf(R.login_page(self.app.nonce, error=error, notice=notice),
                          self.app.csrf_for(""))
        return html_response(doc, status=200 if not error else 401)

    # -- pages -------------------------------------------------------------
    def _overview(self, principal) -> str:
        q = self.app.queries
        stats = q.stats()
        health = assess_health(self.app.readonly_store, q)
        timeline = q.timelines(14)
        top_ips = q.top_values("src_ip", 10)
        top_users = q.top_values("username", 10)
        recent = q.events(EventFilter(limit=15))[0]
        self.app.auth.audit(principal.username, "view.overview", role=principal.role,
                            src_ip=self._client_ip())

        def card(label: str, value, css: str = "") -> str:
            return (f'<div class="card {css}"><div class="n">{R.esc(value, mask=False, limit=20)}</div>'
                    f'<div class="l">{label}</div></div>')

        cards = "".join([
            card("sessions (24h)", stats["sessions_24h"], "accent"),
            card("accepted (24h)", stats["accepted_24h"], "ok" if stats["accepted_24h"] else ""),
            card("failed logins (24h)", stats["logins_failed"], "crit" if stats["logins_failed"] else ""),
            card("distinct sources (24h)", stats["distinct_ips_24h"]),
            card("sessions total", stats["sessions"]),
            card("commands", stats["commands"]),
            card("uploads", stats["uploads"]),
            card("recordings", stats["recordings"]),
        ])

        chart_max = max((int(d.get("connects") or 0) for d in timeline), default=1) or 1
        chart = []
        for day in timeline:
            failed = int(day.get("failed") or 0)
            accepted = int(day.get("accepted") or 0)
            connects = int(day.get("connects") or 0)
            scale = 100.0 / chart_max
            chart.append(
                f'<div class="col" title="{R.esc(day.get("day"), mask=False, limit=10)}: '
                f'{connects} connections, {failed} failed, {accepted} accepted">'
                f'<div class="f" style="height:{failed * scale:.1f}%"></div>'
                f'<div class="a" style="height:{accepted * scale:.1f}%"></div></div>')
        chart_html = (f'<div class="chart">{"".join(chart)}</div>'
                      f'<div class="sub">Connections per day over {len(timeline)} day(s). '
                      f'<span style="color:var(--crit)">red</span> = failed logins, '
                      f'<span style="color:var(--ok)">green</span> = accepted.</div>'
                      ) if timeline else '<div class="empty">No events yet.</div>'

        def listing(rows: list[dict], column: str, link_to: str) -> str:
            """A small top-N table. Values are attacker-controlled: escaped."""
            if not rows:
                return '<div class="empty">Nothing yet.</div>'
            body = "".join(
                f'<tr><td class="mono"><a href="{link_to}?{column}='
                f'{quote(str(r["value"]))}">{R.esc(r["value"], limit=80)}</a></td>'
                f'<td class="nowrap">{int(r["n"])}</td></tr>' for r in rows)
            return (f'<table><thead><tr><th>{column}</th><th>events</th></tr></thead>'
                    f'<tbody>{body}</tbody></table>')

        recent_rows = "".join(
            f'<tr><td class="nowrap muted">{R.fmt_ago(e["ts_epoch"])}</td>'
            f'<td class="nowrap">{R.esc(e["src_ip"], limit=64)}</td>'
            f'<td class="mono">{R.esc(e["eventid"], limit=48)}</td>'
            f'<td>{R.esc(e["username"], limit=48)}</td>'
            f'<td><a class="trunc" href="/session/{quote(str(e["sensor"]))}/'
            f'{quote(str(e["session_id"] or ""))}">{R.esc(e["session_id"], limit=24)}</a></td>'
            f'<td class="trunc muted">{R.esc(e["command"] or e["message"], limit=120)}</td></tr>'
            for e in recent)

        body = f"""
<h1>Overview</h1>
<div class="sub">Read-only. Generated {R.esc(iso(), mask=False, limit=32)}.</div>
{self._health_banner(health)}
<div class="cards">{cards}</div>
<h2>Attempts per day</h2>
<div class="panel">{chart_html}</div>
<h2>Top sources (7 days)</h2>
<div class="panel">{listing(top_ips, "src_ip", "/events")}</div>
<h2>Top usernames (7 days)</h2>
<div class="panel">{listing(top_users, "username", "/events")}</div>
<h2>Recent events</h2>
<table><thead><tr><th>when</th><th>source</th><th>event</th><th>username</th>
<th>session</th><th>detail</th></tr></thead><tbody>{recent_rows}</tbody></table>
"""
        return R.with_csrf(R.page("Overview", body, self.app.nonce, principal, "overview"),
                           self.app.csrf_for(principal.session_token))

    def _health_banner(self, health: dict) -> str:
        cls = {"healthy": "ok", "degraded": "warn", "critical": "crit"}[health["level"]]
        label = {"healthy": "All checks passing", "degraded": "Degraded",
                 "critical": "Attention required"}[health["level"]]
        problems = "".join(
            f'<div class="sig"><span class="dot {p["level"]}"></span><div>'
            f'<b>{R.esc(p["code"], limit=40)}</b> &mdash; {R.esc(p["detail"], limit=400)}'
            f'<div class="sub" style="margin:4px 0 0">Fix: {R.esc(p["fix"], limit=400)}</div>'
            f'</div></div>' for p in health["problems"])
        ok = "".join(f'<div class="sig"><span class="dot ok"></span>'
                     f'<div>{R.esc(text, limit=200)}</div></div>' for text in health["ok"])
        return (f'<div class="notice {cls}"><b>{label}</b>'
                f'{(" &mdash; " + str(len(health["problems"])) + " issue(s)") if health["problems"] else ""}'
                f' &nbsp;<a href="/health">details</a></div>')

    def _filter_fields(self, params: dict, principal, include_outcome: bool = True) -> list[dict]:
        def val(key: str) -> str:
            return (params.get(key, [""])[0] or "")[:200]

        q = self.app.queries
        fields = [
            {"name": "since", "label": "from (date)", "type": "date", "value": val("since")},
            {"name": "until", "label": "to (date)", "type": "date", "value": val("until")},
            {"name": "src_ip", "label": "source IP", "value": val("src_ip"), "wide": True},
            {"name": "username", "label": "username", "value": val("username")},
            {"name": "session_id", "label": "session id", "value": val("session_id")},
        ]
        if include_outcome:
            fields.append({"name": "outcome", "label": "outcome", "value": val("outcome"),
                           "options": [{"value": "", "label": "any"}]
                           + [{"value": o, "label": o} for o in OUTCOMES]})
        fields.append({"name": "q", "label": "text (command / file / url)",
                       "value": val("q"), "wide": True})
        sensors = q.sensors()
        if len(sensors) > 1:
            fields.append({"name": "sensor", "label": "sensor", "value": val("sensor"),
                           "options": [{"value": "", "label": "any"}]
                           + [{"value": s, "label": s} for s in sensors]})
        return fields

    def _events(self, principal, params) -> str:
        f = self.app.filter_from_query(params)
        rows, total = self.app.queries.events(f)
        self.app.auth.audit(
            principal.username, "search.events",
            detail=(f"ip={f.src_ip or '*'} user={f.username or '*'} type={f.event_type or '*'} "
                    f"outcome={f.outcome or '*'} text={f.text or '*'} since={f.since or '*'} "
                    f"until={f.until or '*'} rows={len(rows)} of {total}"),
            role=principal.role, src_ip=self._client_ip())

        unmasked = principal.can("unmask")
        type_options = [{"value": "", "label": "any"}] + [
            {"value": k, "label": k} for k in EVENT_TYPES]
        fields = self._filter_fields(params, principal)
        fields.insert(4, {"name": "event_type", "label": "event type",
                          "value": (params.get("event_type", [""])[0] or ""),
                          "options": type_options})

        body_rows = "".join(
            f'<tr>'
            f'<td class="nowrap muted">{R.fmt_ts(e["timestamp"])}</td>'
            f'<td class="nowrap">{R.esc(e["src_ip"], limit=64)}'
            f'{(":" + str(e["src_port"])) if e["src_port"] else ""}</td>'
            f'<td class="mono nowrap">{R.esc(e["eventid"], limit=48)}</td>'
            f'<td>{R.esc(e["username"], limit=48)}</td>'
            f'<td>{R.secret_cell(e["password"], unmasked) if e["password"] else ""}</td>'
            f'<td class="trunc">{R.esc(e["command"] or e["filename"] or e["url"] or e["message"], limit=200)}</td>'
            f'<td><a href="/session/{quote(str(e["sensor"]))}/{quote(str(e["session_id"] or ""))}">'
            f'{R.esc(e["session_id"], limit=24)}</a></td>'
            f'</tr>' for e in rows) or (
            '<tr><td colspan="7"><div class="empty">No events match these filters.</div>'
            '</td></tr>')

        qs = self.app.query_string(params, drop=("offset",))
        body = f"""
<h1>Events</h1>
<div class="sub">{total} event(s) match. Every search is recorded in the audit trail.</div>
{R.filters_form("/events", fields, self.app.csrf_for(principal.session_token))}
{self._export_bar(principal, "events", qs)}
<table><thead><tr><th>timestamp (UTC)</th><th>source</th><th>event</th><th>username</th>
<th>password</th><th>command / file</th><th>session</th></tr></thead>
<tbody>{body_rows}</tbody></table>
{R.pager(qs, f.offset, f.clamped_limit(), total, "/events")}
"""
        return R.with_csrf(R.page("Events", body, self.app.nonce, principal, "events"),
                           self.app.csrf_for(principal.session_token))

    def _export_bar(self, principal, kind: str, qs: str) -> str:
        if not principal.can("export"):
            return ('<div class="sub">Your role cannot export evidence. '
                    'Exports are audited and limited to analyst and admin roles.</div>')
        return f"""<form method="post" action="/export" class="toolbar">
  <input type="hidden" name="csrf" value="{R.esc(self.app.csrf_for(principal.session_token), mask=False)}">
  <input type="hidden" name="kind" value="{R.esc(kind, mask=False)}">
  <input type="hidden" name="qs" value="{R.esc(qs, mask=False, limit=4000)}">
  <button type="submit" name="fmt" value="csv">Export CSV</button>
  <button type="submit" name="fmt" value="json">Export JSON</button>
  <span class="sub" style="margin:0">Exports are audited. Captured secrets are
  excluded unless you hold the unmask permission.</span>
</form>"""

    def _sessions(self, principal, params) -> str:
        f = self.app.filter_from_query(params)
        only_recorded = (params.get("recorded", [""])[0] or "") in ("1", "on")
        only_accepted = (params.get("accepted", [""])[0] or "") in ("1", "on")
        rows, total = self.app.queries.sessions(f, only_recorded=only_recorded,
                                                only_accepted=only_accepted)
        self.app.auth.audit(
            principal.username, "search.sessions",
            detail=(f"ip={f.src_ip or '*'} user={f.username or '*'} "
                    f"outcome={f.outcome or '*'} text={f.text or '*'} rows={len(rows)} of {total}"),
            role=principal.role, src_ip=self._client_ip())

        body_rows = "".join(
            f'<tr>'
            f'<td class="nowrap muted">{R.fmt_ts(s["started"])}</td>'
            f'<td class="nowrap">{R.esc(s["src_ip"], limit=64)}</td>'
            f'<td>{R.esc(s["username"], limit=48)}</td>'
            f'<td>{R.outcome_badge(s["login_result"])}</td>'
            f'<td class="nowrap">{R.fmt_duration(s["duration_ms"])}</td>'
            f'<td class="nowrap">{int(s["command_count"])}</td>'
            f'<td class="nowrap">{int(s["transfer_count"])}</td>'
            f'<td>{recording_badge(s["chunk_count"], s["recording_duplicate"])}</td>'
            f'<td><a href="/session/{quote(str(s["sensor"]))}/{quote(str(s["session_id"]))}">'
            f'{R.esc(s["session_id"], limit=24)}</a></td>'
            f'</tr>' for s in rows) or (
            '<tr><td colspan="9"><div class="empty">No sessions match these filters.</div></td></tr>')

        fields = self._filter_fields(params, principal)
        fields.insert(5, {"name": "recorded", "label": "recorded only",
                          "value": params.get("recorded", [""])[0],
                          "options": [{"value": "", "label": "any"},
                                      {"value": "1", "label": "has recording"}]})
        fields.insert(6, {"name": "accepted", "label": "accepted only",
                          "value": params.get("accepted", [""])[0],
                          "options": [{"value": "", "label": "any"},
                                      {"value": "1", "label": "accepted"}]})
        qs = self.app.query_string(params, drop=("offset",))
        body = f"""
<h1>Sessions</h1>
<div class="sub">{total} session(s) match. A session appears here even if no recording
exists: an authentication attempt that never reached a shell is still evidence.</div>
{R.filters_form("/sessions", fields, self.app.csrf_for(principal.session_token))}
{self._export_bar(principal, "sessions", qs)}
<table><thead><tr><th>started (UTC)</th><th>source</th><th>username</th><th>outcome</th>
<th>duration</th><th>cmds</th><th>files</th><th>recording</th><th>session</th></tr></thead>
<tbody>{body_rows}</tbody></table>
{R.pager(qs, f.offset, f.clamped_limit(), total, "/sessions")}
"""
        return R.with_csrf(R.page("Sessions", body, self.app.nonce, principal, "sessions"),
                           self.app.csrf_for(principal.session_token))

    # -- session detail ----------------------------------------------------
    def _split_path(self, path: str, prefix: str) -> tuple[str, str]:
        rest = path[len(prefix):].strip("/")
        bits = rest.split("/")
        if len(bits) < 2:
            return "", ""
        from urllib.parse import unquote
        return unquote(bits[0]), unquote(bits[1])

    def _session_bundle(self, sensor: str, session_id: str) -> dict | None:
        """
        Assemble everything the viewer needs for one session.

        The recording is read from the store's own recording directory: the
        SHA-256 is validated as hex and confined to that directory, so a
        poisoned database value cannot become a path traversal.
        """
        q = self.app.queries
        session = q.session(sensor, session_id)
        if not session:
            return None
        chunks: list[dict] = []
        recorded = False
        note = ""
        sha = session.get("recording_sha256") or ""
        if sha:
            path = q.recording_path(sha)
            if path is not None:
                from ttylog import derive_transcript, parse_ttylog_bytes
                data = path.read_bytes()
                parsed = parse_ttylog_bytes(data, source=sha[:12])
                recorded = True
                chunks = [{"offset_ms": c.offset_ms, "direction": c.direction,
                           "text": c.text} for c in parsed]
            elif session.get("recording_duplicate"):
                recorded = True
                note = ("This session's recording was byte-identical to an earlier one, so "
                        "Cowrie stored it once under that earlier session's hash. Find the "
                        "session with the same recording hash to view it.")
            else:
                note = "The recording for this session is missing from the monitoring store."
        else:
            note = "No recording was captured for this session."
        return {"session": session, "chunks": chunks, "recorded": recorded,
                "note": note, "sha": sha}

    def _session_api(self, principal, path: str) -> Response:
        sensor, session_id = self._split_path(path, "/api/session/")
        bundle = self._session_bundle(sensor, session_id)
        if bundle is None:
            return Response(b'{"error":"not found"}', status=404,
                            ctype="application/json; charset=utf-8")
        # The API returns sanitised text, never raw bytes: the same treatment
        # the HTML path gets. A recording is untrusted input on both paths.
        from terminal_safety import safe_text
        mask = not principal.can("unmask")
        payload = {
            "chunks": [{"offset_ms": c["offset_ms"], "direction": c["direction"],
                        "text": safe_text(c["text"], mask=mask)}
                       for c in bundle["chunks"]],
            "recorded": bundle["recorded"],
            "note": bundle["note"],
        }
        self.app.auth.audit(principal.username, "view.recording",
                            target=f"{sensor}/{session_id}",
                            detail=f"chunks={len(payload['chunks'])} masked={mask}",
                            role=principal.role, src_ip=self._client_ip())
        return Response(json.dumps(payload, default=str).encode("utf-8"),
                        ctype="application/json; charset=utf-8")

    def _session_detail(self, principal, path: str) -> Response:
        sensor, session_id = self._split_path(path, "/session/")
        bundle = self._session_bundle(sensor, session_id)
        if bundle is None:
            return html_response(R.with_csrf(
                R.page("Not found",
                       '<h1>Not found</h1><div class="notice warn">No such session in the '
                       'monitoring store.</div>', self.app.nonce, principal), ""), status=404)

        s = bundle["session"]
        q = self.app.queries
        events = q.session_events(sensor, session_id)
        transfers = q.session_transfers(sensor, session_id)
        unmask = principal.can("unmask")
        mask = not unmask

        self.app.auth.audit(principal.username, "view.session",
                            target=f"{sensor}/{session_id}",
                            detail=f"events={len(events)} transfers={len(transfers)} "
                                   f"masked={mask}",
                            role=principal.role, src_ip=self._client_ip())

        # Rows are escaped here; the playback panel is rendered client-side from
        # a sanitised JSON payload embedded below.
        event_rows = "".join(
            f'<tr><td class="nowrap muted">{R.fmt_ts(e["timestamp"])}</td>'
            f'<td class="mono nowrap">{R.esc(e["eventid"], limit=48)}</td>'
            f'<td>{R.esc(e["username"], limit=48)}</td>'
            f'<td>{R.secret_cell(e["password"], unmask) if e["password"] else ""}</td>'
            f'<td class="trunc">{R.esc(e["command"] or e["filename"] or e["url"] or e["message"], limit=220)}</td>'
            f'<td class="hash">{R.esc(e["shasum"], limit=64)}</td></tr>'
            for e in events)

        transfer_rows = "".join(
            f'<tr><td class="nowrap muted">{R.fmt_ts(t["timestamp"])}</td>'
            f'<td>{direction_badge(t["event"])}</td>'
            f'<td class="trunc">{R.esc(t["filename"] or t["url"], limit=200)}</td>'
            f'<td class="nowrap">{R.fmt_bytes(t["size"])}</td>'
            f'<td class="hash">{R.esc(t["sha256"], limit=64)}</td>'
            f'<td class="nowrap">'
            f'{transfer_links(t["sensor"], t["session_id"], t["sha256"])}'
            f'</td></tr>' for t in transfers)

        from terminal_safety import safe_text
        from ttylog import Chunk, derive_transcript
        parsed_chunks = [Chunk(offset_ms=c["offset_ms"], direction=c["direction"],
                               text=c["text"]) for c in bundle["chunks"]]
        chunk_payload = [{"offset_ms": c.offset_ms, "direction": c.direction,
                          "text": safe_text(c.text, mask=mask)} for c in parsed_chunks]
        transcript = derive_transcript(parsed_chunks, mask=mask)

        start_epoch = s.get("started_epoch") or 0
        transfer_payload = [
            {"timestamp": R.fmt_ts(t["timestamp"]), "event": t["event"],
             "filename": safe_text(t["filename"] or t["url"] or "", mask=mask, limit=300),
             "sha256": t["sha256"] or "", "size": t["size"],
             "quarantined": bool(t["quarantined"]),
             "offset_ms": (int((t["ts_epoch"] - start_epoch) * 1000)
                           if start_epoch and t.get("ts_epoch") else -1)}
            for t in transfers]

        payload = {"chunks": chunk_payload, "transcript": transcript,
                   "transfers": transfer_payload, "recorded": bundle["recorded"]}

        unmask_link = ""
        if bundle["note"]:
            unmask_link = f'<div class="notice warn">{R.esc(bundle["note"], limit=400)}</div>'
        if unmask:
            unmask_link += ('<div class="notice crit">Secrets are UNMASKED for this view. '
                            'This has been recorded in the audit trail.</div>')
        else:
            unmask_link += ('<div class="sub">Captured secrets are masked. Analysts can '
                            'reveal them, and doing so is audited.</div>')

        body = f"""
<h1>Session {R.esc(session_id, limit=64)}</h1>
<div class="sub">sensor {R.esc(sensor, limit=64)}</div>
{unmask_link}
<div class="panel">
  <div class="kv">
    <div class="k">source</div><div class="v">{R.esc(s["src_ip"], limit=64)}
      {(":" + str(s["src_port"])) if s["src_port"] else ""}</div>
    <div class="k">started (UTC)</div><div class="v">{R.fmt_ts(s["started"])}</div>
    <div class="k">ended (UTC)</div><div class="v">{R.fmt_ts(s["ended"])}</div>
    <div class="k">duration</div><div class="v">{R.fmt_duration(s["duration_ms"])}</div>
    <div class="k">username</div><div class="v">{R.esc(s["username"], limit=64)}</div>
    <div class="k">login result</div><div class="v">{R.outcome_badge(s["login_result"])}</div>
    <div class="k">client</div><div class="v">{R.esc(s["client_version"], limit=120)}</div>
    <div class="k">commands</div><div class="v">{int(s["command_count"])}</div>
    <div class="k">transfers</div><div class="v">{int(s["transfer_count"])}</div>
    <div class="k">recording</div><div class="v">
      {R.esc(bundle["sha"], mask=False, limit=64) if bundle["sha"] else "(none)"}
      {"" if not s["recording_duplicate"] else " (shared with an earlier session)"}
    </div>
  </div>
</div>

<div class="toolbar">
  <button id="play">Play</button>
  <button id="step">Step</button>
  <button id="back">&minus;5s</button>
  <button id="fwd">+5s</button>
  <span class="clock" id="clock">0.0s / 0.0s</span>
  <input type="range" id="seek" min="0" max="1000" value="0">
  <label class="sub">speed
    <select id="speed">
      <option>0.25</option><option>0.5</option><option selected>1</option>
      <option>2</option><option>4</option><option>8</option>
    </select>
  </label>
</div>

<div class="tabs">
  <button data-tab="term" class="active">Terminal</button>
  <button data-tab="transcript">Command transcript</button>
  <button data-tab="transfers">File transfers ({len(transfers)})</button>
  <button data-tab="events">Cowrie events ({len(events)})</button>
</div>
<div class="tabpane shown" id="tab-term"><div class="term" id="term"></div></div>
<div class="tabpane" id="tab-transcript"></div>
<div class="tabpane" id="tab-transfers"></div>
<div class="tabpane" id="tab-events">
  <div class="sub">The authoritative record from <code>cowrie.json</code>. Compare it with
  the transcript above: a disagreement is itself worth investigating.</div>
  <table><thead><tr><th>timestamp</th><th>event</th><th>username</th><th>password</th>
  <th>command / file</th><th>sha256</th></tr></thead><tbody>{event_rows}</tbody></table>
</div>

<div class="sub" style="margin-top:10px">
  Command search in the recording: <input id="cmdfilter" type="search"
  placeholder="filter transcript" autocomplete="off">
</div>
<p class="sub">Recorded bytes are displayed, never executed. Escape sequences are stripped
and captured secrets are masked before they reach this page.</p>
<input type="hidden" id="session-data" value="">
"""
        script = (f'window.__SESSION_DATA__ = {R.embed_json(payload)};\n' + R.PLAYBACK_JS)
        doc = R.page(f"Session {session_id}", body, self.app.nonce, principal, "sessions",
                     script=script)
        return html_response(R.with_csrf(doc, self.app.csrf_for(principal.session_token)))

    # -- transfers ---------------------------------------------------------
    def _transfers(self, principal, params) -> str:
        f = self.app.filter_from_query(params)
        kind = (params.get("kind", [""])[0] or "").strip()
        rows, total = self.app.queries.transfers(f, kind=kind)
        self.app.auth.audit(principal.username, "search.transfers",
                            detail=f"kind={kind or '*'} text={f.text or '*'} rows={len(rows)}",
                            role=principal.role, src_ip=self._client_ip())

        body_rows = "".join(
            f'<tr><td class="nowrap muted">{R.fmt_ts(t["timestamp"])}</td>'
            f'<td>{direction_badge(t["event"])}</td>'
            f'<td class="nowrap">{R.esc(t["src_ip"], limit=64)}</td>'
            f'<td class="trunc">{R.esc(t["filename"] or t["url"], limit=200)}</td>'
            f'<td class="nowrap">{R.fmt_bytes(t["size"])}</td>'
            f'<td class="hash">{R.esc(t["sha256"], limit=64)}</td>'
            f'<td class="nowrap">'
            f'{transfer_links(t["sensor"], t["session_id"], t["sha256"])}'
            f'</td></tr>' for t in rows) or (
            '<tr><td colspan="7"><div class="empty">No file transfers match.</div></td></tr>')

        fields = self._filter_fields(params, principal, include_outcome=False)
        fields.insert(2, {"name": "kind", "label": "direction", "value": kind,
                          "options": [{"value": "", "label": "any"},
                                      {"value": "upload", "label": "upload"},
                                      {"value": "download", "label": "download"}]})
        qs = self.app.query_string(params, drop=("offset",))
        body = f"""
<h1>File transfers</h1>
<div class="sub">{total} transfer event(s). Captured files are quarantined off-host and are
described by metadata and hash only &mdash; this interface never opens, previews or serves
one.</div>
{R.filters_form("/transfers", fields, self.app.csrf_for(principal.session_token))}
{self._export_bar(principal, "transfers", qs)}
<table><thead><tr><th>time (UTC)</th><th>direction</th><th>source</th><th>file</th>
<th>size</th><th>sha256</th><th>links</th></tr></thead><tbody>{body_rows}</tbody></table>
{R.pager(qs, f.offset, f.clamped_limit(), total, "/transfers")}
"""
        return R.with_csrf(R.page("Transfers", body, self.app.nonce, principal, "transfers"),
                           self.app.csrf_for(principal.session_token))

    def _transfer_detail(self, principal, path: str) -> str:
        from urllib.parse import unquote
        sha = unquote(path[len("/transfer/"):]).strip("/")
        meta = self.app.queries.quarantine_meta(sha)
        self.app.auth.audit(principal.username, "view.transfer_metadata", target=sha[:64],
                            role=principal.role, src_ip=self._client_ip())

        with self.app.readonly_store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM transfer WHERE sha256=? ORDER BY ts_epoch DESC", (sha,)).fetchall()
        transfers = [dict(r) for r in rows]

        rows_html = "".join(
            f'<tr><td class="nowrap muted">{R.fmt_ts(t["timestamp"])}</td>'
            f'<td>{R.esc(t["event"], limit=16)}</td>'
            f'<td class="trunc">{R.esc(t["filename"] or t["url"], limit=200)}</td>'
            f'<td><a href="/session/{quote(str(t["sensor"]))}/{quote(str(t["session_id"] or ""))}">'
            f'{R.esc(t["session_id"], limit=24)}</a></td></tr>' for t in transfers)

        body = f"""
<h1>Captured file metadata</h1>
<div class="notice warn">The file itself is quarantined and is not available here. This page
shows metadata only. Analysing a captured file requires a separate disposable environment
with no route to production &mdash; see docs/06.</div>
<div class="panel"><div class="kv">
  <div class="k">sha256</div><div class="v hash">{R.esc(meta["sha256"], limit=64)}</div>
  <div class="k">quarantined copy</div><div class="v">
     {"present on the monitoring host" if meta["present"] else "not present in this store"}</div>
  <div class="k">size</div><div class="v">{R.fmt_bytes(meta.get("bytes")) or "-"}</div>
  <div class="k">recorded transfers</div><div class="v">{len(transfers)}</div>
</div></div>
<h2>Transfers with this hash</h2>
<table><thead><tr><th>time (UTC)</th><th>direction</th><th>file</th><th>session</th></tr></thead>
<tbody>{rows_html or '<tr><td colspan="4"><div class="empty">No transfer rows reference this hash.</div></td></tr>'}</tbody></table>
"""
        return R.with_csrf(R.page("Captured file", body, self.app.nonce, principal, "transfers"),
                           self.app.csrf_for(principal.session_token))

    # -- health ------------------------------------------------------------
    def _health(self, principal) -> str:
        q = self.app.queries
        health = assess_health(self.app.readonly_store, q)
        self.app.auth.audit(principal.username, "view.health",
                            detail=f"level={health['level']}", role=principal.role,
                            src_ip=self._client_ip())

        signals = "".join(
            f'<div class="sig"><span class="dot {p["level"]}"></span><div>'
            f'<b>{R.esc(p["code"], limit=40)}</b> &mdash; {R.esc(p["detail"], limit=400)}'
            f'<div class="sub" style="margin:4px 0 0">Fix: {R.esc(p["fix"], limit=500)}</div>'
            f'</div></div>' for p in health["problems"])
        ok_signals = "".join(
            f'<div class="sig"><span class="dot ok"></span><div>{R.esc(t, limit=200)}</div></div>'
            for t in health["ok"])

        ingest_rows = "".join(
            f'<tr><td class="nowrap muted">{R.fmt_ts(r["finished"] or r["started"])}</td>'
            f'<td><span class="badge {"ok" if r["status"] == "ok" else "crit"}">'
            f'{R.esc(r["status"], limit=16)}</span></td>'
            f'<td class="nowrap">{int(r["events_new"] or 0)}</td>'
            f'<td class="nowrap muted">{int(r["events_dup"] or 0)}</td>'
            f'<td class="nowrap">{int(r["recordings_new"] or 0)}</td>'
            f'<td class="nowrap">{int(r["quarantine_new"] or 0)}</td>'
            f'<td class="trunc muted">{R.esc(r["error"], limit=200) if r["error"] else ""}</td></tr>'
            for r in q.ingest_history(20))

        sensor_rows = "".join(
            f'<tr><td>{R.esc(h["sensor"], limit=64)}</td>'
            f'<td class="nowrap muted">{R.fmt_ts(h["timestamp"])}</td>'
            f'<td class="nowrap">{R.fmt_ago(h["ts_epoch"])}</td>'
            f'<td><span class="badge {"ok" if h["banner_ok"] else "crit"}">'
            f'{"ok" if h["banner_ok"] else "no banner"}</span></td>'
            f'<td class="nowrap">{(str(h["log_age_s"]) + "s") if h["log_age_s"] is not None else "-"}</td>'
            f'<td class="nowrap">{(str(h["disk_pct"]) + "%") if h["disk_pct"] is not None else "-"}</td>'
            f'<td class="nowrap">{(str(h["quarantine_mb"]) + " MB") if h["quarantine_mb"] is not None else "-"}</td>'
            f'<td>{badge("unexpected", "crit") if h["outbound"] else badge("none", "ok")}</td>'
            f'</tr>' for h in q.health_latest())

        backup_file = self.app.readonly_store.root / "backup-status.json"
        if backup_file.is_file():
            try:
                backup = json.loads(backup_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                backup = {"status": "unreadable"}
            backup_html = (f'<div class="kv">'
                           f'<div class="k">status</div><div class="v">'
                           f'{R.esc(backup.get("status"), limit=40)}</div>'
                           f'<div class="k">last success</div><div class="v">'
                           f'{R.esc(backup.get("last_success"), limit=40)}</div>'
                           f'<div class="k">last run</div><div class="v">'
                           f'{R.esc(backup.get("last_run"), limit=40)}</div>'
                           f'<div class="k">location</div><div class="v">'
                           f'{R.esc(backup.get("destination"), limit=200)}</div>'
                           f'<div class="k">detail</div><div class="v">'
                           f'{R.esc(backup.get("detail"), limit=300)}</div></div>')
        else:
            backup_html = ('<div class="notice warn">No backup has reported status. '
                           'Install <code>ops/store_backup.sh</code> and its timer on the '
                           'monitoring host &mdash; the store is the only copy of this '
                           'evidence, because the honeypot prunes locally after shipping.'
                           '</div>')

        thresholds = health["thresholds"]
        body = f"""
<h1>Health</h1>
<div class="sub">Checked {R.esc(health["checked_at"], mask=False, limit=32)}.</div>
<div class="notice {"ok" if health["level"] == "healthy" else ("warn" if health["level"] == "degraded" else "crit")}">
  <b>{R.esc(health["level"].upper(), mask=False, limit=20)}</b>
</div>
<h2>Signals</h2>
<div class="panel">{signals or '<div class="sig"><span class="dot ok"></span><div>No problems detected.</div></div>'}{ok_signals}</div>

<h2>Last ingested batches</h2>
<table><thead><tr><th>finished (UTC)</th><th>status</th><th>events</th><th>duplicates</th>
<th>recordings</th><th>captures</th><th>error</th></tr></thead>
<tbody>{ingest_rows or '<tr><td colspan="7"><div class="empty">No ingest has run.</div></td></tr>'}</tbody></table>

<h2>Honeypot sensors</h2>
<table><thead><tr><th>sensor</th><th>reported (UTC)</th><th>age</th><th>banner</th>
<th>log age</th><th>disk</th><th>quarantine</th><th>outbound</th></tr></thead>
<tbody>{sensor_rows or '<tr><td colspan="8"><div class="empty">No health reports ingested. The honeypot ships its health-check log in each bundle.</div></td></tr>'}</tbody></table>

<h2>Backup status</h2>
<div class="panel">{backup_html}</div>

<h2>Thresholds in force</h2>
<div class="panel"><div class="kv">
{''.join(f'<div class="k">{R.esc(k, limit=48)}</div><div class="v">{R.esc(v, limit=40)}</div>' for k, v in thresholds.items())}
</div></div>

<h2>Recovery</h2>
<div class="panel sub">
If ingestion has stopped, the honeypot is still collecting &mdash; evidence accumulates
on it until its local retention prunes it. The order of operations matters:
<ol>
<li>Check the honeypot's <code>cowrie-logship.timer</code> and its outbound rule.</li>
<li>Confirm bundles are arriving at the export path the ingest timer reads.</li>
<li>Re-run ingestion by hand and read the error.</li>
<li>If the honeypot host is lost, rebuild from the evidence store &mdash; see
<code>docs/11-rollback-and-rebuild.md</code>.</li>
<li>If the store is lost, restore from backup before doing anything else: it is the
only copy of anything the honeypot has already pruned.</li>
</ol>
</div>
"""
        return R.with_csrf(R.page("Health", body, self.app.nonce, principal, "health"),
                           self.app.csrf_for(principal.session_token))

    # -- audit -------------------------------------------------------------
    def _audit(self, principal, params) -> Response:
        try:
            self.app.auth.require(principal, "audit.read")
        except PermissionDenied as exc:
            return html_response(self._forbidden(principal, str(exc)), status=403)
        limit = 200
        try:
            limit = max(1, min(2000, int((params.get("limit", ["200"])[0] or "200"))))
        except ValueError:
            pass
        actor = (params.get("actor", [""])[0] or "")[:64]
        action = (params.get("action", [""])[0] or "")[:64]
        entries = self.app.auth.audit_entries(limit=limit, actor=actor, action=action)

        rows = "".join(
            f'<tr><td class="nowrap muted">{R.fmt_ts(e["timestamp"])}</td>'
            f'<td>{R.esc(e["actor"], limit=64)}</td>'
            f'<td class="mono">{R.esc(e["action"], limit=48)}</td>'
            f'<td>{R.esc(e["role"], limit=24)}</td>'
            f'<td class="trunc">{R.esc(e["target"], limit=200)}</td>'
            f'<td class="trunc muted">{R.esc(e["detail"], limit=300)}</td>'
            f'<td class="nowrap muted">{R.esc(e["src_ip"], limit=64)}</td></tr>'
            for e in entries)

        fields = [
            {"name": "actor", "label": "administrator", "value": actor},
            {"name": "action", "label": "action contains", "value": action},
            {"name": "limit", "label": "limit", "value": str(limit)},
        ]
        # Reading the audit trail is itself an audited action.
        self.app.auth.audit(principal.username, "view.audit",
                            detail=f"actor={actor or '*'} action={action or '*'} "
                                   f"rows={len(entries)}",
                            role=principal.role, src_ip=self._client_ip())
        body = f"""
<h1>Audit trail</h1>
<div class="sub">Append-only: the database rejects UPDATE and DELETE on this table, and a
copy is written to a file on separate storage. Administrator logins, searches, exports and
configuration changes are recorded here.</div>
{R.filters_form("/audit", fields, self.app.csrf_for(principal.session_token))}
<table><thead><tr><th>when (UTC)</th><th>administrator</th><th>action</th><th>role</th>
<th>target</th><th>detail</th><th>source</th></tr></thead>
<tbody>{rows or '<tr><td colspan="7"><div class="empty">No audit entries.</div></td></tr>'}</tbody></table>
"""
        return html_response(R.with_csrf(
            R.page("Audit", body, self.app.nonce, principal, "audit"),
            self.app.csrf_for(principal.session_token)))

    # -- users -------------------------------------------------------------
    def _users(self, principal) -> Response:
        try:
            self.app.auth.require(principal, "users.read")
        except PermissionDenied as exc:
            return html_response(self._forbidden(principal, str(exc)), status=403)
        users = self.app.auth.list_users()
        rows = "".join(
            f'<tr><td>{R.esc(u["username"], limit=64)}</td>'
            f'<td><span class="badge">{R.esc(u["role"], limit=16)}</span></td>'
            f'<td>{"yes" if u["totp_enabled"] else badge("no", "crit")}</td>'
            f'<td>{"disabled" if u["disabled"] else "active"}</td>'
            f'<td class="nowrap muted">{R.fmt_ts(u["last_login"])}</td>'
            f'<td class="nowrap muted">{R.esc(u["created"], limit=32)}</td></tr>'
            for u in users)
        body = f"""
<h1>Administrators</h1>
<div class="sub">Accounts are created and changed with
<code>python3 dashboard/manage.py</code> on the monitoring host. There is no self-service
path and no password reset by email &mdash; an account change is an audited administrative
action, and it is shown in the audit trail.</div>
<table><thead><tr><th>username</th><th>role</th><th>MFA</th><th>state</th>
<th>last login</th><th>created</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Roles</h2>
<div class="panel sub">
<b>viewer</b> &mdash; read-only: overview, events, sessions, playback, transfers, health.
Captured secrets stay masked and export is refused.<br>
<b>analyst</b> &mdash; a viewer that can additionally unmask captured secrets, export
evidence, and read the audit trail. Both unmasking and exporting are audited.<br>
<b>admin</b> &mdash; an analyst that can additionally read the account list and the
configuration in force. It has no additional ability to affect the honeypot, because no
role has any.
</div>
"""
        return html_response(R.with_csrf(
            R.page("Administrators", body, self.app.nonce, principal, "users"),
            self.app.csrf_for(principal.session_token)))

    # -- export ------------------------------------------------------------
    def _export(self, principal, form: dict[str, str]) -> Response:
        try:
            self.app.auth.require(principal, "export", target=form.get("kind", ""))
        except PermissionDenied as exc:
            return html_response(self._forbidden(principal, str(exc)), status=403)

        kind = (form.get("kind") or "events")[:32]
        fmt = (form.get("fmt") or "csv")[:8]
        if fmt not in ("csv", "json"):
            fmt = "csv"
        raw_qs = (form.get("qs") or "")[:4000]
        params = parse_qs(raw_qs, keep_blank_values=False)
        f = self.app.filter_from_query(params)
        f.limit = MAX_EXPORT_ROWS
        f.offset = 0

        unmask = principal.can("unmask")
        if kind == "sessions":
            rows, total = self.app.queries.sessions(f)
            columns = ["sensor", "session_id", "src_ip", "src_port", "started", "ended",
                       "duration_ms", "username", "login_result", "client_version",
                       "command_count", "transfer_count", "recording_sha256"]
        elif kind == "transfers":
            rows, total = self.app.queries.transfers(f)
            columns = ["sensor", "session_id", "timestamp", "event", "filename", "sha256",
                       "size", "url", "quarantined"]
        else:
            rows, total = self.app.queries.events(f)
            columns = ["sensor", "session_id", "eventid", "timestamp", "src_ip", "src_port",
                       "username", "outcome", "command", "filename", "url", "shasum", "size"]
            if unmask:
                columns.insert(7, "password")

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"honeypot-{kind}-{stamp}.{fmt}"

        if fmt == "json":
            payload = {
                "exported_at": iso(),
                "exported_by": principal.username,
                "kind": kind,
                "filter": {k: v for k, v in params.items()},
                "row_count": len(rows),
                "secrets_included": bool(unmask and "password" in columns),
                "rows": [{k: r.get(k) for k in columns} for r in rows],
            }
            body = json.dumps(payload, indent=2, default=str).encode("utf-8")
            ctype = "application/json; charset=utf-8"
        else:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(columns)
            for r in rows:
                writer.writerow([r.get(k) for k in columns])
            body = buf.getvalue().encode("utf-8")
            ctype = "text/csv; charset=utf-8"

        # The export is recorded BEFORE it is served, so an interrupted
        # download is still accounted for.
        self.app.auth.audit(
            principal.username, "export", target=kind,
            detail=(f"format={fmt} rows={len(rows)} of {total} "
                    f"secrets_included={bool(unmask and 'password' in columns)} "
                    f"filter={raw_qs[:300]}"),
            role=principal.role, src_ip=self._client_ip())
        with self.app.auth_store.connect() as conn:
            conn.execute(
                """INSERT INTO export_log(timestamp, ts_epoch, actor, kind, query,
                       row_count, bytes, dest) VALUES(?,?,?,?,?,?,?,?)""",
                (iso(), time.time(), principal.username, kind, raw_qs, len(rows),
                 len(body), filename))

        return Response(body, ctype=ctype, headers=[
            ("Content-Disposition", f'attachment; filename="{filename}"'),
        ])

    # -- errors ------------------------------------------------------------
    def _fail(self, exc: Exception) -> None:
        """
        Never leak a traceback or an internal path to a browser.

        The detail goes to the service log, sanitised; the browser gets a bare
        message and a request id so an operator can correlate the two.
        """
        request_id = secrets.token_hex(6)
        sys.stderr.write(
            f"[dashboard] request {request_id} failed: {type(exc).__name__}: "
            f"{safe_log_value(exc, 400)}\n")
        try:
            principal = self._principal()
            doc = R.page("Error",
                         f'<h1>Something went wrong</h1>'
                         f'<div class="notice crit">The request could not be completed.</div>'
                         f'<div class="sub">Reference <code>{request_id}</code> appears in the '
                         f'service log with the detail.</div>',
                         self.app.nonce, principal)
            self._send(html_response(R.with_csrf(doc, ""), status=500))
        except Exception:  # noqa: BLE001
            self._send(Response(b"internal error\n", status=500,
                                ctype="text/plain; charset=utf-8"))


class UnixHTTPServer(ThreadingHTTPServer):
    """
    HTTP server on a UNIX domain socket.

    This is the recommended deployment: the socket lives on the host filesystem
    with mode 0660, a dumb TCP-to-UNIX forwarder (socat, in the systemd unit) is
    the only thing that listens on TCP, and the dashboard process itself never
    opens a network socket. Combined with RestrictAddressFamilies=AF_UNIX in
    the unit, the process is structurally incapable of connecting to the
    honeypot.
    """
    address_family = socket.AF_UNIX
    daemon_threads = True

    def server_bind(self) -> None:
        self.socket.bind(self.server_address)
        try:
            os.chmod(self.server_address, 0o660)
        except OSError as exc:
            print(f"warning: could not chmod socket: {safe_log_value(exc, 200)}",
                  file=sys.stderr)

    def get_request(self):
        conn, _ = self.socket.accept()
        return conn, ("unix-socket", 0)


class TCPHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def parse_listen(spec: str) -> tuple[str, object]:
    """Parse --listen into ('unix'|'tcp', address)."""
    if spec.startswith("unix:"):
        return "unix", spec[len("unix:"):]
    if spec.startswith("["):
        host, _, port = spec.rpartition("]:")
        return "tcp", (host.lstrip("["), int(port))
    host, _, port = spec.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"cannot parse --listen {spec!r}; use host:port or unix:/path")
    return "tcp", (host, int(port))


def bootstrap_store(store_root: Path) -> None:
    Store(store_root)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", default="/var/lib/honeypot-store",
                    help="monitoring store root (required)")
    ap.add_argument("--listen", default="127.0.0.1:8443",
                    help="host:port, or unix:/path (recommended)")
    ap.add_argument("--audit-file", default="",
                    help="append the audit trail to this file as well as the database")
    ap.add_argument("--idle-timeout", type=int, default=900,
                    help="seconds of inactivity before a session expires (default 900)")
    ap.add_argument("--hard-timeout", type=int, default=28800,
                    help="absolute session lifetime in seconds (default 8h)")
    ap.add_argument("--demo-mode", action="store_true",
                    help="local evaluation only: do not enforce the authenticator step")
    ap.add_argument("--allow-framing", action="store_true",
                    help="permit embedding in an iframe; for local UI previews only")
    ap.add_argument("--relax-cookie-policy", action="store_true",
                    help="send SameSite=None instead of Strict; local UI previews "
                         "only, never for a deployment")
    ap.add_argument("--no-secure-cookies", action="store_true",
                    help="omit the Secure cookie flag; needed only for plain-HTTP "
                         "non-loopback access, which you should not be doing")
    ap.add_argument("--i-know-this-exposes-monitoring", action="store_true",
                    help="acknowledge a non-loopback bind")
    args = ap.parse_args()

    store_root = Path(args.store)
    if not (store_root / "store.sqlite3").is_file():
        print(f"error: no store at {store_root}/store.sqlite3\n"
              f"       create it by running ingest.py, or pass --store for an "
              f"existing store.", file=sys.stderr)
        return 2

    kind, address = parse_listen(args.listen)
    if kind == "tcp":
        host, port = address  # type: ignore[misc]
        if host not in ("127.0.0.1", "::1", "localhost") and not args.i_know_this_exposes_monitoring:
            print(
                f"refusing to bind to {host}.\n"
                "This interface shows captured credentials and session recordings, and it\n"
                "has no protection other than the network boundary. Reach it over a private\n"
                "management path instead:\n"
                "  aws ssm start-session --target <instance> \\\n"
                "      --document-name AWS-StartPortForwardingSession \\\n"
                "      --parameters '{\"portNumber\":[\"8443\"],\"localPortNumber\":[\"8443\"]}'\n"
                "A non-loopback bind is legitimate only on a VPN interface you control, and\n"
                "even then SSL or the tunnel must provide confidentiality. An obscure URL is\n"
                "not a control. Pass --i-know-this-exposes-monitoring to proceed.",
                file=sys.stderr)
            return 2

    if args.demo_mode and kind == "tcp" and address[0] not in ("127.0.0.1", "::1", "localhost"):
        if not args.i_know_this_exposes_monitoring:
            print("refusing: --demo-mode never runs on a non-loopback interface without "
                  "--i-know-this-exposes-monitoring.", file=sys.stderr)
            return 2

    app = Dashboard(store_root,
                    audit_file=Path(args.audit_file) if args.audit_file else None,
                    idle_timeout=args.idle_timeout, hard_timeout=args.hard_timeout,
                    demo_mode=args.demo_mode)

    Handler.app = app
    Handler.allow_framing = args.allow_framing
    Handler.secure_cookies = not args.no_secure_cookies
    if args.relax_cookie_policy:
        Handler.same_site = "None"
        print("warning: SameSite=None. Cross-site requests will carry the session "
              "cookie.\n         This is for looking at the interface locally. Do not "
              "deploy it.", file=sys.stderr)

    if kind == "unix":
        sock_path = Path(str(address))
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        if sock_path.exists():
            sock_path.unlink()
        server = UnixHTTPServer(str(address), Handler)
        print(f"honeypot dashboard on unix:{address} (store: {store_root})")
    else:
        server = TCPHTTPServer(address, Handler)  # type: ignore[arg-type]
        print(f"honeypot dashboard on http://{address[0]}:{address[1]} (store: {store_root})")

    print("read-only: no shell, no command execution, no access to the honeypot.")
    if args.demo_mode:
        print("WARNING: --demo-mode is active. The authenticator step is NOT enforced.\n"
              "         Local evaluation only. Never expose this.")
    if not Handler.secure_cookies:
        print("WARNING: --no-secure-cookies is set. Use only over loopback or TLS.",
              file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if kind == "unix":
            try:
                Path(str(address)).unlink()
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

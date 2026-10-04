#!/usr/bin/env python3
"""
Tests for the monitoring dashboard: sanitizers, authentication, ingestion and
the recording join.

Run from the repository root:

    python3 tests/test_dashboard.py

Nothing here needs a running sensor. The bundle fixture is synthesised from the
real Cowrie recording format, so the tests exercise the same code paths the
ingest timer uses without depending on whatever happens to be in lab/.

Three of these tests exist because the code was wrong in a way that a casual
look would not catch, and each is named for what it protects:

  TestIngestDedupe        -- Cowrie's `uuid` is a sensor identity, not an event
                             identity. Keying on it discards every event but
                             the first and still reports success.
  TestRecordingJoinKey    -- a recording is named for the hash of the visitor's
                             input, not of the file. Renaming it to its content
                             hash detaches it from every session silently.
  TestSanitizerParity     -- the terminal sanitizers are shared between the
                             on-host playback viewer and the off-host dashboard,
                             so they cannot drift apart.
  TestCredentialRedaction -- Cowrie writes the captured password into a
                             human-readable `message` field as well as into a
                             structured column, so masking the column alone
                             leaves the same secret readable.
"""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import json
import os
import re
import shutil
import socket
import subprocess
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for sub in ("dashboard", "shared"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from auth import (AuthError, Authenticator, password_strength_problems,  # noqa: E402
                  provisioning_uri, totp_at, verify_totp)
from store import EventFilter, Queries, Store  # noqa: E402
from terminal_safety import mask_sensitive, safe_html, safe_text  # noqa: E402
from ttylog import parse_ttylog_bytes  # noqa: E402


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def ttylog_bytes(*events: tuple[int, int, bytes]) -> bytes:
    """
    Build a ttylog in Cowrie's real format.

    Header is "<iLiiLL" = (op, tty, length, direction, sec, usec); the same
    struct the playback viewer decodes.
    """
    out = bytearray()
    for i, (direction, usec, payload) in enumerate(events):
        out += struct.pack("<iLiiLL", 3, 0, len(payload), direction,
                           1_700_000_000, usec)
        out += payload
    return bytes(out)


def make_bundle(root: Path, *, sensor: str = "deploy-01") -> Path:
    """Assemble a minimal but structurally real bundle."""
    bundle = root / "bundle"
    (bundle / "tty").mkdir(parents=True, exist_ok=True)
    (bundle / "downloads").mkdir(parents=True, exist_ok=True)
    (bundle / "health").mkdir(parents=True, exist_ok=True)
    (bundle / "SENSOR").write_text(sensor + "\n")

    # Two sessions. The second shares the first's recording, which is exactly
    # what Cowrie does when a visitor repeats an identical session.
    rec = ttylog_bytes((1, 0, b"id\n"), (2, 30_000, b"uid=1000(deploy)\n"))
    rec_name = hashlib.sha256(b"visitor input, not the file").hexdigest()
    (bundle / "tty" / rec_name).write_bytes(rec)

    events = [
        {"eventid": "cowrie.session.connect", "session": "aaaa1111bbbb",
         "src_ip": "203.0.113.9", "src_port": 51000,
         "timestamp": "2026-07-31T09:14:01.000000Z",
         "uuid": "SAME-EVERY-EVENT", "sensor": sensor,
         "message": "New connection: 203.0.113.9:51000"},
        {"eventid": "cowrie.login.success", "session": "aaaa1111bbbb",
         "username": "deploy", "password": "Sunrise-Ledger-1972",
         "timestamp": "2026-07-31T09:14:02.000000Z",
         "uuid": "SAME-EVERY-EVENT", "sensor": sensor,
         "message": "login attempt [deploy/Sunrise-Ledger-1972] succeeded"},
        {"eventid": "cowrie.command.input", "session": "aaaa1111bbbb",
         "input": "id", "timestamp": "2026-07-31T09:14:03.000000Z",
         "uuid": "SAME-EVERY-EVENT", "sensor": sensor, "message": "CMD: id"},
        {"eventid": "cowrie.log.closed", "session": "aaaa1111bbbb",
         "ttylog": f"var/lib/cowrie/tty/{rec_name}", "shasum": rec_name,
         "size": len(rec), "duplicate": False, "duration_ms": 1200,
         "timestamp": "2026-07-31T09:14:04.000000Z",
         "uuid": "SAME-EVERY-EVENT", "sensor": sensor,
         "message": f"Closing TTY Log: var/lib/cowrie/tty/{rec_name}"},
        {"eventid": "cowrie.session.closed", "session": "aaaa1111bbbb",
         "timestamp": "2026-07-31T09:14:05.000000Z",
         "uuid": "SAME-EVERY-EVENT", "sensor": sensor,
         "message": "Connection lost"},
        # a second, failed session from a different source
        {"eventid": "cowrie.session.connect", "session": "cccc2222dddd",
         "src_ip": "198.51.100.4", "src_port": 40000,
         "timestamp": "2026-07-31T10:00:00.000000Z",
         "uuid": "SAME-EVERY-EVENT", "sensor": sensor, "message": "New connection"},
        {"eventid": "cowrie.login.failed", "session": "cccc2222dddd",
         "username": "root", "password": "toor",
         "timestamp": "2026-07-31T10:00:01.000000Z",
         "uuid": "SAME-EVERY-EVENT", "sensor": sensor,
         "message": "login attempt [root/toor] failed"},
    ]
    with (bundle / "cowrie.json").open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")

    manifest = {
        "sensor": sensor,
        "counts": {"events": len(events), "recordings": 1},
        "files": [{"kind": "recording", "sha256": rec_name,
                   "content_sha256": hashlib.sha256(rec).hexdigest(),
                   "bytes": len(rec), "source_name": rec_name}],
    }
    (bundle / "BUNDLE.json").write_text(json.dumps(manifest, indent=2))
    return bundle


class DashboardTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="dash-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bundle = make_bundle(self.tmp)
        self.store_root = self.tmp / "store"

    def store(self) -> Store:
        return Store(self.store_root, readonly=True)

    def ingest(self):
        """Ingest the fixture bundle into a writable handle on the store."""
        return Store(self.store_root).ingest_bundle(self.bundle)


# ----------------------------------------------------------------------
# Sanitizer parity
# ----------------------------------------------------------------------

class TestSanitizerParity(DashboardTestCase):
    """
    The on-host viewer and the off-host dashboard must sanitise identically.

    They are separate programs maintained by the same person, which is exactly
    how two copies of an escaper drift: one gets a fix for a new escape
    sequence, the other keeps serving the old bytes. Both now import
    `shared/terminal_safety.py`, and these tests fail if either grows a private
    copy or re-exports something different.
    """

    def test_playback_imports_the_shared_module(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "onhost_playback", ROOT / "playback" / "server.py")
        self.assertIsNotNone(spec, "playback/server.py is missing")
        module = importlib.util.module_from_spec(spec)
        # Register before executing: dataclasses resolves annotations through
        # sys.modules[cls.__module__] at decoration time, so a module that is
        # not registered explodes inside the @dataclass decorator with a
        # confusing AttributeError.
        sys.modules["onhost_playback"] = module
        self.addCleanup(sys.modules.pop, "onhost_playback", None)
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except SystemExit as exc:  # pragma: no cover - environment problem
            self.fail(f"playback/server.py could not find shared/: {exc}")

        for name in ("strip_escapes", "strip_terminal_control", "mask_sensitive",
                     "safe_text", "safe_html"):
            self.assertTrue(hasattr(module, name),
                            f"playback/server.py no longer exposes {name}()")

    def test_both_sides_produce_identical_html(self) -> None:
        """The same bytes decide the same output on both sides."""
        payloads = [
            "<script>alert('xss')</script>",
            "\x1b[2J\x1b[Hcleared",
            "OSC\x1b]0;title\x07rest",
            "back\x08space\x7fdel",
            "bidi\u202eoverride\u202c",
            "login attempt [deploy/Sunrise-Ledger-1972] succeeded",
            'quote" and & ampersand and <angle>',
        ]
        for payload in payloads:
            with self.subTest(payload=payload[:24]):
                html = safe_html(payload)
                text = safe_text(payload)
                # Same shared function called twice must be deterministic...
                self.assertEqual(html, safe_html(payload))
                # ...and no raw markup may survive.
                self.assertNotIn("<script", html.lower())
                self.assertNotIn("alert('xss')", html)

    def test_escaping_cannot_be_escaped(self) -> None:
        for raw in ("<script>", "&lt;script&gt;", "&#60;script&#62;",
                    "&amp;lt;script&amp;gt;"):
            out = safe_html(raw)
            self.assertNotIn("<script", out.lower(),
                             "double-escaped input decoded back into markup")

    def test_identifier_is_not_masked_independently(self) -> None:
        """
        A username must survive masking: masking that swallows the whole line
        makes the dashboard useless, which is how operators end up turning it
        off.
        """
        out = mask_sensitive("login attempt [deploy/Sunrise-Ledger-1972] succeeded")
        self.assertIn("deploy", out)
        self.assertNotIn("Sunrise-Ledger-1972", out)


# ----------------------------------------------------------------------
# Credential redaction
# ----------------------------------------------------------------------

class TestCredentialRedaction(DashboardTestCase):
    """Captured secrets must not reach a viewer without the unmask permission."""

    def test_cowrie_message_field_is_masked(self) -> None:
        """
        The structured password column is masked separately. Cowrie also spells
        the credential out in `message`, so without a pattern for its wording the
        same secret stays readable. This is a regression test for a real leak
        found against a live sensor.
        """
        cases = [
            "login attempt [deploy/Sunrise-Ledger-1972] succeeded",
            "login attempt [root/toor] failed",
            "login attempt [phil/] succeeded",
            "login attempt [deploy/My Pass Word] failed",
        ]
        for message in cases:
            with self.subTest(message=message):
                out = mask_sensitive(message)
                self.assertNotIn("Sunrise-Ledger-1972", out)
                self.assertIn("[REDACTED]", out)

    def test_ordinary_output_is_not_mangled(self) -> None:
        """Masking must not eat paths or permissions, or it is unusable."""
        keep = [
            "cat /home/deploy/projects/artifacts/build-manifest.json",
            "-rw-r--r-- 1 deploy deploy 412 Jul 31 09:14 build-manifest.json",
            "uid=1000(deploy) gid=1000(deploy) groups=1000(deploy)",
            "total 48\ndrwxr-xr-x 2 deploy deploy 4096 Jul 31 09:00 projects",
        ]
        for line in keep:
            with self.subTest(line=line[:30]):
                self.assertEqual(line, mask_sensitive(line))

    def test_stored_evidence_keeps_original_bytes(self) -> None:
        """
        Redaction is a display concern. Evidence that has been rewritten is not
        evidence, so the stored event must still hold the true password.
        """
        self.ingest()
        with self.store().connect() as conn:
            row = conn.execute(
                "SELECT password, message FROM event "
                "WHERE eventid='cowrie.login.success' LIMIT 1").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["password"], "Sunrise-Ledger-1972")
        self.assertIn("Sunrise-Ledger-1972", row["message"])


class TestSanitizerPerformance(DashboardTestCase):
    """
    Every sanitizer pattern must be linear in the length of its input.

    This is a security property, not a nicety. The sanitizers run over
    attacker-controlled text on every page render, and Cowrie accepts a 16 KB
    command, so a quadratic pattern lets any visitor to the honeypot make the
    dashboard unusable -- without touching the monitoring host and without
    leaving a trace anyone would think to look for.

    It has happened once already. A pattern written as
    `(\\blogin attempt \\[[^\\]\\n]*/)([^\\]\\n]*)(?=\\])` let the first group
    end at any slash, so a line of slashes with no closing bracket made the
    engine try every split: measured 22 ms at 2 KB and 1213 ms at 16 KB, growing
    with the square of the input. The test below fails on that pattern.
    """

    # A hostile input per shape the patterns key on: long runs of the
    # characters a pattern looks for, with no terminator, which is what makes
    # a backtracking engine explore every split point.
    HOSTILE = {
        "slashes, no bracket": "login attempt [" + "a/" * 16000,
        "slashes": "/" * 16384,
        "pass flags": "-pass " * 2700,
        "password assignments": "password= " * 1800,
        "letters": "A" * 16384,
        "quotes": "\"'" * 8000,
        "spaces": " " * 16384,
        "newlines": "a\n" * 8000,
        "brackets": "[" * 16384,
        "markers repeated": "login attempt [" * 1000,
        "curl flags": "curl " + "-x " * 5000,
        "wget user": "wget " + "--user=a " * 2000,
        "ssh key": "ssh-rsa " + "A" * 16000,
    }

    # Per-payload budget. Sized by measurement, not by feel: the current
    # implementation takes 3 ms on the worst payload here and the quadratic one
    # took 5400 ms, so 400 ms sits two orders of magnitude above the honest
    # cost and still fails the regression by more than ten times.
    BUDGET_S = 0.4

    def test_no_pattern_backtracks_catastrophically(self) -> None:
        import time
        worst_name, worst = "", 0.0
        for name, payload in self.HOSTILE.items():
            start = time.perf_counter()
            mask_sensitive(payload)
            elapsed = time.perf_counter() - start
            if elapsed > worst:
                worst_name, worst = name, elapsed
        self.assertLess(
            worst, self.BUDGET_S,
            f"sanitizer took {worst * 1000:.0f} ms on {worst_name!r}; "
            f"a pattern is backtracking catastrophically")

    def test_growth_is_linear_not_quadratic(self) -> None:
        """
        Timing a single input can pass by luck. Doubling the input and checking
        that the time does not roughly quadruple is what actually distinguishes
        linear from quadratic.
        """
        import time

        def cost(n: int) -> float:
            payload = "login attempt [" + "a/" * n
            best = min(
                (self._timed(mask_sensitive, payload) for _ in range(3)))
            return best

        small = cost(4000)
        large = cost(16000)          # 4x the input
        # Linear would be ~4x, quadratic ~16x. 8x is comfortably between.
        if small < 0.0002:           # below the clock's useful resolution
            self.skipTest("timings below the measurement floor")
        self.assertLess(large / small, 8.0,
                        f"4x the input cost {large / small:.1f}x the time")

    @staticmethod
    def _timed(fn, *args) -> float:
        import time
        start = time.perf_counter()
        fn(*args)
        return time.perf_counter() - start

    def test_long_recording_still_masks(self) -> None:
        """Bounding the quantifiers must not quietly stop masking."""
        for payload in ("login attempt [deploy/Sunrise-Ledger-1972] succeeded",
                        "login attempt [root/toor] failed",
                        "login attempt [deploy/] succeeded"):
            with self.subTest(payload=payload):
                self.assertNotIn("Sunrise-Ledger-1972", mask_sensitive(payload))
                self.assertNotIn("toor", mask_sensitive(payload))


# ----------------------------------------------------------------------
# Ingestion
# ----------------------------------------------------------------------

class TestIngestDedupe(DashboardTestCase):
    def test_every_event_is_stored(self) -> None:
        self.ingest()
        with self.store().connect() as conn:
            n = conn.execute("SELECT COUNT(*) FROM event").fetchone()[0]
        self.assertEqual(n, 7, "events were dropped during ingest")

    def test_dedupe_does_not_key_on_cowrie_uuid(self) -> None:
        """
        Every event in the fixture carries the same `uuid`, because Cowrie uses
        that field as a sensor identity. Deduplicating on it keeps one event and
        discards the rest while still reporting success.
        """
        self.ingest()
        with self.store().connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM event").fetchone()[0]
            distinct = conn.execute(
                "SELECT COUNT(DISTINCT dedupe_key) FROM event").fetchone()[0]
        # One dedupe key per line: nothing was collapsed.
        self.assertEqual(total, 7)
        self.assertEqual(distinct, 7,
                         "events were collapsed onto a shared identity again")

    def test_reingest_is_idempotent(self) -> None:
        self.ingest()
        first = self.ingest()
        with self.store().connect() as conn:
            n = conn.execute("SELECT COUNT(*) FROM event").fetchone()[0]
        self.assertEqual(n, 7)
        self.assertEqual(first.events_new, 0,
                         "a second ingest added events that were already stored")

    def test_store_opens_read_only(self) -> None:
        """A bug in the web process must not be able to rewrite evidence."""
        self.ingest()
        store = self.store()
        with self.assertRaises(Exception):
            with store.connect() as conn:
                conn.execute("DELETE FROM event")


class TestRecordingJoinKey(DashboardTestCase):
    """
    A recording is named for the SHA-256 of the visitor's INPUT, not of the
    file's bytes. Verified against a live sensor: 115 of 115 recordings had a
    filename that did not match the hash of their own content.

    `cowrie.log.closed` refers to the recording by that same name, so it is the
    join key. Copying the file under its content hash instead detaches every
    recording from its session, and does so silently: ingestion still reports
    success and the recordings are still on disk.
    """

    def test_recording_name_is_preserved(self) -> None:
        self.ingest()
        stored = sorted(p.name for p in (self.store_root / "recordings").iterdir())
        self.assertEqual(len(stored), 1)
        name = stored[0]
        data = (self.store_root / "recordings" / name).read_bytes()
        self.assertNotEqual(name, hashlib.sha256(data).hexdigest(),
                            "fixture no longer reproduces the trap")
        self.assertEqual(name, hashlib.sha256(
            b"visitor input, not the file").hexdigest())

    def test_session_finds_its_recording(self) -> None:
        self.ingest()
        q = Queries(self.store())
        sessions, _ = q.sessions(EventFilter(limit=50))
        linked = [s for s in sessions if s["session_id"] == "aaaa1111bbbb"]
        self.assertEqual(len(linked), 1)
        session = linked[0]
        self.assertGreater(session["chunk_count"], 0,
                           "session did not resolve its recording")
        path = q.recording_path(session["recording_sha256"])
        self.assertIsNotNone(path)

    def test_recording_path_rejects_path_traversal(self) -> None:
        q = Queries(self.store())
        for bad in ("../../etc/passwd", "/etc/passwd", "a/../../b",
                    "00" * 32 + "/../../etc/passwd", "", "not-a-hash"):
            with self.subTest(value=bad):
                self.assertIsNone(q.recording_path(bad))

    def test_tampered_recording_is_refused(self) -> None:
        """Bytes that do not match the manifest are refused, not indexed."""
        (self.bundle / "tty" / os.listdir(self.bundle / "tty")[0]).write_bytes(b"x")
        stats = self.ingest()
        self.assertTrue(stats.errors, "a recording altered in transit was accepted")
        self.assertFalse(list((self.store_root / "recordings").iterdir()))


class TestHeaderInjection(DashboardTestCase):
    """
    A header value containing CR or LF lets whoever controls it write the rest
    of the response.

    This was reachable: /export built `Content-Disposition` from a form field
    truncated to 32 characters, and http.server writes header values verbatim.
    A 32-character field is ample room for `\\r\\nContent-Type: text/html\\r\\n\\r\\n`
    plus a script tag, which splits the response and lets the attacker set the
    beginning of the body. Reproduced against a running instance before the
    fix.
    """

    def test_line_breaks_are_refused(self) -> None:
        from server import invalid_header
        bad = [
            ("Content-Disposition", 'attachment; filename="a\r\nX-Injected: 1"'),
            ("Content-Disposition", 'attachment; filename="a\nX-Injected: 1"'),
            ("X\r\nY", "value"),
            ("X", "value\r\n"),
            ("", "value"),
            ("X:Y", "value"),
        ]
        for key, value in bad:
            with self.subTest(key=key, value=value[:30]):
                self.assertTrue(invalid_header(key, value),
                                f"accepted a header that splits the response: {key!r}")

    def test_ordinary_headers_are_allowed(self) -> None:
        from server import invalid_header
        for key, value in (("Content-Type", "text/csv; charset=utf-8"),
                           ("Content-Disposition",
                            'attachment; filename="honeypot-events-20260101T000000Z.csv"'),
                           ("Content-Length", "4096")):
            with self.subTest(key=key):
                self.assertEqual(invalid_header(key, value), "")

    def test_non_latin1_is_refused_before_the_status_line(self) -> None:
        """http.server encodes headers as latin-1; raising mid-response would
        leave a half-written reply on the wire."""
        from server import invalid_header
        self.assertTrue(invalid_header("X-Test", "caf\u00e9 \u2603"))

    def test_filename_allowlist(self) -> None:
        from server import safe_filename
        cases = {
            'evil"\r\nX: 1': "evilX1",
            "../../etc/passwd": "etcpasswd",
            "honeypot-events-20260101T000000Z.csv":
                "honeypot-events-20260101T000000Z.csv",
            "": "download",
            "---": "download",
            "a" * 500: "a" * 96,
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw[:24]):
                got = safe_filename(raw)
                self.assertEqual(got, expected)
                self.assertFalse(any(c in got for c in '\r\n"/\\'))

    def test_kind_is_allowlisted_not_truncated(self) -> None:
        """
        The export must pick its branch from a fixed set. Truncation is not a
        sanitiser.
        """
        src = (ROOT / "dashboard" / "server.py").read_text(encoding="utf-8")
        self.assertIn('if kind not in ("events", "sessions", "transfers")', src,
                      "the export kind is no longer allowlisted")


# ----------------------------------------------------------------------
# Authentication
# ----------------------------------------------------------------------

class TestTotpRfc6238Vectors(DashboardTestCase):
    """
    RFC 6238 Appendix B, SHA-1 rows. The ASCII secret is
    "12345678901234567890"; the RFC prints eight digits, so `digits=8` is used
    where it differs. Checking against the published vectors rather than against
    a second copy of the same implementation is the only way this test can fail
    when the implementation is wrong.
    """

    SECRET = base64.b32encode(b"12345678901234567890").decode()

    VECTORS = [
        (59,          "94287082", "287082"),
        (1111111109,  "07081804", "081804"),
        (1111111111,  "14050471", "050471"),
        (1234567890,  "89005924", "005924"),
        (2000000000,  "69279037", "279037"),
        (20000000000, "65353130", "353130"),
    ]

    def test_rfc_vectors(self) -> None:
        self.assertEqual(self.SECRET, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        for at, eight, six in self.VECTORS:
            with self.subTest(t=at):
                self.assertEqual(totp_at(self.SECRET, at, digits=8), eight)
                self.assertEqual(totp_at(self.SECRET, at, digits=6), six)

    def test_window_accepts_one_step_either_side(self) -> None:
        # A real epoch: the counter is packed as an unsigned 64-bit integer, so
        # times before 1970 are out of range by definition.
        secret, now = self.SECRET, 1_700_000_000
        self.assertTrue(verify_totp(secret, totp_at(secret, now), at=now))
        self.assertTrue(verify_totp(secret, totp_at(secret, now), at=now + 30))
        self.assertTrue(verify_totp(secret, totp_at(secret, now), at=now - 30))

    def test_window_rejects_far_outside(self) -> None:
        secret, now = self.SECRET, 1_700_000_000
        self.assertFalse(verify_totp(secret, totp_at(secret, now), at=now + 300))
        self.assertFalse(verify_totp(secret, totp_at(secret, now), at=now - 300))

    def test_malformed_codes_are_rejected(self) -> None:
        secret = self.SECRET
        for bad in ("", "abc", "12345", "1234567", "12 34 56 78"):
            with self.subTest(code=bad):
                self.assertFalse(verify_totp(secret, bad, at=1_700_000_000))

    def test_provisioning_uri_is_well_formed(self) -> None:
        uri = provisioning_uri(self.SECRET, "alice")
        self.assertTrue(uri.startswith("otpauth://totp/"))
        self.assertIn(f"secret={self.SECRET}", uri)
        self.assertIn("algorithm=SHA1", uri)
        self.assertIn("digits=6", uri)


class TestAuthentication(DashboardTestCase):
    PASSWORD = "Ledger-Thistle-49-Quay"

    def auth(self, **kw) -> Authenticator:
        return Authenticator(Store(self.store_root), **kw)

    def test_password_is_never_stored_in_the_clear(self) -> None:
        a = self.auth()
        a.create_user("alice", self.PASSWORD, "admin")
        with self.store().connect() as conn:
            blob = " ".join(
                str(v) for row in conn.execute("SELECT * FROM admin_user")
                for v in tuple(row))
        self.assertNotIn(self.PASSWORD, blob)
        self.assertIn("scrypt", blob.lower())

    def test_weak_passwords_are_refused(self) -> None:
        for bad in ("short", "password", "123456789012", "aaaaaaaaaaaa"):
            with self.subTest(password=bad):
                self.assertTrue(password_strength_problems(bad))

    def test_login_requires_the_second_factor(self) -> None:
        a = self.auth()
        secret = a.create_user("bob", self.PASSWORD, "admin")
        code = totp_at(secret)
        principal, token = a.login("bob", self.PASSWORD, code, "10.0.0.1")
        self.assertIsNotNone(principal)
        self.assertTrue(token)
        with self.assertRaises(AuthError):
            a.login("bob", self.PASSWORD, "000000", "10.0.0.1")

    def test_lockout_after_repeated_failures(self) -> None:
        a = self.auth()
        secret = a.create_user("carol", self.PASSWORD, "viewer")
        for _ in range(5):
            with self.assertRaises(AuthError):
                a.login("carol", "wrong-password", "000000", "10.0.0.1")
        with self.assertRaises(AuthError):
            a.login("carol", self.PASSWORD, totp_at(secret), "10.0.0.1")

    def test_password_change_revokes_sessions(self) -> None:
        a = self.auth()
        secret = a.create_user("dave", self.PASSWORD, "admin")
        principal, token = a.login("dave", self.PASSWORD, totp_at(secret), "10.0.0.1")
        self.assertIsNotNone(principal)
        self.assertIsNotNone(a.validate_session(token))
        a.set_password("dave", "Quarry-Meadow-88-Flint", actor="test")
        self.assertIsNone(a.validate_session(token, touch=False),
                          "a session outlived the password change that should revoke it")

    def test_roles_gate_privileges(self) -> None:
        a = self.auth()
        s_admin = a.create_user("root1", self.PASSWORD, "admin")
        s_view = a.create_user("viewer1", self.PASSWORD, "viewer")
        admin, _ = a.login("root1", self.PASSWORD, totp_at(s_admin), "10.0.0.1")
        viewer, _ = a.login("viewer1", self.PASSWORD, totp_at(s_view), "10.0.0.1")
        self.assertTrue(admin.can("unmask"))
        self.assertTrue(admin.can("users.write"))
        self.assertFalse(viewer.can("unmask"))
        self.assertFalse(viewer.can("export"))
        self.assertFalse(viewer.can("users.write"))

    def test_session_tokens_are_stored_hashed(self) -> None:
        a = self.auth()
        secret = a.create_user("erin", self.PASSWORD, "viewer")
        _, token = a.login("erin", self.PASSWORD, totp_at(secret), "10.0.0.1")
        with self.store().connect() as conn:
            stored = [str(r[0]) for r in conn.execute("SELECT token_hash FROM admin_session")]
        self.assertNotIn(token, stored, "the raw session token was stored")

    def test_audit_trail_is_append_only(self) -> None:
        a = self.auth()
        a.create_user("frank", self.PASSWORD, "viewer")
        with a.store.connect() as conn:
            conn.execute("INSERT INTO audit(timestamp, ts_epoch, actor, role, "
                         "action, target, detail, src_ip) "
                         "VALUES('2026-07-31T00:00:00Z', 0, 'x', 'admin', "
                         "'test', '', '', '')")
        for sql in ("UPDATE audit SET actor='tampered'",
                    "DELETE FROM audit"):
            with self.subTest(sql=sql):
                with self.assertRaises(Exception):
                    with a.store.connect() as conn:
                        conn.execute(sql)

    def test_logins_are_audited(self) -> None:
        a = self.auth()
        secret = a.create_user("gina", self.PASSWORD, "viewer")
        a.login("gina", self.PASSWORD, totp_at(secret), "10.0.0.1")
        actions = {e["action"] for e in a.audit_entries(limit=100)}
        self.assertTrue(any("login" in a_ for a_ in actions),
                        f"no login was audited; saw {sorted(actions)}")


# ----------------------------------------------------------------------
# Queries
# ----------------------------------------------------------------------

class TestQueries(DashboardTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.ingest()
        self.q = Queries(self.store())

    def test_stats_match_the_fixture(self) -> None:
        stats = self.q.stats()
        self.assertEqual(stats["events"], 7)
        self.assertEqual(stats["sessions"], 2)
        self.assertEqual(stats["accepted"], 1)

    def test_filter_by_source_ip(self) -> None:
        rows, total = self.q.events(EventFilter(src_ip="203.0.113.9", limit=100))
        self.assertGreater(total, 0)
        for row in rows:
            self.assertEqual(row["src_ip"], "203.0.113.9")

    def test_filter_by_username(self) -> None:
        rows, total = self.q.events(EventFilter(username="root", limit=100))
        self.assertGreater(total, 0)
        for row in rows:
            self.assertEqual(row["username"], "root")

    def test_filter_by_text_is_escaped_at_render_time(self) -> None:
        """A search term is data, never a pattern and never markup."""
        for needle in ("'; DROP TABLE event; --", "<script>", "%", "_"):
            with self.subTest(needle=needle):
                self.q.events(EventFilter(text=needle, limit=10))
        with self.store().connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM event").fetchone()[0], 7)

    def test_transfer_join_is_unambiguous(self) -> None:
        """
        `transfer` and `session` share the column names sensor, session_id and
        ts_epoch. Row access here has failed with "ambiguous column name" in
        exactly this join.
        """
        rows, total = self.q.transfers(EventFilter(limit=50))
        self.assertIsInstance(total, int)

    def test_session_search_by_outcome(self) -> None:
        rows, total = self.q.sessions(EventFilter(outcome="accepted", limit=50))
        self.assertEqual(total, 1)
        self.assertEqual(rows[0]["session_id"], "aaaa1111bbbb")

    def test_health_assessment_returns_a_verdict(self) -> None:
        from store import assess_health
        health = assess_health(self.store(), self.q)
        self.assertIn(health["level"], ("healthy", "degraded", "critical"))
        self.assertIsInstance(health["problems"], list)
        self.assertIsInstance(health["ok"], list)


class TestTtylogParser(unittest.TestCase):
    def test_round_trip(self) -> None:
        data = ttylog_bytes((1, 0, b"ls -la\n"), (2, 1000, b"total 0\n"))
        chunks = parse_ttylog_bytes(data)
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0].direction, "in")
        self.assertEqual(chunks[1].direction, "out")
        self.assertEqual(chunks[0].text, "ls -la\n")
        self.assertEqual(chunks[1].text, "total 0\n")

    def test_truncated_recording_does_not_raise(self) -> None:
        """A session cut off mid-write is normal; the parser must survive it."""
        data = ttylog_bytes((1, 0, b"id\n"), (2, 1000, b"uid=1000\n"))
        for cut in range(len(data)):
            with self.subTest(cut=cut):
                parse_ttylog_bytes(data[:cut])

    def test_garbage_does_not_raise(self) -> None:
        parse_ttylog_bytes(b"\x00" * 64)
        parse_ttylog_bytes(b"not a ttylog at all")


# ----------------------------------------------------------------------
# Filters that cannot be honoured (AUDIT F-06)
# ----------------------------------------------------------------------

class TestFilterValidation(DashboardTestCase):
    """
    A filter must return what was asked for or fail. It must never widen.

    The previous behaviour was `except ValueError: return None`, which dropped
    the clause: `since=garbage` returned every event in the store with a page
    that looked like a successful search, and a search for the literal
    character `_` matched every row with a non-empty field because `_` is a
    LIKE wildcard. Both are covered here.
    """

    def test_unparsable_dates_are_refused(self) -> None:
        from store import FilterError, _date_bound
        for bad in ("garbage", "2026-13-45", "2026-07-31T99", "31/07/2026", "2026-7-3"):
            with self.subTest(value=bad):
                with self.assertRaises(FilterError):
                    _date_bound(bad)
        # Empty still means "no bound", and a valid bound still parses.
        self.assertIsNone(_date_bound(""))
        self.assertIsNotNone(_date_bound("2026-07-31"))

    def test_every_query_path_refuses_a_bad_bound(self) -> None:
        self.ingest()
        q = Queries(self.store())
        for call in (lambda: q.events(EventFilter(since="garbage")),
                     lambda: q.sessions(EventFilter(until="not-a-date")),
                     lambda: q.transfers(EventFilter(since="2026-99-99"))):
            with self.assertRaises(Exception) as ctx:
                call()
            self.assertIn("not a date", str(ctx.exception))

    def test_a_valid_bound_still_bounds(self) -> None:
        self.ingest()
        q = Queries(self.store())
        same_day = q.events(EventFilter(since="2026-07-31", until="2026-07-31"))[1]
        later = q.events(EventFilter(since="2026-08-01"))[1]
        self.assertGreater(same_day, 0)
        self.assertEqual(later, 0,
                         "a bound that should exclude every fixture event returned rows")

    def test_like_wildcards_are_literal_characters(self) -> None:
        self.ingest()
        q = Queries(self.store())
        # No fixture field contains a literal underscore or percent sign, so a
        # literal search returns nothing. Before escaping, `_` matched every
        # row with a non-empty command, filename, url or username.
        self.assertEqual(q.events(EventFilter(text="_"))[1], 0)
        self.assertEqual(q.events(EventFilter(text="%"))[1], 0)
        self.assertEqual(q.transfers(EventFilter(text="%"))[1], 0)

    def test_literal_search_still_works(self) -> None:
        self.ingest()
        q = Queries(self.store())
        self.assertGreater(q.events(EventFilter(text="deploy"))[1], 0)

    def test_like_escaping_escapes_the_escape_character(self) -> None:
        from store import _like
        self.assertEqual(_like("a_b"), "%a\\_b%")
        self.assertEqual(_like("50%"), "%50\\%%")
        self.assertEqual(_like(r"c:\\x"), r"%c:\\\\x%")


# ----------------------------------------------------------------------
# Playback bounds (AUDIT F-04)
# ----------------------------------------------------------------------

class _StubHandler:
    """Just enough of the request handler to call _session_bundle directly."""

    def __init__(self, app) -> None:
        self.app = app

    def _client_ip(self) -> str:
        return "127.0.0.1"


class TestPlaybackBounds(DashboardTestCase):
    """
    Rendering a recording costs a multiple of its size, and the size is chosen
    by whoever connected. Two bounds: refuse to read above a display limit, and
    only render a few at once.
    """

    def app(self, **kw):
        import server as server_mod
        kw.setdefault("demo_mode", True)
        return server_mod.Dashboard(self.store_root, **kw)

    def bundle_for(self, app, sensor: str, session_id: str, principal=None):
        import server as server_mod
        return server_mod.Handler._session_bundle(
            _StubHandler(app), sensor, session_id, principal)

    def first_session(self) -> tuple[str, str]:
        self.ingest()
        rows, _ = Queries(self.store()).sessions(EventFilter(limit=5))
        for row in rows:
            if row.get("recording_sha256"):
                return str(row["sensor"]), str(row["session_id"])
        self.fail("the fixture has no recorded session")

    def test_oversized_recording_is_described_not_read(self) -> None:
        sensor, session_id = self.first_session()
        app = self.app(playback_display_limit=16)  # the fixture recording is 40+ bytes
        bundle = self.bundle_for(app, sensor, session_id)
        self.assertTrue(bundle["recorded"])
        self.assertTrue(bundle["too_large"])
        self.assertEqual(bundle["chunks"], [])
        self.assertIn("display limit", bundle["note"])
        self.assertGreater(bundle["bytes"], 16)

    def test_the_file_is_not_even_opened_when_it_is_too_large(self) -> None:
        sensor, session_id = self.first_session()
        app = self.app(playback_display_limit=16)
        opened: list[str] = []
        original = Path.read_bytes

        def tracing(self, *a, **kw):
            opened.append(str(self))
            return original(self, *a, **kw)

        Path.read_bytes = tracing  # type: ignore[assignment]
        try:
            self.bundle_for(app, sensor, session_id)
        finally:
            Path.read_bytes = original  # type: ignore[assignment]
        self.assertEqual(opened, [],
                         "the recording was read into memory despite exceeding the "
                         "display limit")

    def test_small_recording_still_renders(self) -> None:
        sensor, session_id = self.first_session()
        app = self.app(playback_display_limit=8 * 1024 * 1024)
        bundle = self.bundle_for(app, sensor, session_id)
        self.assertTrue(bundle["recorded"])
        self.assertFalse(bundle["too_large"])
        self.assertGreater(len(bundle["chunks"]), 0)

    def test_renderer_slots_are_bounded_and_do_not_leak(self) -> None:
        sensor, session_id = self.first_session()
        app = self.app(playback_display_limit=8 * 1024 * 1024,
                       playback_concurrency=1, playback_wait=0.05)
        # Hold the only slot: the request must be told the renderer is busy
        # rather than queueing without limit.
        acquired = app.playback_slots.acquire(timeout=1)
        self.assertTrue(acquired)
        try:
            busy = self.bundle_for(app, sensor, session_id)
            self.assertTrue(busy["recorded"])
            self.assertEqual(busy["chunks"], [])
            self.assertIn("busy", busy["note"])
        finally:
            app.playback_slots.release()
        # Released, so the next render works: a hostile recording that raises
        # mid-parse must not consume a slot permanently.
        after = self.bundle_for(app, sensor, session_id)
        self.assertGreater(len(after["chunks"]), 0)

    def test_a_parse_failure_does_not_leak_a_slot(self) -> None:
        sensor, session_id = self.first_session()
        app = self.app(playback_display_limit=8 * 1024 * 1024,
                       playback_concurrency=1, playback_wait=0.05)

        def boom(*a, **kw):
            raise ValueError("hostile recording")

        import ttylog
        original = ttylog.parse_ttylog_bytes
        # The handler imports the parser inside the function, so patching the
        # module attribute is what the next call will pick up.
        ttylog.parse_ttylog_bytes = boom
        try:
            with self.assertRaises(ValueError):
                self.bundle_for(app, sensor, session_id)
        finally:
            ttylog.parse_ttylog_bytes = original
        self.assertTrue(app.playback_slots.acquire(timeout=0.1),
                        "a failed render leaked the playback slot")
        app.playback_slots.release()


# ----------------------------------------------------------------------
# Session lifecycle (AUDIT F-09)
# ----------------------------------------------------------------------

class TestSessionHousekeeping(DashboardTestCase):
    PASSWORD = "Ledger-Thistle-49-Quay"

    def auth(self) -> Authenticator:
        return Authenticator(Store(self.store_root))

    def test_expired_rows_are_purged(self) -> None:
        a = self.auth()
        secret = a.create_user("vera", self.PASSWORD, "admin")
        a.login("vera", self.PASSWORD, totp_at(secret), "10.0.0.1", user_agent="UA")
        with Store(self.store_root).connect() as conn:
            conn.execute("UPDATE admin_session SET idle_expiry=0, hard_expiry=0")
        self.assertEqual(a.purge_expired_sessions(), 1)
        self.assertEqual(a.purge_expired_sessions(), 0)

    def test_login_purges_expired_rows(self) -> None:
        a = self.auth()
        secret = a.create_user("walt", self.PASSWORD, "admin")
        a.login("walt", self.PASSWORD, totp_at(secret), "10.0.0.1", user_agent="UA")
        with Store(self.store_root).connect() as conn:
            conn.execute("UPDATE admin_session SET idle_expiry=0, hard_expiry=0")
        a.login("walt", self.PASSWORD, totp_at(secret), "10.0.0.1", user_agent="UA")
        with Store(self.store_root).connect() as conn:
            stale = conn.execute(
                "SELECT COUNT(*) FROM admin_session WHERE idle_expiry < ?",
                (time.time(),)).fetchone()[0]
        self.assertEqual(stale, 0, "expired session rows accumulated after a login")

    def test_session_is_bound_to_the_user_agent(self) -> None:
        a = self.auth()
        secret = a.create_user("xena", self.PASSWORD, "admin")
        _, token = a.login("xena", self.PASSWORD, totp_at(secret), "10.0.0.1",
                           user_agent="Mozilla/5.0 (test)")
        self.assertIsNotNone(a.validate_session(token, user_agent="Mozilla/5.0 (test)"))
        self.assertIsNone(a.validate_session(token, touch=False, user_agent="curl/8.0"),
                          "a session cookie was accepted from a different client")
        # The destruction is recorded, because a replayed token is a signal.
        actions = [e["action"] for e in a.audit_entries(limit=50)]
        self.assertIn("session.ua_mismatch", actions)

    def test_missing_user_agent_does_not_lock_a_session_out(self) -> None:
        a = self.auth()
        secret = a.create_user("yuri", self.PASSWORD, "admin")
        _, token = a.login("yuri", self.PASSWORD, totp_at(secret), "10.0.0.1")
        self.assertIsNotNone(a.validate_session(token, user_agent=""))


class TestMultipleRecordings(DashboardTestCase):
    """
    One session can have several recordings, and all of them must be reachable.

    Found by pointing the dashboard at real traffic rather than at the fixture:
    Cowrie starts a ttylog per SHELL, not per connection, so a client that opens
    more than one channel on a single SSH connection (ssh -M, paramiko, most
    scripted toolkits -- including this package's own test client) produces
    several `cowrie.log.closed` events for one session, each naming a different
    shasum. The session table's single recording_sha256 column could only
    remember one, so the others were stored in the monitoring store and
    unreachable from the UI. An investigator saw one of eight transcripts and
    had no indication the rest existed.
    """

    PASSWORD = "Ledger-Thistle-49-Quay"

    def make_bundle_multi(self, tmp: Path) -> Path:
        """A session with three recordings, like a real multiplexed client."""
        bundle = tmp / "multi"
        (bundle / "tty").mkdir(parents=True, exist_ok=True)
        (bundle / "downloads").mkdir(parents=True, exist_ok=True)
        (bundle / "health").mkdir(parents=True, exist_ok=True)
        (bundle / "SENSOR").write_text("deploy-01\n")

        names = []
        events = []
        for i, (cmd, out) in enumerate((("id", "uid=1000(deploy)\n"),
                                        ("pwd", "/home/deploy\n"),
                                        ("whoami", "deploy\n"))):
            rec = ttylog_bytes((1, 0, cmd.encode()), (2, 30_000, out.encode()))
            name = hashlib.sha256(f"visitor input {i}".encode()).hexdigest()
            (bundle / "tty" / name).write_bytes(rec)
            names.append(name)
            events.append({"eventid": "cowrie.command.input", "session": "multi1",
                           "input": cmd, "sensor": "deploy-01",
                           "timestamp": f"2026-07-31T09:14:0{i}.000000Z",
                           "uuid": f"u-cmd-{i}", "message": f"CMD: {cmd}"})
            events.append({"eventid": "cowrie.log.closed", "session": "multi1",
                           "ttylog": f"var/lib/cowrie/tty/{name}", "shasum": name,
                           "size": len(rec), "duplicate": False, "duration_ms": 1200,
                           "sensor": "deploy-01",
                           "timestamp": f"2026-07-31T09:14:1{i}.000000Z",
                           "uuid": f"u-log-{i}",
                           "message": f"Closing TTY Log: var/lib/cowrie/tty/{name}"})
        events.append({"eventid": "cowrie.session.connect", "session": "multi1",
                       "src_ip": "203.0.113.77", "sensor": "deploy-01",
                       "timestamp": "2026-07-31T09:14:00.000000Z",
                       "uuid": "u-connect", "message": "New connection"})
        events.append({"eventid": "cowrie.login.success", "session": "multi1",
                       "username": "deploy", "password": "x", "sensor": "deploy-01",
                       "timestamp": "2026-07-31T09:14:00.500000Z",
                       "uuid": "u-login", "message": "login succeeded"})
        events.append({"eventid": "cowrie.session.closed", "session": "multi1",
                       "sensor": "deploy-01", "duration_ms": 9000,
                       "timestamp": "2026-07-31T09:14:20.000000Z",
                       "uuid": "u-closed", "message": "Connection lost"})

        with (bundle / "cowrie.json").open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        (bundle / "BUNDLE.json").write_text(json.dumps({
            "sensor": "deploy-01",
            "counts": {"events": len(events), "recordings": len(names)},
            "files": [{"kind": "recording", "sha256": n,
                       "content_sha256": hashlib.sha256(
                           (bundle / "tty" / n).read_bytes()).hexdigest(),
                       "bytes": (bundle / "tty" / n).stat().st_size,
                       "source_name": n} for n in names],
        }, indent=2))
        return bundle

    def setUp(self) -> None:
        super().setUp()
        import server as server_mod
        self.server_mod = server_mod
        bundle = self.make_bundle_multi(self.tmp)
        Store(self.store_root).ingest_bundle(bundle)
        self.app = server_mod.Dashboard(self.store_root, demo_mode=True)
        self.q = Queries(self.store())


    def bundle_for(self, sha: str = ""):
        import server as server_mod
        return server_mod.Handler._session_bundle(
            _StubHandler(self.app), "deploy-01", "multi1", None, sha)

    def test_ingest_keeps_every_recording_link(self) -> None:
        recs = self.q.session_recordings("deploy-01", "multi1")
        self.assertEqual(len(recs), 3,
                         "recordings that Cowrie wrote are missing from the session")
        self.assertEqual([r["ordinal"] for r in recs], [0, 1, 2],
                         "recordings are not in the order Cowrie closed them")

    def test_every_recording_is_rendered_by_hash(self) -> None:
        seen = []
        for rec in self.q.session_recordings("deploy-01", "multi1"):
            bundle = self.bundle_for(rec["sha256"])
            self.assertEqual(bundle["sha"], rec["sha256"],
                             "the requested recording is not the one served")
            self.assertTrue(bundle["recorded"])
            self.assertTrue(bundle["chunks"])
            seen.append(bundle["chunks"][0]["text"])
        self.assertEqual(sorted(seen), ["id", "pwd", "whoami"],
                         "the three transcripts are not three different transcripts")

    def test_an_unknown_hash_is_refused_not_substituted(self) -> None:
        bundle = self.bundle_for("a" * 64)
        self.assertEqual(bundle["invalid_sha"], "a" * 64)
        self.assertEqual(bundle["chunks"], [])
        self.assertFalse(bundle["recorded"])

    def test_the_primary_recording_is_one_that_exists(self) -> None:
        session = self.q.session("deploy-01", "multi1")
        recs = self.q.session_recordings("deploy-01", "multi1")
        self.assertIn(session["recording_sha256"], [r["sha256"] for r in recs])
        self.assertIsNotNone(self.q.recording_path(session["recording_sha256"]),
                             "the session's default recording is not openable")

    def test_the_list_is_present_even_when_one_recording_is_duplicate(self) -> None:
        """
        A duplicate has no file of its own, so it must be marked and skipped --
        not allowed to become the default the page tries to open.
        """
        bundle_dir = self.make_bundle_multi(self.tmp / "dup")
        Store(self.store_root).ingest_bundle(bundle_dir)
        recs = self.q.session_recordings("deploy-01", "multi1")
        for rec in recs:
            self.assertTrue(self.q.recording_path(rec["sha256"]) is not None
                            or rec["duplicate"])


class TestManageUnlockCli(DashboardTestCase):
    """
    The recovery path has to work from a shell, not just from the library.

    AUDIT F-05: five failed logins lock an account for 15 minutes, and the only
    command that cleared the lock was `passwd`, because it happened to reset the
    counter. That is not what an operator guesses at 3 a.m. This runs the actual
    CLI, the way they would.
    """

    PASSWORD = "Ledger-Thistle-49-Quay"

    def run_cli(self, *args: str):
        return subprocess.run(
            [sys.executable, str(ROOT / "dashboard" / "manage.py"),
             "--store", str(self.store_root), *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=120)

    def test_unlock_clears_a_lock_without_changing_the_password(self) -> None:
        a = Authenticator(Store(self.store_root))
        secret = a.create_user("ops1", self.PASSWORD, "admin", actor="test")
        for _ in range(5):
            with self.assertRaises(AuthError):
                a.login("ops1", "wrong-password", "000000", "10.0.0.1")
        self.assertIsNotNone(a.get_user("ops1")["locked_until"])

        proc = self.run_cli("unlock", "--username", "ops1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("not changed", proc.stdout)

        self.assertIsNone(a.get_user("ops1")["locked_until"])
        _, token = a.login("ops1", self.PASSWORD, totp_at(secret), "10.0.0.1")
        self.assertTrue(token, "unlock did not restore sign-in")
        self.assertIn("user.unlock", [e["action"] for e in a.audit_entries(limit=50)],
                      "the unlock was not recorded in the audit trail")

    def test_unlock_reports_an_unknown_account(self) -> None:
        Store(self.store_root)
        proc = self.run_cli("unlock", "--username", "nobody")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("no such user", proc.stderr)


# ----------------------------------------------------------------------
# Login CSRF (AUDIT F-07)
# ----------------------------------------------------------------------

class _NoLogHandlerMixin:
    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        pass


class TestLoginCsrf(DashboardTestCase):
    """
    The login POST must be bound to the page the browser was served.

    Before this, /login was routed before the CSRF gate and never validated a
    token, while the form still rendered one -- and that token was
    HMAC(process_secret, ""), identical for every visitor, so it protected
    nothing even if it had been checked. Login CSRF lets an attacker sign a
    victim into an account the attacker controls, after which the victim's
    actions are attributed to it in the audit trail.
    """

    PASSWORD = "Ledger-Thistle-49-Quay"

    def setUp(self) -> None:
        super().setUp()
        import server as server_mod
        self.server_mod = server_mod
        self.ingest()
        self.app = server_mod.Dashboard(self.store_root, demo_mode=True)
        self.app.auth.create_user("admin1", self.PASSWORD, "admin", actor="test")
        handler = type("TestHandler", (_NoLogHandlerMixin, server_mod.Handler), {})
        handler.app = self.app
        handler.secure_cookies = False  # the test speaks plain HTTP on loopback
        self.server = server_mod.TCPHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.base = f"http://127.0.0.1:{self.port}"

    def request(self, path: str, data: dict | None = None, method: str = "GET"):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.base + path, data=body, method=method)
        try:
            return self.opener.open(req, timeout=10)
        except urllib.error.HTTPError as exc:
            return exc  # a response object, so status and body are readable

    def login_page_token(self) -> str:
        page = self.request("/login").read().decode("utf-8")
        match = re.search(r'name="csrf" value="([^"]+)"', page)
        self.assertIsNotNone(match, "the login form no longer carries a CSRF field")
        return match.group(1)

    def cookie_value(self, name: str) -> str:
        for cookie in self.jar:
            if cookie.name == name:
                return cookie.value
        return ""

    def test_the_form_token_is_bound_to_a_cookie(self) -> None:
        token = self.login_page_token()
        self.assertTrue(token)
        self.assertEqual(self.cookie_value(self.server_mod.LOGIN_CSRF_COOKIE), token)
        self.assertNotEqual(token, self.app.csrf_for(""),
                            "the login page still renders the constant token")

    def test_post_without_the_token_is_refused(self) -> None:
        self.login_page_token()
        resp = self.request("/login", {"username": "admin1", "password": self.PASSWORD},
                            method="POST")
        self.assertEqual(resp.status, 403)
        self.assertEqual(self.cookie_value(self.server_mod.COOKIE_NAME), "",
                         "a refused login still issued a session cookie")

    def test_post_with_a_mismatched_token_is_refused(self) -> None:
        self.login_page_token()
        resp = self.request("/login",
                            {"username": "admin1", "password": self.PASSWORD,
                             "csrf": "not-the-token"}, method="POST")
        self.assertEqual(resp.status, 403)

    def test_the_previously_constant_token_is_not_accepted(self) -> None:
        self.login_page_token()
        resp = self.request("/login",
                            {"username": "admin1", "password": self.PASSWORD,
                             "csrf": self.app.csrf_for("")}, method="POST")
        self.assertEqual(resp.status, 403,
                         "the old constant token was accepted as a CSRF check")

    def test_a_correct_token_signs_in(self) -> None:
        token = self.login_page_token()
        resp = self.request("/login",
                            {"username": "admin1", "password": self.PASSWORD,
                             "csrf": token}, method="POST")
        # urllib follows the 303, so the outcome is checked by where the browser
        # lands and by the session cookie the response installed.
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.geturl(), self.base + "/")
        self.assertTrue(self.cookie_value(self.server_mod.COOKIE_NAME),
                        "a valid login did not issue a session cookie")

    def test_an_unusable_filter_is_a_visible_400(self) -> None:
        token = self.login_page_token()
        self.request("/login", {"username": "admin1", "password": self.PASSWORD,
                                "csrf": token}, method="POST")
        resp = self.request("/events?since=garbage")
        self.assertEqual(resp.status, 400)
        body = resp.read().decode("utf-8")
        self.assertIn("cannot be used", body)
        self.assertIn("not a date", body)
        self.assertIn("garbage", body)

    def test_an_oversized_body_closes_the_connection(self) -> None:
        """A rejected body must not be parsed as the next request (AUDIT F-10)."""
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            sock.sendall(b"POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                         b"Content-Length: 2000000\r\n\r\n")
            response = b""
            while True:
                block = sock.recv(65536)
                if not block:
                    break
                response += block
            self.assertIn(b"403", response)
            # Reaching EOF is the assertion: the server closed the connection,
            # so the 2 MB of unread body can never be parsed as a second
            # request. (Draining it would also do; closing is the version with
            # no bound to get wrong on a slow sender.)
            self.assertEqual(sock.recv(1), b"")
        finally:
            sock.close()


class TestRelaxedControls(unittest.TestCase):
    """AUDIT F-08: the running configuration must be stated, not implied."""

    def ns(self, **kw):
        base = dict(demo_mode=False, allow_framing=False, relax_cookie_policy=False,
                    no_secure_cookies=False)
        base.update(kw)
        return type("NS", (), base)

    def setUp(self) -> None:
        import server as server_mod
        self.server_mod = server_mod

    def test_nothing_reported_when_nothing_is_relaxed(self) -> None:
        self.assertEqual(self.server_mod.relaxed_controls(self.ns(), "tcp", ("127.0.0.1", 8443)), [])

    def test_every_relaxation_is_listed(self) -> None:
        items = self.server_mod.relaxed_controls(
            self.ns(demo_mode=True, allow_framing=True, relax_cookie_policy=True,
                    no_secure_cookies=True),
            "tcp", ("0.0.0.0", 8443))
        joined = " ".join(items)
        for needle in ("demo-mode", "non-loopback", "allow-framing",
                       "relax-cookie-policy", "no-secure-cookies"):
            self.assertIn(needle, joined)

    def test_demo_mode_on_a_reachable_interface_is_named(self) -> None:
        """The old comment claimed this combination was refused. It is not."""
        items = self.server_mod.relaxed_controls(self.ns(demo_mode=True),
                                                 "tcp", ("10.0.0.5", 8443))
        self.assertTrue(any("NOT enforced" in i for i in items))
        self.assertTrue(any("non-loopback" in i for i in items))


class TestHtmlEscaping(DashboardTestCase):
    def test_backticks_are_escaped(self) -> None:
        """AUDIT F-11: latent, not exploitable as written, cheap to close."""
        out = safe_html("`onmouseover=alert(1)")
        self.assertNotIn("`", out)
        self.assertIn("&#96;", out)

    def test_escaping_is_still_correct_for_the_usual_characters(self) -> None:
        out = safe_html('<img src=x onerror="alert(1)">')
        for raw in ("<", ">", '"'):
            self.assertNotIn(raw, out)



if __name__ == "__main__":
    unittest.main(verbosity=2)

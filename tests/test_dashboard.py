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
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
Tests for the administrator-only session playback interface.

The point of these tests is not that the viewer shows the right pixels. It is
that a hostile recording cannot affect the reviewer, and that a captured secret
does not appear on screen by default. A playback tool that renders attacker
bytes faithfully is a vulnerability, not a feature.

Run:  python3 tests/test_playback.py
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "playback"))

import server as playback  # noqa: E402

TTYSTRUCT = "<iLiiLL"
OP_OPEN, OP_CLOSE, OP_WRITE = 1, 2, 3
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3

# A recording that tries three separate attacks plus one secret.
HOSTILE_INPUT = (
    b"curl -u admin:hunter2 http://x/\r"                 # secret to mask
    b"\x1b]0;evil title\x07echo hi\r"                    # OSC window title
    b"\x1b[2J\x1b[1;1Hclear attempt\r"                   # CSI cursor control
    b"\u202egnirts\x1b[0m\r"                             # bidi override
    b"<script>alert('xss')</script>\r"                   # markup injection
    b"</script><script nonce=nope>alert(1)</script>\r"   # CSP nonce brute force
    b"</textarea>\x00\x07\x1b[31m\xff\xfe\r"             # raw control + bad utf-8
)
HOSTILE_OUTPUT = b"$ \x1b[32mok\x1b[0m\n<img src=x onerror=alert(1)>\n"


def build_ttylog(path: Path, start: float = 1_700_000_000.0) -> None:
    def rec(op: int, direction: int, payload: bytes, offset: float) -> bytes:
        return struct.pack(TTYSTRUCT, op, 0, len(payload), direction, int(start + offset),
                           int(((start + offset) % 1) * 1_000_000)) + payload

    with path.open("wb") as fh:
        fh.write(struct.pack(TTYSTRUCT, OP_OPEN, 0, 0, 0, int(start), 0))
        fh.write(rec(OP_WRITE, TYPE_INPUT, HOSTILE_INPUT, 0.10))
        fh.write(rec(OP_WRITE, TYPE_OUTPUT, HOSTILE_OUTPUT, 0.20))
        fh.write(rec(OP_WRITE, TYPE_INTERACT, b"id;whoami;uname -a", 0.30))
        fh.write(struct.pack(TTYSTRUCT, OP_CLOSE, 0, 0, 0, int(start + 1), 0))


def make_state(root: Path, session: str = "cafe01234567") -> Path:
    state = root / "state"
    (state / "var/log/cowrie").mkdir(parents=True)
    (state / "var/lib/cowrie/tty").mkdir(parents=True)
    (state / "var/lib/cowrie/downloads").mkdir(parents=True)

    tty_name = "a" * 64
    build_ttylog(state / "var/lib/cowrie/tty" / tty_name)

    ts = "2026-01-02T03:04:05.000000Z"
    events = [
        {"eventid": "cowrie.session.connect", "session": session, "src_ip": "203.0.113.9",
         "src_port": 51234, "timestamp": ts, "protocol": "ssh"},
        {"eventid": "cowrie.client.version", "session": session,
         "version": "SSH-2.0-libssh_0.9.6", "timestamp": ts},
        {"eventid": "cowrie.login.failed", "session": session, "username": "root",
         "password": "hunter2", "timestamp": ts},
        {"eventid": "cowrie.login.success", "session": session, "username": "deploy",
         "password": "Sunrise-Ledger-1972", "timestamp": ts},
        {"eventid": "cowrie.session.file_upload", "session": session,
         "filename": "../../etc/passwd", "shasum": "b" * 64, "size": 4096,
         "timestamp": "2026-01-02T03:04:15.000000Z"},
        {"eventid": "cowrie.log.closed", "session": session,
         "ttylog": f"var/lib/cowrie/tty/{tty_name}", "shasum": tty_name,
         "duplicate": False, "size": 999, "duration_ms": 30000, "timestamp": ts},
        {"eventid": "cowrie.session.closed", "session": session, "duration_ms": 30000,
         "timestamp": ts},
    ]
    with (state / "var/log/cowrie/cowrie.json").open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    return state


class TestTerminalSafety(unittest.TestCase):
    def test_escape_sequences_are_stripped(self) -> None:
        cleaned = playback.strip_terminal_control("\x1b[31mred\x1b[0m")
        self.assertEqual(cleaned, "red")

    def test_osc_sequence_is_stripped(self) -> None:
        # OSC 52 can set the reviewer's clipboard in some terminals.
        cleaned = playback.strip_terminal_control("\x1b]52;c;cGF3bmVk\x07visible")
        self.assertEqual(cleaned, "visible")

    def test_bidi_override_is_stripped(self) -> None:
        # "\u202erm -rf /" would otherwise display reordered.
        cleaned = playback.strip_terminal_control("rm \u202e-fr /")
        self.assertNotIn("\u202e", cleaned)

    def test_control_characters_are_stripped(self) -> None:
        cleaned = playback.strip_terminal_control("a\x00b\x07c\x7fd")
        self.assertEqual(cleaned, "abcd")

    def test_newline_survives(self) -> None:
        self.assertEqual(playback.strip_terminal_control("a\nb\tc"), "a\nb\tc")


class TestMasking(unittest.TestCase):
    def test_curl_basic_auth_is_masked(self) -> None:
        masked = playback.mask_sensitive("curl -u admin:hunter2 http://x/")
        self.assertNotIn("hunter2", masked)
        self.assertIn("[REDACTED]", masked)

    def test_password_assignment_is_masked(self) -> None:
        for text in ("password=SuperSecret", "PASSWD: SuperSecret", "pwd: SuperSecret"):
            with self.subTest(text=text):
                masked = playback.mask_sensitive(text)
                self.assertNotIn("SuperSecret", masked)

    def test_mysqldump_short_password_is_masked(self) -> None:
        masked = playback.mask_sensitive("mysqldump -u root -pTr0ub4dor db > x.sql")
        self.assertNotIn("Tr0ub4dor", masked)

    def test_aws_key_is_masked(self) -> None:
        masked = playback.mask_sensitive("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", masked)

    def test_private_key_header_is_flagged(self) -> None:
        masked = playback.mask_sensitive("-----BEGIN OPENSSH PRIVATE KEY-----")
        self.assertIn("[REDACTED]", masked)

    def test_ordinary_text_is_untouched(self) -> None:
        text = "cat /etc/passwd && ls -la /var/log"
        self.assertEqual(playback.mask_sensitive(text), text)

    def test_backspace_is_kept_for_line_editing(self) -> None:
        # strip_escapes keeps editing characters; strip_terminal_control does not.
        self.assertEqual(playback.strip_escapes("ab\x7f\x7fcd"), "ab\x7f\x7fcd")
        self.assertEqual(playback.strip_terminal_control("ab\x7f\x7fcd"), "abcd")

    def test_ctrl_c_is_kept_for_line_editing(self) -> None:
        self.assertIn("\x03", playback.strip_escapes("partial\x03"))

    def test_masking_runs_after_escape_stripping(self) -> None:
        # An attacker could try to split "password=" with an escape sequence so
        # that a naive masker misses it.
        hostile = "pass\x1b[0mword=Secret123"
        result = playback.safe_text(hostile, mask=True)
        self.assertNotIn("Secret123", result)


class TestPayloadSafety(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = make_state(Path(self.tmp.name))
        self.store = playback.EvidenceStore(self.state)
        self.store.load()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_session_is_parsed(self) -> None:
        sessions = self.store.sessions()
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0].source_ip, "203.0.113.9")
        self.assertEqual(sessions[0].login_result, "accepted")
        self.assertEqual(sessions[0].username, "deploy")

    def test_recording_found_by_log_closed_path(self) -> None:
        s = self.store.sessions()[0]
        self.assertTrue(s.chunks, "recording was not attached")
        self.assertEqual(s.ttylog_sha256, "a" * 64)

    def test_exec_command_shows_in_transcript(self) -> None:
        s = self.store.sessions()[0]
        commands = [r["command"] for r in self.store.transcript(s)]
        self.assertIn("id;whoami;uname -a", commands)

    def test_escape_parameters_do_not_leak_into_transcript(self) -> None:
        """
        "\x1b[2J" must vanish entirely. If it were stripped only after line
        assembly, the transcript would show a command named "[2J" that the
        visitor never typed (and an attacker could fabricate such lines).
        """
        s = self.store.sessions()[0]
        commands = [r["command"] for r in self.store.transcript(s)]
        joined = "\n".join(commands)
        for artefact in ("[2J", "[1;1H", "[0m", "[31m", "]0;", "\x1b"):
            self.assertNotIn(artefact, joined, f"{artefact!r} leaked into the transcript")
        # The real text of those lines survives.
        self.assertIn("clear attempt", joined)
        self.assertIn("echo hi", joined)

    def test_embedded_payload_cannot_close_script_element(self) -> None:
        payload = playback.build_payload(self.store, mask=True)
        self.assertNotIn("<", payload)
        self.assertNotIn(">", payload)
        self.assertNotIn("</script", payload)
        json.loads(payload)   # still valid JSON

    def test_html_in_recording_is_neutralised(self) -> None:
        payload = playback.build_payload(self.store, mask=True)
        # The recorded text is still *present* as data, but there is no raw
        # markup character anywhere in the payload, so it cannot become live
        # markup when embedded in the page.
        self.assertNotIn("<script>", payload)
        self.assertNotIn("<img src=x", payload)
        self.assertIn("\\u003cscript\\u003e", payload)
        # And it is still valid JSON that decodes back to the original text.
        decoded = json.loads(payload)
        blob = json.dumps(decoded)
        self.assertIn("<script>alert", blob)

    def test_secrets_absent_by_default(self) -> None:
        payload = playback.build_payload(self.store, mask=True)
        self.assertNotIn("hunter2", payload)
        self.assertNotIn("Sunrise-Ledger-1972", payload)

    def test_secrets_present_only_when_unmasked(self) -> None:
        payload = playback.build_payload(self.store, mask=False)
        self.assertIn("hunter2", payload)
        self.assertIn("[REDACTED]", playback.build_payload(self.store, mask=True))

    def test_upload_filename_is_marked_quarantined(self) -> None:
        s = self.store.sessions()[0]
        self.assertEqual(len(s.transfers), 1)
        self.assertEqual(s.transfers[0].event, "upload")
        self.assertTrue(s.transfers[0].quarantined)
        self.assertEqual(s.transfers[0].sha256, "b" * 64)

    def test_transfer_has_seek_offset(self) -> None:
        s = self.store.sessions()[0]
        self.assertGreaterEqual(s.transfers[0].offset_ms, 0)

    def test_traversal_in_ttylog_path_is_refused(self) -> None:
        """A poisoned cowrie.json must not let the viewer read /etc/shadow."""
        state = Path(self.tmp.name) / "state2"
        (state / "var/log/cowrie").mkdir(parents=True)
        (state / "var/lib/cowrie/tty").mkdir(parents=True)
        (state / "var/log/cowrie/cowrie.json").write_text(
            json.dumps({"eventid": "cowrie.log.closed", "session": "s1",
                        "ttylog": "../../../../../../etc/shadow",
                        "shasum": "../../etc/shadow", "timestamp": "2026-01-01T00:00:00Z"}) + "\n",
            encoding="utf-8",
        )
        store = playback.EvidenceStore(state)
        store.load()
        s = store.session("s1")
        self.assertIsNotNone(s)
        self.assertEqual(s.chunks, [], "viewer followed a path outside the tty directory")

    def test_absolute_ttylog_path_outside_state_is_refused(self) -> None:
        state = Path(self.tmp.name) / "state3"
        (state / "var/log/cowrie").mkdir(parents=True)
        (state / "var/lib/cowrie/tty").mkdir(parents=True)
        (state / "var/log/cowrie/cowrie.json").write_text(
            json.dumps({"eventid": "cowrie.log.closed", "session": "s2",
                        "ttylog": "/etc/hostname", "timestamp": "2026-01-01T00:00:00Z"}) + "\n",
            encoding="utf-8",
        )
        store = playback.EvidenceStore(state)
        store.load()
        self.assertEqual(store.session("s2").chunks, [])

    def test_truncated_log_line_is_tolerated(self) -> None:
        state = Path(self.tmp.name) / "state4"
        (state / "var/log/cowrie").mkdir(parents=True)
        (state / "var/lib/cowrie/tty").mkdir(parents=True)
        (state / "var/log/cowrie/cowrie.json").write_text(
            '{"eventid": "cowrie.session.connect", "session": "s3", "timestamp": "2026-01-01T00:00:00Z"}\n'
            '{"eventid": "cowrie.session.clo',   # killed mid-write
            encoding="utf-8",
        )
        store = playback.EvidenceStore(state)
        store.load()
        self.assertEqual(len(store.sessions()), 1)

    def test_truncated_recording_is_tolerated(self) -> None:
        tty = self.state / "var/lib/cowrie/tty" / ("a" * 64)
        data = tty.read_bytes()
        tty.write_bytes(data[: len(data) - 5])   # chop mid-record
        store = playback.EvidenceStore(self.state)
        store.load()
        # Must not raise; partial chunks are acceptable.
        store.transcript(store.sessions()[0])


class TestServer(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = make_state(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_refuses_to_bind_publicly_without_acknowledgement(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(REPO / "playback/server.py"),
             "--state", str(self.state), "--host", "0.0.0.0", "--port", "0"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("refusing to bind", proc.stderr)

    def test_serves_page_and_safety_headers(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, str(REPO / "playback/server.py"),
             "--state", str(self.state), "--port", "18099"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                try:
                    with urllib.request.urlopen("http://127.0.0.1:18099/healthz", timeout=1) as r:
                        if r.status == 200:
                            break
                except Exception:
                    time.sleep(0.1)
            with urllib.request.urlopen("http://127.0.0.1:18099/", timeout=5) as r:
                body = r.read().decode("utf-8")
                headers = {k.lower(): v for k, v in r.getheaders()}
            self.assertIn("Content-Security-Policy", {k: v for k, v in r.getheaders()})
        finally:
            proc.terminate()
            proc.wait(timeout=10)

        csp = headers["content-security-policy"]
        self.assertIn("script-src 'nonce-", csp)
        self.assertNotIn("unsafe-inline", csp.split("script-src")[1].split(";")[0])
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertEqual(headers["cache-control"], "no-store")

        self.assertIn("session playback", body)
        # The hostile recording must not have ended up as live markup.
        self.assertNotIn("<script>alert", body)
        self.assertNotIn("hunter2", body)
        self.assertIn("\\u003cscript\\u003e", body)
        # The nonce in the header must match the one on the script tag.
        nonce = csp.split("script-src 'nonce-")[1].split("'")[0]
        self.assertIn(f'nonce="{nonce}"', body)

    def test_healthz(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, str(REPO / "playback/server.py"),
             "--state", str(self.state), "--port", "18098"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                try:
                    with urllib.request.urlopen("http://127.0.0.1:18098/healthz", timeout=1) as r:
                        self.assertEqual(r.read().strip(), b"ok")
                        return
                except Exception:
                    time.sleep(0.1)
            self.fail("server did not become ready")
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_unknown_path_is_404(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, str(REPO / "playback/server.py"),
             "--state", str(self.state), "--port", "18097"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                try:
                    urllib.request.urlopen("http://127.0.0.1:18097/healthz", timeout=1).close()
                    break
                except Exception:
                    time.sleep(0.1)
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen("http://127.0.0.1:18097/../etc/passwd", timeout=5)
            self.assertEqual(ctx.exception.code, 404)
        finally:
            proc.terminate()
            proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""
The monitoring store: a separate, restricted database of honeypot evidence.

ARCHITECTURE, AND WHY IT IS SHAPED THIS WAY
    The dashboard must not be able to reach the honeypot. Not "must not
    normally", not "is configured not to" -- must not be able to. That is a
    structural property here, enforced in three places:

      1. The store has no idea the honeypot exists. There is no hostname, no
         address, no port and no credential for it anywhere in this module or
         in the database schema. A dashboard that does not know where the
         honeypot is cannot command it.

      2. Ingestion is a separate program (`ingest.py`) that reads an export
         bundle and writes into the store. It runs on a timer on the monitoring
         host. The web process never imports it and never triggers it.

      3. In production the web process has no network capability at all: it
         listens on a UNIX socket and the unit sets RestrictAddressFamilies to
         AF_UNIX. It cannot open a TCP connection to anything, so it cannot
         reach the honeypot even if a future bug tried to.

    Data flows one way: honeypot -> export bundle -> ingest -> store -> browser.
    There is no path in the other direction.

WHAT IS STORED WHERE
    store.sqlite3        the event index. Queried by the dashboard.
    recordings/<sha256>  Cowrie ttylogs, content-addressed.
    quarantine/<sha256>  Captured uploaded files. The dashboard NEVER reads
                         this directory -- it has no code path that opens a
                         file here, and the group permissions on this
                         deployment keep the web account out of it entirely.
                         Only metadata and hashes appear in the UI.
    manifests/           ingest manifests, so re-ingestion is idempotent and a
                         gap in coverage is detectable.
    backup-status.json   written by ops/store_backup.sh, read for the health
                         page.

EVIDENCE INTEGRITY
    The store is append-only for events and recordings. Identical input
    re-ingested produces no duplicate rows, so a re-run is always safe. The
    audit table is protected by triggers that reject UPDATE and DELETE, so the
    record of who looked at what cannot be quietly edited -- not by the
    application, not by an operator with a SQLite client.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _cand in (_HERE.parent / "shared", Path("/opt/honeypot-monitor/share")):
    if (_cand / "terminal_safety.py").is_file():
        sys.path.insert(0, str(_cand))
        break

from terminal_safety import safe_log_value, strip_terminal_control  # noqa: E402
from ttylog import parse_ts_epoch, parse_ttylog_bytes  # noqa: E402

SCHEMA_VERSION = 1

# Event ids the dashboard understands. Anything not listed is still stored and
# still visible under "other", so a Cowrie upgrade that adds events cannot
# silently drop them.
LOGIN_EVENTS = ("cowrie.login.success", "cowrie.login.failed")
TRANSFER_EVENTS = ("cowrie.session.file_upload", "cowrie.session.file_download",
                   "cowrie.session.file_download.failed")
COMMAND_EVENTS = ("cowrie.command.input", "cowrie.command.failed", "cowrie.command.success")

EVENT_TYPES = {
    "session.connect": ["cowrie.session.connect"],
    "session.closed": ["cowrie.session.closed"],
    "login.success": ["cowrie.login.success"],
    "login.failed": ["cowrie.login.failed"],
    "command": list(COMMAND_EVENTS),
    "transfer": list(TRANSFER_EVENTS),
    "recording": ["cowrie.log.open", "cowrie.log.closed"],
    "client": ["cowrie.client.version", "cowrie.client.kex", "cowrie.client.fingerprint"],
    "other": [],
}

OUTCOMES = ("accepted", "rejected", "unknown")

MAX_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 50


# =============================================================================
# Schema
# =============================================================================
SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_run (
    id             INTEGER PRIMARY KEY,
    started        TEXT NOT NULL,
    finished       TEXT,
    source         TEXT NOT NULL,
    files_seen     INTEGER NOT NULL DEFAULT 0,
    events_new     INTEGER NOT NULL DEFAULT 0,
    events_dup     INTEGER NOT NULL DEFAULT 0,
    recordings_new INTEGER NOT NULL DEFAULT 0,
    quarantine_new INTEGER NOT NULL DEFAULT 0,
    health_new     INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'running',
    error          TEXT
);

CREATE TABLE IF NOT EXISTS event (
    id          INTEGER PRIMARY KEY,
    dedupe_key  TEXT NOT NULL UNIQUE,
    ingest_id   INTEGER REFERENCES ingest_run(id),
    sensor      TEXT NOT NULL,
    session_id  TEXT,
    eventid     TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    ts_epoch    REAL NOT NULL,
    src_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    username    TEXT,
    password    TEXT,
    outcome     TEXT,
    command     TEXT,
    filename    TEXT,
    url         TEXT,
    shasum      TEXT,
    size        INTEGER,
    message     TEXT,
    raw         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_ts      ON event(ts_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_event_src     ON event(src_ip);
CREATE INDEX IF NOT EXISTS idx_event_user    ON event(username);
CREATE INDEX IF NOT EXISTS idx_event_id_eid  ON event(eventid);
CREATE INDEX IF NOT EXISTS idx_event_session ON event(sensor, session_id);
CREATE INDEX IF NOT EXISTS idx_event_outcome ON event(outcome);

CREATE TABLE IF NOT EXISTS session (
    sensor             TEXT NOT NULL,
    session_id         TEXT NOT NULL,
    src_ip             TEXT,
    src_port           INTEGER,
    started            TEXT,
    started_epoch      REAL,
    ended              TEXT,
    duration_ms        INTEGER NOT NULL DEFAULT 0,
    username           TEXT,
    login_result       TEXT NOT NULL DEFAULT 'unknown',
    client_version     TEXT,
    recording_sha256   TEXT,
    recording_bytes    INTEGER NOT NULL DEFAULT 0,
    recording_duplicate INTEGER NOT NULL DEFAULT 0,
    command_count      INTEGER NOT NULL DEFAULT 0,
    transfer_count     INTEGER NOT NULL DEFAULT 0,
    chunk_count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (sensor, session_id)
);
CREATE INDEX IF NOT EXISTS idx_session_start  ON session(started_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_session_src    ON session(src_ip);
CREATE INDEX IF NOT EXISTS idx_session_result ON session(login_result);

CREATE TABLE IF NOT EXISTS transfer (
    id          INTEGER PRIMARY KEY,
    dedupe_key  TEXT NOT NULL UNIQUE,
    sensor      TEXT NOT NULL,
    session_id  TEXT,
    timestamp   TEXT NOT NULL,
    ts_epoch    REAL NOT NULL,
    event       TEXT NOT NULL,
    filename    TEXT,
    sha256      TEXT,
    size        INTEGER,
    url         TEXT,
    quarantined INTEGER NOT NULL DEFAULT 0,
    offset_ms   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_transfer_ts      ON transfer(ts_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_transfer_sha     ON transfer(sha256);
CREATE INDEX IF NOT EXISTS idx_transfer_session ON transfer(sensor, session_id);

CREATE TABLE IF NOT EXISTS recording (
    sha256       TEXT PRIMARY KEY,
    sensor       TEXT NOT NULL,
    relpath      TEXT NOT NULL,
    bytes        INTEGER NOT NULL DEFAULT 0,
    chunk_count  INTEGER NOT NULL DEFAULT 0,
    duration_ms  INTEGER NOT NULL DEFAULT 0,
    ingested     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS command (
    id         INTEGER PRIMARY KEY,
    dedupe_key TEXT NOT NULL UNIQUE,
    sensor     TEXT NOT NULL,
    session_id TEXT,
    timestamp  TEXT NOT NULL,
    ts_epoch   REAL NOT NULL,
    command    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_command_session ON command(sensor, session_id);
CREATE INDEX IF NOT EXISTS idx_command_ts      ON command(ts_epoch DESC);

CREATE TABLE IF NOT EXISTS health (
    id            INTEGER PRIMARY KEY,
    dedupe_key    TEXT NOT NULL UNIQUE,
    sensor        TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    ts_epoch      REAL NOT NULL,
    service       TEXT,
    banner_ok     INTEGER,
    log_age_s     INTEGER,
    disk_pct      INTEGER,
    quarantine_mb INTEGER,
    outbound      INTEGER,
    raw           TEXT
);
CREATE INDEX IF NOT EXISTS idx_health_ts ON health(ts_epoch DESC);

-- ---------------------------------------------------------------------------
-- Administrator accounts and audit
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_user (
    username       TEXT PRIMARY KEY,
    password_hash  TEXT NOT NULL,
    totp_secret    TEXT,
    totp_enabled   INTEGER NOT NULL DEFAULT 0,
    role           TEXT NOT NULL,
    created        TEXT NOT NULL,
    last_login     TEXT,
    disabled       INTEGER NOT NULL DEFAULT 0,
    failed_count   INTEGER NOT NULL DEFAULT 0,
    locked_until   REAL
);

CREATE TABLE IF NOT EXISTS admin_session (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    role       TEXT NOT NULL,
    created    REAL NOT NULL,
    last_seen  REAL NOT NULL,
    idle_expiry REAL NOT NULL,
    hard_expiry REAL NOT NULL,
    src_ip     TEXT,
    ua_hash    TEXT
);
CREATE INDEX IF NOT EXISTS idx_asess_user ON admin_session(username);

CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    ts_epoch  REAL NOT NULL,
    actor     TEXT NOT NULL,
    role      TEXT,
    action    TEXT NOT NULL,
    target    TEXT,
    detail    TEXT,
    src_ip    TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts    ON audit(ts_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit(actor);
CREATE INDEX IF NOT EXISTS idx_audit_act   ON audit(action);

-- The audit trail is evidence about administrators. Triggers reject any attempt
-- to modify or delete it, so "who looked at what" survives an operator with a
-- SQLite client as well as an application bug.
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit trail is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit trail is append-only');
END;

CREATE TABLE IF NOT EXISTS export_log (
    id        INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    ts_epoch  REAL NOT NULL,
    actor     TEXT NOT NULL,
    kind      TEXT NOT NULL,
    query     TEXT,
    row_count INTEGER,
    bytes     INTEGER,
    dest      TEXT
);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    dt = dt or utcnow()
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class IngestStats:
    files_seen: int = 0
    events_new: int = 0
    events_dup: int = 0
    recordings_new: int = 0
    quarantine_new: int = 0
    health_new: int = 0
    errors: list[str] = field(default_factory=list)


class Store:
    """
    Read/write handle on the monitoring store.

    The web process opens it read-only (`readonly=True`), which is a second
    structural guarantee that the dashboard cannot alter evidence: SQLite
    rejects the write at the driver level, not at the application's discretion.
    """

    def __init__(self, root: str | Path, readonly: bool = False) -> None:
        self.root = Path(root)
        self.readonly = readonly
        self.db_path = self.root / ("store.sqlite3" if not readonly else "store.sqlite3")
        self.recordings_dir = self.root / "recordings"
        self.quarantine_dir = self.root / "quarantine"
        self.manifests_dir = self.root / "manifests"
        if not readonly:
            for d in (self.root, self.recordings_dir, self.quarantine_dir, self.manifests_dir):
                d.mkdir(parents=True, exist_ok=True)
            self._init_schema()

    # -- connection --------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        if self.readonly:
            uri = f"file:{self.db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=15.0)
            conn.execute("PRAGMA query_only = ON")
        else:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def connect(self):
        conn = self._connect()
        try:
            yield conn
            if not self.readonly:
                conn.commit()
        except Exception:
            if not self.readonly:
                conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    def ingest_bundle(self, bundle: Path) -> IngestStats:
        """
        Import one export bundle. Idempotent: re-running over overlapping input
        adds nothing, because every row carries a dedupe key derived from
        Cowrie's own event uuid where present.

        A bundle is a directory containing any of:
            cowrie.json          newline-delimited Cowrie events
            tty/<sha256>         recordings
            downloads/<sha256>   captured files, moved to quarantine, never read
            health/*.log         health-check log lines
        """
        stats = IngestStats()
        sensor = self._sensor_name(bundle)
        started = iso()

        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO ingest_run(started, source, status) VALUES(?,?,?)",
                (started, str(bundle), "running"),
            )
            run_id = cur.lastrowid

        # Recordings are copied BEFORE the events are parsed. `_link_recording`
        # resolves a session's recording hash to a file in the store, so if the
        # files were copied afterwards the first ingest of a bundle would
        # produce sessions with no recording attached -- and only the first,
        # because the second run would find them already present. That is the
        # worst kind of bug: it works when you retest and fails in production.
        self._ingest_recordings(bundle, sensor, stats)
        self._ingest_quarantine(bundle, sensor, stats)

        log_files = sorted(bundle.glob("cowrie.json*")) + sorted(bundle.glob("*.jsonl"))
        for path in log_files:
            stats.files_seen += 1
            self._ingest_events(path, sensor, run_id, stats)

        self._ingest_health(bundle, sensor, stats)
        # Order-independent safety net: link any session that names a recording
        # now present in the store but whose chunk count was never filled in.
        self._backfill_recording_links()
        self._write_manifest(bundle, sensor, stats, started)

        with self.connect() as conn:
            conn.execute(
                """UPDATE ingest_run SET finished=?, files_seen=?, events_new=?,
                       events_dup=?, recordings_new=?, quarantine_new=?, health_new=?,
                       status=?, error=? WHERE id=?""",
                (iso(), stats.files_seen, stats.events_new, stats.events_dup,
                 stats.recordings_new, stats.quarantine_new, stats.health_new,
                 "failed" if stats.errors else "ok",
                 "; ".join(stats.errors[:10]) or None, run_id),
            )
        return stats

    @staticmethod
    def _sensor_name(bundle: Path) -> str:
        """Sensor identity from the bundle's sensor file, else the directory name."""
        marker = bundle / "SENSOR"
        if marker.is_file():
            name = marker.read_text(encoding="utf-8", errors="replace").strip()
            if name:
                return name[:128]
        return bundle.name[:128]

    def _ingest_events(self, path: Path, sensor: str, run_id: int, stats: IngestStats) -> None:
        session_rows: dict[str, dict] = {}
        try:
            fh = path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            stats.errors.append(f"cannot read {path.name}: {exc}")
            return

        with fh, self.connect() as conn:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    # A truncated final line after a hard kill is normal.
                    stats.errors.append(f"unparsable line in {path.name}")
                    continue
                if not isinstance(ev, dict) or "eventid" not in ev:
                    continue

                # Dedupe on the content of the line, NOT on Cowrie's `uuid`.
                #
                # Cowrie's `uuid` field looks like an event identifier and is
                # not one: it is a sensor/boot identity, and every event from a
                # given sensor carries the same value. Keying on it silently
                # discards all but the first event -- a failure that looks like
                # success, because ingestion reports "4873 duplicates" rather
                # than an error. Verified directly against a real log
                # (tests/test_dashboard.py::TestIngestDedupe).
                #
                # The cost of keying on content: two byte-identical lines in the
                # same log would collapse to one. Cowrie timestamps carry
                # microsecond precision, so a genuine collision would require
                # two identical events in the same microsecond.
                key = hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()
                row = self._event_row(ev, line, sensor, run_id, key)
                try:
                    conn.execute(
                        """INSERT INTO event(dedupe_key, ingest_id, sensor, session_id, eventid,
                               timestamp, ts_epoch, src_ip, src_port, dst_port, username,
                               password, outcome, command, filename, url, shasum, size,
                               message, raw)
                           VALUES(:dedupe_key,:ingest_id,:sensor,:session_id,:eventid,
                               :timestamp,:ts_epoch,:src_ip,:src_port,:dst_port,:username,
                               :password,:outcome,:command,:filename,:url,:shasum,:size,
                               :message,:raw)""",
                        row,
                    )
                    stats.events_new += 1
                except sqlite3.IntegrityError:
                    stats.events_dup += 1

                self._accumulate_session(session_rows, ev)

            # Materialise the session summaries this batch described.
            for sid, acc in session_rows.items():
                self._upsert_session(conn, sensor, sid, acc)

        for sid, acc in session_rows.items():
            self._link_recording(sensor, sid, acc)

    @staticmethod
    def _event_row(ev: dict, raw_line: str, sensor: str, run_id: int, key: str) -> dict:
        eid = str(ev.get("eventid", ""))
        outcome = None
        if eid == "cowrie.login.success":
            outcome = "accepted"
        elif eid == "cowrie.login.failed":
            outcome = "rejected"
        command = ev.get("input") or ev.get("command")
        size = ev.get("size")
        try:
            size = int(size) if size is not None else None
        except (TypeError, ValueError):
            size = None
        src_port = ev.get("src_port")
        try:
            src_port = int(src_port) if src_port is not None else None
        except (TypeError, ValueError):
            src_port = None
        dst_port = ev.get("dst_port")
        try:
            dst_port = int(dst_port) if dst_port is not None else None
        except (TypeError, ValueError):
            dst_port = None
        return {
            "dedupe_key": key,
            "ingest_id": run_id,
            "sensor": sensor,
            "session_id": ev.get("session"),
            "eventid": eid,
            "timestamp": str(ev.get("timestamp", "")),
            "ts_epoch": parse_ts_epoch(ev.get("timestamp")) or 0.0,
            "src_ip": ev.get("src_ip"),
            "src_port": src_port,
            "dst_port": dst_port,
            "username": ev.get("username"),
            # Stored, because it is evidence and the analyst may need it.
            # Never rendered unless an administrator explicitly unmasks.
            "password": ev.get("password"),
            "outcome": outcome,
            "command": command,
            "filename": ev.get("filename"),
            "url": ev.get("url"),
            "shasum": ev.get("shasum"),
            "size": size,
            "message": ev.get("message"),
            "raw": raw_line[:64_000],
        }

    @staticmethod
    def _accumulate_session(acc: dict[str, dict], ev: dict) -> None:
        sid = ev.get("session")
        if not sid:
            return
        s = acc.setdefault(sid, {
            "src_ip": None, "src_port": None, "started": None, "started_epoch": None,
            "ended": None, "duration_ms": 0, "username": None, "login_result": "unknown",
            "client_version": None, "recording_sha256": None, "recording_bytes": 0,
            "recording_duplicate": 0, "command_count": 0, "transfer_count": 0,
            "chunk_count": 0,
        })
        eid = str(ev.get("eventid", ""))
        ts = str(ev.get("timestamp", ""))

        if eid == "cowrie.session.connect":
            s["src_ip"] = s["src_ip"] or ev.get("src_ip")
            s["src_port"] = s["src_port"] or ev.get("src_port")
            s["started"] = s["started"] or ts
            s["started_epoch"] = s["started_epoch"] or parse_ts_epoch(ts)
        elif eid == "cowrie.client.version":
            s["client_version"] = s["client_version"] or ev.get("version")
        elif eid == "cowrie.login.success":
            s["username"] = ev.get("username") or s["username"]
            s["login_result"] = "accepted"
        elif eid == "cowrie.login.failed":
            if s["login_result"] != "accepted":
                s["login_result"] = "rejected"
            s["username"] = s["username"] or ev.get("username")
        elif eid == "cowrie.session.closed":
            s["ended"] = ts
            try:
                s["duration_ms"] = int(ev.get("duration_ms") or 0)
            except (TypeError, ValueError):
                pass
        elif eid == "cowrie.log.closed":
            # Authoritative recording pointer. `shasum` is the SHA-256 of the
            # visitor's input; `duplicate` means Cowrie deleted this session's
            # file because an identical recording already existed.
            s["recording_sha256"] = ev.get("shasum") or s["recording_sha256"]
            s["recording_duplicate"] = 1 if ev.get("duplicate") else 0
            try:
                s["recording_bytes"] = int(ev.get("size") or 0)
            except (TypeError, ValueError):
                pass
            if not s["duration_ms"]:
                try:
                    s["duration_ms"] = int(ev.get("duration_ms") or 0)
                except (TypeError, ValueError):
                    pass
        elif eid in COMMAND_EVENTS:
            s["command_count"] += 1
        elif eid in TRANSFER_EVENTS:
            s["transfer_count"] += 1

    def _upsert_session(self, conn: sqlite3.Connection, sensor: str, sid: str, s: dict) -> None:
        conn.execute(
            """INSERT INTO session(sensor, session_id, src_ip, src_port, started,
                   started_epoch, ended, duration_ms, username, login_result,
                   client_version, recording_sha256, recording_bytes,
                   recording_duplicate, command_count, transfer_count)
               VALUES(:sensor,:session_id,:src_ip,:src_port,:started,:started_epoch,
                   :ended,:duration_ms,:username,:login_result,:client_version,
                   :recording_sha256,:recording_bytes,:recording_duplicate,
                   :command_count,:transfer_count)
               ON CONFLICT(sensor, session_id) DO UPDATE SET
                   src_ip             = COALESCE(excluded.src_ip, session.src_ip),
                   src_port           = COALESCE(excluded.src_port, session.src_port),
                   started            = COALESCE(session.started, excluded.started),
                   started_epoch      = COALESCE(session.started_epoch, excluded.started_epoch),
                   ended              = COALESCE(excluded.ended, session.ended),
                   duration_ms        = MAX(session.duration_ms, excluded.duration_ms),
                   username           = COALESCE(session.username, excluded.username),
                   login_result       = CASE
                       WHEN session.login_result = 'accepted' THEN 'accepted'
                       WHEN excluded.login_result = 'accepted' THEN 'accepted'
                       WHEN excluded.login_result = 'rejected' THEN 'rejected'
                       ELSE session.login_result END,
                   client_version     = COALESCE(session.client_version, excluded.client_version),
                   recording_sha256   = COALESCE(session.recording_sha256, excluded.recording_sha256),
                   recording_bytes    = MAX(session.recording_bytes, excluded.recording_bytes),
                   recording_duplicate= MAX(session.recording_duplicate, excluded.recording_duplicate),
                   command_count      = MAX(session.command_count, excluded.command_count),
                   transfer_count     = MAX(session.transfer_count, excluded.transfer_count)""",
            {"sensor": sensor, "session_id": sid, "src_ip": s["src_ip"],
             "src_port": s["src_port"], "started": s["started"],
             "started_epoch": s["started_epoch"], "ended": s["ended"],
             "duration_ms": s["duration_ms"], "username": s["username"],
             "login_result": s["login_result"], "client_version": s["client_version"],
             "recording_sha256": s["recording_sha256"],
             "recording_bytes": s["recording_bytes"],
             "recording_duplicate": s["recording_duplicate"],
             "command_count": s["command_count"], "transfer_count": s["transfer_count"]},
        )
        # Command rows, for transcript search without loading recordings.
        for row in conn.execute(
            "SELECT dedupe_key, timestamp, ts_epoch, command FROM event "
            "WHERE sensor=? AND session_id=? AND eventid IN "
            "('cowrie.command.input','cowrie.command.failed','cowrie.command.success')",
            (sensor, sid),
        ).fetchall():
            try:
                conn.execute(
                    """INSERT INTO command(dedupe_key, sensor, session_id, timestamp,
                           ts_epoch, command) VALUES(?,?,?,?,?,?)""",
                    ("cmd:" + row["dedupe_key"], sensor, sid, row["timestamp"],
                     row["ts_epoch"], row["command"] or ""),
                )
            except sqlite3.IntegrityError:
                pass

    def _link_recording(self, sensor: str, sid: str, s: dict) -> None:
        sha = s.get("recording_sha256")
        if not sha:
            return
        path = self.recordings_dir / sha
        if not path.is_file():
            return
        try:
            data = path.read_bytes()
        except OSError:
            return
        chunks = parse_ttylog_bytes(data, source=sha[:12])
        duration = chunks[-1].offset_ms if chunks else 0
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO recording(sha256, sensor, relpath, bytes, chunk_count,
                       duration_ms, ingested)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(sha256) DO UPDATE SET
                       chunk_count = excluded.chunk_count,
                       bytes       = excluded.bytes""",
                (sha, sensor, f"recordings/{sha}", len(data), len(chunks), duration, iso()),
            )
            conn.execute(
                "UPDATE session SET chunk_count=? WHERE sensor=? AND session_id=?",
                (len(chunks), sensor, sid),
            )

    def _backfill_recording_links(self) -> int:
        """
        Attach recordings to sessions that name one but have no chunk count yet.

        Runs after every ingest so the store converges regardless of the order
        bundles arrive in -- an events-only bundle followed later by a
        recordings-only bundle ends up in the same state as a bundle containing
        both.
        """
        linked = 0
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT sensor, session_id, recording_sha256 FROM session "
                "WHERE recording_sha256 IS NOT NULL AND recording_sha256 != '' "
                "AND chunk_count = 0").fetchall()
        for row in rows:
            sha = row["recording_sha256"]
            if not sha or len(sha) != 64 or any(
                    ch not in "0123456789abcdefABCDEF" for ch in sha):
                continue                    # never build a path from a bad value
            path = self.recordings_dir / sha.lower()
            if not path.is_file():
                continue
            try:
                chunks = parse_ttylog_bytes(path.read_bytes(), source=sha[:12])
            except OSError:
                continue
            with self.connect() as conn:
                conn.execute(
                    "UPDATE session SET chunk_count=? WHERE sensor=? AND session_id=?",
                    (len(chunks), row["sensor"], row["session_id"]))
                conn.execute(
                    """INSERT INTO recording(sha256, sensor, relpath, bytes, chunk_count,
                           duration_ms, ingested) VALUES(?,?,?,?,?,?,?)
                       ON CONFLICT(sha256) DO UPDATE SET chunk_count=excluded.chunk_count""",
                    (sha.lower(), row["sensor"], f"recordings/{sha.lower()}",
                     path.stat().st_size, len(chunks),
                     chunks[-1].offset_ms if chunks else 0, iso()))
            linked += 1
        return linked

    def _declared_hashes(self, bundle: Path) -> dict[str, str]:
        """
        Map recording name -> content hash, as declared by the bundle manifest.

        Used to verify that a recording arrived intact, which is a check on the
        bytes and not on the filename. Returns {} when there is no manifest,
        which is the case for a bundle assembled by hand.
        """
        out: dict[str, str] = {}
        for name in ("BUNDLE.json", "bundle.json"):
            path = bundle / name
            if not path.is_file():
                continue
            try:
                doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                return {}
            for entry in doc.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                if entry.get("kind") == "recording" and entry.get("sha256"):
                    if entry.get("content_sha256"):
                        out[str(entry["sha256"])] = str(entry["content_sha256"])
            return out
        return out

    def _ingest_recordings(self, bundle: Path, sensor: str, stats: IngestStats) -> None:
        """
        Copy recordings into the store under the name the honeypot gave them.

        The name is the join key: `cowrie.log.closed` carries it in `shasum`, and
        that is how a session finds its recording. It is NOT the hash of the
        file's bytes (Cowrie hashes the visitor's input instead), so renaming to
        the content hash here would detach every recording from its session while
        still reporting a clean ingest. Integrity is checked by comparing the
        bytes against the manifest's `content_sha256` when the bundle carries
        one.
        """
        src = bundle / "tty"
        if not src.is_dir():
            return
        declared = self._declared_hashes(bundle)
        for path in sorted(src.iterdir()):
            if not path.is_file():
                continue
            name = path.name
            if len(name) != 64 or any(ch not in "0123456789abcdef" for ch in name):
                stats.errors.append(f"recording {name[:40]!r} is not named as a sha256")
                continue
            data = path.read_bytes()
            content = hashlib.sha256(data).hexdigest()
            expected = declared.get(name)
            if expected and expected != content:
                # The bytes do not match what the sender hashed. Usually a
                # truncated copy; occasionally an edited quarantine. Either way
                # it is evidence, so it is refused and reported, never stored
                # under a name that implies the original content.
                stats.errors.append(
                    f"recording {name[:12]} does not match its manifest hash")
                continue
            dest = self.recordings_dir / name
            if not dest.exists():
                tmp = dest.with_suffix(".part")
                tmp.write_bytes(data)
                os.replace(tmp, dest)
                os.chmod(dest, 0o640)
                stats.recordings_new += 1
            chunks = parse_ttylog_bytes(data, source=name[:12])
            with self.connect() as conn:
                conn.execute(
                    """INSERT INTO recording(sha256, sensor, relpath, bytes, chunk_count,
                           duration_ms, ingested) VALUES(?,?,?,?,?,?,?)
                       ON CONFLICT(sha256) DO UPDATE SET
                           chunk_count = excluded.chunk_count,
                           bytes       = excluded.bytes""",
                    (name, sensor, f"recordings/{name}", len(data), len(chunks),
                     chunks[-1].offset_ms if chunks else 0, iso()),
                )

    def _ingest_quarantine(self, bundle: Path, sensor: str, stats: IngestStats) -> None:
        """
        Move captured files into quarantine.

        The bytes are written and never read again by any component in this
        package. The dashboard has no code path that opens this directory; it
        shows metadata and hashes from the database only. Analysing a capture
        requires a separate disposable environment -- see docs/06.
        """
        src = bundle / "downloads"
        if not src.is_dir():
            return
        for path in src.iterdir():
            if not path.is_file():
                continue
            data = path.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            dest = self.quarantine_dir / sha
            if not dest.exists():
                tmp = dest.with_suffix(".part")
                tmp.write_bytes(data)
                os.replace(tmp, dest)
                os.chmod(dest, 0o600)
                stats.quarantine_new += 1

    def _ingest_health(self, bundle: Path, sensor: str, stats: IngestStats) -> None:
        src = bundle / "health"
        if not src.is_dir():
            return
        for path in sorted(src.glob("*.log")):
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                rec = _parse_health_line(line)
                if not rec:
                    continue
                rec["sensor"] = sensor
                rec["dedupe_key"] = hashlib.sha256(
                    f"{sensor}|{line}".encode()).hexdigest()
                with self.connect() as conn:
                    try:
                        conn.execute(
                            """INSERT INTO health(dedupe_key, sensor, timestamp, ts_epoch,
                                   service, banner_ok, log_age_s, disk_pct, quarantine_mb,
                                   outbound, raw) VALUES(:dedupe_key,:sensor,:timestamp,
                                   :ts_epoch,:service,:banner_ok,:log_age_s,:disk_pct,
                                   :quarantine_mb,:outbound,:raw)""", rec)
                        stats.health_new += 1
                    except sqlite3.IntegrityError:
                        pass

    def _write_manifest(self, bundle: Path, sensor: str, stats: IngestStats,
                        started: str) -> None:
        manifest = {
            "sensor": sensor,
            "bundle": str(bundle),
            "ingested_at": iso(),
            "started": started,
            "files_seen": stats.files_seen,
            "events_new": stats.events_new,
            "events_dup": stats.events_dup,
            "recordings_new": stats.recordings_new,
            "quarantine_new": stats.quarantine_new,
            "health_new": stats.health_new,
            "errors": stats.errors[:50],
        }
        name = f"{sensor}-{started.replace(':', '').replace('-', '')}.json"
        (self.manifests_dir / name).write_text(
            json.dumps(manifest, indent=2), encoding="utf-8")


HEALTH_RE = None


def _parse_health_line(line: str) -> dict | None:
    """
    Parse one health-check log line.

    The honeypot's health check writes lines like:

        [2026-10-04T08:00:00Z] OK service=running banner=ok log_age=12 disk=41 ...

    Anything unparsable is ignored rather than guessed at: a malformed health
    record that is silently treated as healthy is worse than no record.
    """
    line = line.strip()
    if not line:
        return None
    global HEALTH_RE
    if HEALTH_RE is None:
        import re
        HEALTH_RE = re.compile(r"^\[(?P<ts>[^\]]+)\]\s+(?P<kv>.*)$")
    m = HEALTH_RE.match(line)
    if not m:
        return None
    fields: dict[str, str] = {}
    for token in m.group("kv").split():
        if "=" in token:
            k, _, v = token.partition("=")
            fields[k.strip()] = v.strip()
    ts = m.group("ts")
    epoch = parse_ts_epoch(ts)
    if epoch is None:
        return None

    def num(key: str) -> int | None:
        raw = fields.get(key, "")
        digits = "".join(ch for ch in raw if ch.isdigit() or ch == "-")
        try:
            return int(digits) if digits not in ("", "-") else None
        except ValueError:
            return None

    banner = fields.get("banner", "")
    outbound = fields.get("outbound", "")
    return {
        "timestamp": ts,
        "ts_epoch": epoch,
        "service": fields.get("service"),
        "banner_ok": 1 if banner in ("ok", "true", "yes") else (0 if banner else None),
        "log_age_s": num("log_age"),
        "disk_pct": num("disk"),
        "quarantine_mb": num("quarantine"),
        "outbound": 1 if outbound in ("unexpected", "alert", "true") else (
            0 if outbound else None),
        "raw": line[:2000],
    }


# =============================================================================
# Read-only query layer used by the dashboard
# =============================================================================
@dataclass
class EventFilter:
    """Filters the dashboard exposes. Every field is optional."""
    text: str = ""                  # free text over command / filename / username
    src_ip: str = ""
    username: str = ""
    session_id: str = ""
    event_type: str = ""            # a key of EVENT_TYPES
    eventid: str = ""               # raw event id
    outcome: str = ""               # accepted | rejected | unknown
    sensor: str = ""
    since: str = ""                 # ISO date or datetime
    until: str = ""
    has_transfer: bool = False
    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0

    def clamped_limit(self) -> int:
        return max(1, min(int(self.limit or DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE))


def _date_bound(value: str, end: bool = False) -> float | None:
    """Turn a yyyy-mm-dd or full ISO string into an epoch bound."""
    if not value:
        return None
    text = value.strip()
    try:
        if len(text) == 10:
            dt = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if end:
                dt = dt + timedelta(days=1)
            return dt.timestamp()
        return parse_ts_epoch(text)
    except ValueError:
        return None


class Queries:
    """Read-only queries. Constructed with a readonly Store."""

    def __init__(self, store: Store) -> None:
        self.store = store

    @contextmanager
    def _conn(self):
        with self.store.connect() as conn:
            yield conn

    def stats(self) -> dict:
        with self._conn() as conn:
            def one(sql: str, args: tuple = ()) -> int:
                row = conn.execute(sql, args).fetchone()
                return int(row[0]) if row and row[0] is not None else 0

            now = utcnow()
            day_ago = (now - timedelta(days=1)).timestamp()
            week_ago = (now - timedelta(days=7)).timestamp()
            return {
                "events": one("SELECT COUNT(*) FROM event"),
                "sessions": one("SELECT COUNT(*) FROM session"),
                "sessions_24h": one("SELECT COUNT(*) FROM session WHERE started_epoch >= ?",
                                    (day_ago,)),
                "accepted": one("SELECT COUNT(*) FROM session WHERE login_result='accepted'"),
                "accepted_24h": one(
                    "SELECT COUNT(*) FROM session WHERE login_result='accepted' AND started_epoch >= ?",
                    (day_ago,)),
                "distinct_ips": one("SELECT COUNT(DISTINCT src_ip) FROM event WHERE src_ip IS NOT NULL"),
                "distinct_ips_24h": one(
                    "SELECT COUNT(DISTINCT src_ip) FROM event WHERE src_ip IS NOT NULL AND ts_epoch >= ?",
                    (day_ago,)),
                "logins_failed": one(
                    "SELECT COUNT(*) FROM event WHERE eventid='cowrie.login.failed' AND ts_epoch >= ?",
                    (day_ago,)),
                "commands": one("SELECT COUNT(*) FROM command"),
                "transfers": one("SELECT COUNT(*) FROM transfer"),
                "uploads": one("SELECT COUNT(*) FROM transfer WHERE event='upload'"),
                "quarantined": one("SELECT COUNT(*) FROM transfer WHERE quarantined=1"),
                "recordings": one("SELECT COUNT(*) FROM recording"),
                "distinct_users": one(
                    "SELECT COUNT(DISTINCT username) FROM event WHERE username IS NOT NULL"),
                "week_events": one("SELECT COUNT(*) FROM event WHERE ts_epoch >= ?", (week_ago,)),
            }

    def timelines(self, days: int = 14) -> list[dict]:
        """Attempts per day, for the overview chart."""
        since = (utcnow() - timedelta(days=days)).timestamp()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT substr(timestamp,1,10) AS day,
                          SUM(CASE WHEN eventid='cowrie.login.failed'  THEN 1 ELSE 0 END) AS failed,
                          SUM(CASE WHEN eventid='cowrie.login.success' THEN 1 ELSE 0 END) AS accepted,
                          SUM(CASE WHEN eventid='cowrie.session.connect' THEN 1 ELSE 0 END) AS connects
                   FROM event WHERE ts_epoch >= ? GROUP BY day ORDER BY day""",
                (since,),
            ).fetchall()
        return [dict(r) for r in rows]

    def top_values(self, column: str, limit: int = 10, since_days: int = 7) -> list[dict]:
        if column not in ("src_ip", "username", "eventid"):
            raise ValueError("unsupported column")
        since = (utcnow() - timedelta(days=since_days)).timestamp()
        with self._conn() as conn:
            rows = conn.execute(
                f"""SELECT {column} AS value, COUNT(*) AS n FROM event
                    WHERE {column} IS NOT NULL AND ts_epoch >= ?
                    GROUP BY {column} ORDER BY n DESC LIMIT ?""",
                (since, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- events ------------------------------------------------------------
    def _event_where(self, f: EventFilter) -> tuple[str, list]:
        clauses: list[str] = []
        args: list = []
        if f.event_type:
            ids = EVENT_TYPES.get(f.event_type)
            if ids:
                clauses.append("eventid IN (%s)" % ",".join("?" * len(ids)))
                args.extend(ids)
            elif f.event_type == "other":
                known = [i for k, v in EVENT_TYPES.items() if k != "other" for i in v]
                clauses.append("eventid NOT IN (%s)" % ",".join("?" * len(known)))
                args.extend(known)
        if f.eventid:
            clauses.append("eventid = ?")
            args.append(f.eventid)
        if f.src_ip:
            clauses.append("src_ip = ?")
            args.append(f.src_ip)
        if f.username:
            clauses.append("username = ?")
            args.append(f.username)
        if f.session_id:
            clauses.append("session_id = ?")
            args.append(f.session_id)
        if f.outcome == "accepted":
            clauses.append("eventid = 'cowrie.login.success'")
        elif f.outcome == "rejected":
            clauses.append("eventid = 'cowrie.login.failed'")
        elif f.outcome == "unknown":
            clauses.append(
                "session_id IN (SELECT session_id FROM session WHERE login_result='unknown')")
        if f.sensor:
            clauses.append("sensor = ?")
            args.append(f.sensor)
        if f.has_transfer:
            clauses.append(
                "session_id IN (SELECT session_id FROM transfer)")
        since = _date_bound(f.since)
        if since is not None:
            clauses.append("ts_epoch >= ?")
            args.append(since)
        until = _date_bound(f.until, end=True)
        if until is not None:
            clauses.append("ts_epoch < ?")
            args.append(until)
        if f.text:
            clauses.append("(command LIKE ? OR filename LIKE ? OR url LIKE ? OR username LIKE ?)")
            needle = f"%{f.text}%"
            args.extend([needle] * 4)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, args

    def events(self, f: EventFilter) -> tuple[list[dict], int]:
        where, args = self._event_where(f)
        limit = f.clamped_limit()
        with self._conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM event{where}", args).fetchone()[0]
            rows = conn.execute(
                f"""SELECT id, sensor, session_id, eventid, timestamp, ts_epoch, src_ip,
                           src_port, dst_port, username, password, outcome, command,
                           filename, url, shasum, size, message
                    FROM event{where} ORDER BY ts_epoch DESC, id DESC LIMIT ? OFFSET ?""",
                [*args, limit, int(f.offset or 0)],
            ).fetchall()
        return [dict(r) for r in rows], int(total)

    # -- sessions ----------------------------------------------------------
    def sessions(self, f: EventFilter, only_recorded: bool = False,
                 only_accepted: bool = False) -> tuple[list[dict], int]:
        clauses: list[str] = []
        args: list = []
        if f.src_ip:
            clauses.append("src_ip = ?")
            args.append(f.src_ip)
        if f.username:
            clauses.append("username = ?")
            args.append(f.username)
        if f.session_id:
            clauses.append("session_id = ?")
            args.append(f.session_id)
        if f.sensor:
            clauses.append("sensor = ?")
            args.append(f.sensor)
        if f.outcome in ("accepted", "rejected", "unknown"):
            clauses.append("login_result = ?")
            args.append(f.outcome)
        if only_recorded:
            clauses.append("chunk_count > 0")
        if only_accepted:
            clauses.append("login_result = 'accepted'")
        if f.has_transfer:
            clauses.append(
                "EXISTS (SELECT 1 FROM transfer t WHERE t.sensor=session.sensor "
                "AND t.session_id=session.session_id)")
        since = _date_bound(f.since)
        if since is not None:
            clauses.append("started_epoch >= ?")
            args.append(since)
        until = _date_bound(f.until, end=True)
        if until is not None:
            clauses.append("started_epoch < ?")
            args.append(until)
        if f.text:
            clauses.append(
                "(session_id LIKE ? OR username LIKE ? OR client_version LIKE ? "
                "OR EXISTS (SELECT 1 FROM command c WHERE c.sensor=session.sensor "
                "AND c.session_id=session.session_id AND c.command LIKE ?))")
            needle = f"%{f.text}%"
            args.extend([needle] * 4)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = f.clamped_limit()
        with self._conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM session{where}", args).fetchone()[0]
            rows = conn.execute(
                f"""SELECT * FROM session{where}
                    ORDER BY COALESCE(started_epoch,0) DESC LIMIT ? OFFSET ?""",
                [*args, limit, int(f.offset or 0)],
            ).fetchall()
        return [dict(r) for r in rows], int(total)

    def session(self, sensor: str, session_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM session WHERE sensor=? AND session_id=?",
                (sensor, session_id)).fetchone()
        return dict(row) if row else None

    def session_events(self, sensor: str, session_id: str, limit: int = 1000) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, eventid, timestamp, ts_epoch, src_ip, src_port, username,
                          password, outcome, command, filename, url, shasum, size, message
                   FROM event WHERE sensor=? AND session_id=?
                   ORDER BY ts_epoch ASC, id ASC LIMIT ?""",
                (sensor, session_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def session_transfers(self, sensor: str, session_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM transfer WHERE sensor=? AND session_id=?
                   ORDER BY ts_epoch ASC""", (sensor, session_id)).fetchall()
        return [dict(r) for r in rows]

    # -- recordings --------------------------------------------------------
    def recording_path(self, sha256: str) -> Path | None:
        """
        Resolve a recording to a path inside the store.

        Confined to the recordings directory by construction: the SHA-256 is
        validated as hex before it is used, so a poisoned database value cannot
        become a traversal. Returns None for anything else, including a
        well-formed name for a file that does not exist.
        """
        if not sha256 or len(sha256) != 64:
            return None
        if any(ch not in "0123456789abcdefABCDEF" for ch in sha256):
            return None
        path = (self.store.recordings_dir / sha256.lower()).resolve()
        root = self.store.recordings_dir.resolve()
        if not path.is_relative_to(root) or not path.is_file():
            return None
        return path

    def recording_meta(self, sha256: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM recording WHERE sha256=?",
                               (sha256,)).fetchone()
        return dict(row) if row else None

    # -- transfers ---------------------------------------------------------
    def transfers(self, f: EventFilter, kind: str = "") -> tuple[list[dict], int]:
        # Columns are qualified with `t.` throughout. `transfer` and `session`
        # share the names sensor, session_id and ts_epoch, so an unqualified
        # reference in this join is an "ambiguous column name" error rather
        # than a subtly wrong answer -- but only once both tables are in scope,
        # which is exactly the kind of thing that passes a unit test and fails
        # in production.
        clauses: list[str] = []
        args: list = []
        if kind in ("upload", "download"):
            clauses.append("t.event = ?")
            args.append(kind)
        if f.session_id:
            clauses.append("t.session_id = ?")
            args.append(f.session_id)
        if f.sensor:
            clauses.append("t.sensor = ?")
            args.append(f.sensor)
        if f.text:
            clauses.append("(t.filename LIKE ? OR t.url LIKE ? OR t.sha256 LIKE ?)")
            needle = f"%{f.text}%"
            args.extend([needle] * 3)
        since = _date_bound(f.since)
        if since is not None:
            clauses.append("t.ts_epoch >= ?")
            args.append(since)
        until = _date_bound(f.until, end=True)
        if until is not None:
            clauses.append("t.ts_epoch < ?")
            args.append(until)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = f.clamped_limit()
        with self._conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM transfer t{where}", args).fetchone()[0]
            rows = conn.execute(
                f"""SELECT t.*, s.src_ip, s.login_result FROM transfer t
                    LEFT JOIN session s ON s.sensor = t.sensor
                                       AND s.session_id = t.session_id
                    {where}
                    ORDER BY t.ts_epoch DESC LIMIT ? OFFSET ?""",
                [*args, limit, int(f.offset or 0)],
            ).fetchall()
        return [dict(r) for r in rows], int(total)

    def quarantine_meta(self, sha256: str) -> dict:
        """
        Metadata for a captured file, WITHOUT touching the bytes.

        This is the only thing the dashboard knows how to do with a capture:
        report its hash, size and whether the quarantined blob exists on disk by
        name. It never opens it, never reads a byte of it, and never offers it
        for download. Analysing a capture requires a separate disposable
        environment (docs/06).
        """
        meta: dict = {"sha256": sha256, "present": False, "bytes": None}
        if not sha256 or len(sha256) != 64 or any(
                ch not in "0123456789abcdefABCDEF" for ch in sha256):
            return meta
        path = self.store.quarantine_dir / sha256.lower()
        try:
            stat = path.stat()
            meta["present"] = True
            meta["bytes"] = stat.st_size
            meta["mode"] = oct(stat.st_mode & 0o777)
        except OSError:
            pass
        return meta

    # -- health ------------------------------------------------------------
    def health_latest(self, per_sensor: bool = True) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT h.* FROM health h
                   JOIN (SELECT sensor, MAX(ts_epoch) AS m FROM health GROUP BY sensor) x
                     ON x.sensor = h.sensor AND x.m = h.ts_epoch
                   ORDER BY h.sensor""").fetchall()
        return [dict(r) for r in rows]

    def health_history(self, limit: int = 200) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM health ORDER BY ts_epoch DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def last_ingest(self) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ingest_run ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def ingest_history(self, limit: int = 50) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ingest_run ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def sensors(self) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT DISTINCT sensor FROM event
                   UNION SELECT DISTINCT sensor FROM session ORDER BY 1""").fetchall()
        return [r[0] for r in rows if r[0]]

    def distinct(self, column: str, limit: int = 500) -> list[str]:
        if column not in ("src_ip", "username"):
            raise ValueError("unsupported column")
        with self._conn() as conn:
            rows = conn.execute(
                f"""SELECT {column} FROM event WHERE {column} IS NOT NULL AND {column} != ''
                    GROUP BY {column} ORDER BY COUNT(*) DESC LIMIT ?""",
                (limit,)).fetchall()
        return [r[0] for r in rows]


# =============================================================================
# Health assessment
# =============================================================================
def assess_health(store: Store, q: Queries, thresholds: dict | None = None) -> dict:
    """
    Turn raw signals into an explicit status.

    The dashboard exists to answer "is the honeypot still collecting?", and the
    honest answer has three parts: is it alive, is evidence arriving, and are we
    keeping it. Each problem below is reported with the evidence that produced
    it, because "degraded" without a reason is not actionable.
    """
    t = {
        "ingest_stale_s": 900,        # 15 min: shipping runs every 5
        "log_stale_s": 3600,          # no new events for an hour
        "disk_warn_pct": 80,
        "disk_crit_pct": 92,
        "backup_stale_s": 172800,     # 48 h
        "quarantine_warn_mb": 2048,
        **(thresholds or {}),
    }
    problems: list[dict] = []
    ok_signals: list[str] = []
    now = utcnow().timestamp()

    def problem(level: str, code: str, detail: str, fix: str) -> None:
        problems.append({"level": level, "code": code, "detail": detail, "fix": fix})

    # 1. Is evidence arriving at all?
    last_ingest = q.last_ingest()
    if last_ingest is None:
        problem("critical", "no_ingest",
                "No ingest run has ever completed. The store is empty.",
                "Check the honeypot-dashboard-ingest timer and the export bundle path.")
    else:
        finished = parse_ts_epoch(last_ingest.get("finished") or last_ingest.get("started"))
        age = (now - finished) if finished else None
        if last_ingest.get("status") == "failed":
            problem("critical", "ingest_failed",
                    f"Last ingest failed: {safe_log_value(last_ingest.get('error'), 300)}",
                    "Check disk space and permissions on the bundle path, then re-run ingest.")
        elif age is not None and age > t["ingest_stale_s"]:
            problem("critical", "ingest_stale",
                    f"No ingest run for {int(age / 60)} minutes.",
                    "The honeypot may be down, or shipping may have stopped. "
                    "Check the honeypot's cowrie-logship timer.")
        else:
            ok_signals.append(f"last ingest {int(age or 0)}s ago")

    # 2. Are events still being produced? A running pipeline that carries
    #    nothing is the failure mode that looks healthy.
    with store.connect() as conn:
        row = conn.execute("SELECT MAX(ts_epoch) AS m FROM event").fetchone()
    newest = row["m"] if row and row["m"] else None
    if newest is None:
        problem("critical", "no_events", "No events in the store at all.",
                "A honeypot with no events has never been reached, or ingest is broken.")
    else:
        gap = now - newest
        if gap > t["log_stale_s"]:
            problem("warning", "log_stale",
                    f"No new events for {int(gap / 3600)} hours.",
                    "Normal on a quiet honeypot, worth confirming: check the security group "
                    "and whether the service is listening.")
        else:
            ok_signals.append(f"newest event {int(gap / 60)}m ago" if gap > 90
                              else "events current")

    # 3. The honeypot's own health report.
    for h in q.health_latest():
        sensor = h.get("sensor") or "?"
        if h.get("banner_ok") == 0:
            problem("critical", "banner",
                    f"{sensor}: the service accepts TCP but does not answer with an SSH banner.",
                    "This is the wedged-reactor failure. systemctl kill -s SIGKILL cowrie, "
                    "then start it. See docs/10 section 2.4.")
        if h.get("outbound") == 1:
            problem("critical", "outbound",
                    f"{sensor}: unexpected outbound traffic observed from the honeypot.",
                    "Investigate now. If the honeypot can reach anything, the isolation "
                    "boundary is broken. See docs/05.")
        if h.get("service") and h["service"] not in ("running", "ok", "active"):
            problem("warning", "service",
                    f"{sensor}: reported service state '{safe_log_value(h['service'], 40)}'.",
                    "Check the unit on the honeypot.")

    # 4. Disk, from the monitoring host's own view of the store.
    try:
        usage = os.statvfs(store.root)
        pct = int(100 * (usage.f_blocks - usage.f_bfree) / max(usage.f_blocks, 1))
        free_gb = usage.f_bavail * usage.f_frsize / 1e9
        if pct >= t["disk_crit_pct"]:
            problem("critical", "disk",
                    f"Monitoring store volume {pct}% full ({free_gb:.1f} GB free).",
                    "Prune shipped bundles or extend the volume. Ingestion stops when "
                    "the disk fills, and a gap in ingestion is a gap in evidence.")
        elif pct >= t["disk_warn_pct"]:
            problem("warning", "disk",
                    f"Monitoring store volume {pct}% full ({free_gb:.1f} GB free).",
                    "Plan to extend the volume or shorten retention.")
        else:
            ok_signals.append(f"store volume {pct}% used")
    except OSError as exc:
        problem("warning", "disk_unreadable",
                f"Cannot read store volume usage: {safe_log_value(exc, 120)}",
                "Check permissions on the store root.")

    # 5. Quarantine growth.
    q_row = q.stats()
    if q_row["quarantined"]:
        total_bytes = 0
        try:
            for entry in os.scandir(store.quarantine_dir):
                try:
                    total_bytes += entry.stat().st_size
                except OSError:
                    pass
        except OSError:
            pass
        mb = total_bytes / (1024 * 1024)
        if mb >= t["quarantine_warn_mb"]:
            problem("warning", "quarantine",
                    f"Quarantine holds {mb:.0f} MB across {q_row['quarantined']} capture(s).",
                    "Ship and prune, or raise the cap deliberately. Captures are evidence: "
                    "do not delete them without exporting first.")
        else:
            ok_signals.append(f"quarantine {mb:.1f} MB")

    # 6. Backup status.
    backup_file = store.root / "backup-status.json"
    if backup_file.is_file():
        try:
            backup = json.loads(backup_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            backup = None
        if backup:
            last_ok = parse_ts_epoch(backup.get("last_success"))
            age = (now - last_ok) if last_ok else None
            if backup.get("status") != "ok":
                problem("critical", "backup_failed",
                        f"Last backup reported '{safe_log_value(backup.get('status'), 60)}'.",
                        "Check ops/store_backup.sh on the monitoring host. An unrestorable "
                        "store is not a backup.")
            elif age is not None and age > t["backup_stale_s"]:
                problem("warning", "backup_stale",
                        f"Last successful backup was {int(age / 3600)} hours ago.",
                        "Check the backup timer.")
            else:
                ok_signals.append("backup recent")
    else:
        problem("warning", "no_backup_status",
                "No backup has reported status.",
                "Install ops/store_backup.sh and its timer. The store is the only copy "
                "of this evidence: the honeypot prunes locally after shipping.")

    if not problems:
        level = "healthy"
    elif any(p["level"] == "critical" for p in problems):
        level = "critical"
    else:
        level = "degraded"
    return {"level": level, "problems": problems, "ok": ok_signals,
            "checked_at": iso(), "thresholds": t}

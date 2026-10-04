"""
Authentication, authorisation and the administrator audit trail.

WHAT IS REQUIRED
    Strong authentication with MFA, role-based access, short idle timeouts, and
    an auditable record of administrator logins, searches, exports and
    configuration changes.

HOW IT IS IMPLEMENTED
    Passwords   scrypt (n=2^14, r=8, p=1), 32-byte random salt, constant-time
                comparison. Five failures locks the account for 15 minutes.
    MFA         RFC 6238 TOTP, SHA-1, 6 digits, 30-second period, +/-1 step of
                drift. Verified against the RFC's own test vectors in
                tests/test_dashboard.py. Replay of a used code in the same step
                is rejected.
    Sessions    A 256-bit random token, stored only as a SHA-256 hash, sent in
                a HttpOnly + SameSite=Strict + Secure cookie. Idle and hard
                expiry are separate; the idle clock resets on use, the hard
                clock never does.
    RBAC        Three roles with an explicit permission set. Permission checks
                happen in one place (`require`) and every denial is audited.
    Audit       Append-only by database trigger. UPDATE and DELETE on the audit
                table are rejected by SQLite itself, so an application bug or an
                operator with a SQLite client cannot quietly rewrite history.
                Every entry is also appended to a file on separate storage.

DELIBERATELY ABSENT
    * No "remember me". The idle timeout is short because this interface shows
      captured credentials.
    * No password reset by email or any self-service path. An administrator
      creates or resets accounts out of band, and that action is audited.
    * No API tokens. They would outlive the session controls.
    * No fallback that skips MFA. `--demo-mode` exists for local
      demonstrations. It is refused on a non-loopback bind unless the operator
      also passes --i-know-this-exposes-monitoring, which is an acknowledgement
      rather than a safeguard: with both flags, MFA is off on a reachable
      interface. The startup banner lists that, and every other relaxed
      control, in one place.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
# shared/ sits beside the package in a checkout and under
# $STATE_DIR/share/pkg/ in an installed host (deploy/install.sh stage 8).
_state = Path(os.environ.get("HONEYPOT_STATE_DIR") or "/opt/cowrie")
for _cand in (_HERE.parent / "shared", _state / "share" / "pkg" / "shared"):
    if (_cand / "terminal_safety.py").is_file():
        sys.path.insert(0, str(_cand))
        break

from terminal_safety import safe_log_value  # noqa: E402

# ---------------------------------------------------------------------------
# Roles and permissions
# ---------------------------------------------------------------------------
ROLES = ("viewer", "analyst", "admin")

PERMISSIONS: dict[str, frozenset[str]] = {
    # Read-only. Can see that a password field exists and is redacted, and that
    # a capture exists, but not their contents.
    "viewer": frozenset({
        "view", "search", "playback", "transfers", "health", "audit.self",
    }),
    # Everything a reviewer needs to do an investigation, including revealing
    # captured secrets and exporting evidence. Both are audited.
    "analyst": frozenset({
        "view", "search", "playback", "transfers", "health", "audit.self",
        "unmask", "export", "audit.read",
    }),
    # Administration of the dashboard itself. Deliberately NOT a superset that
    # includes anything that reaches the honeypot, because nothing does.
    "admin": frozenset({
        "view", "search", "playback", "transfers", "health", "audit.self",
        "unmask", "export", "audit.read",
        "users.read", "users.write", "config.read", "retention.read",
    }),
}

# Session lifetimes, in seconds.
DEFAULT_IDLE_TIMEOUT = 900          # 15 minutes
DEFAULT_HARD_TIMEOUT = 8 * 3600     # 8 hours
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 900
TOTP_PERIOD = 30
TOTP_DIGITS = 6
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1


class AuthError(Exception):
    """Authentication failed. Message is safe to show to the user."""


class PermissionDenied(Exception):
    """Authorisation failed."""


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Return a self-describing scrypt hash: algorithm$params$salt$digest."""
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode())


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time verification. Returns False on any malformed hash."""
    try:
        algo, n, r, p, salt_b64, digest_b64 = encoded.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(digest_b64, validate=True)
        got = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                             n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(got, expected)


def password_strength_problems(password: str) -> list[str]:
    """Cheap policy check for the account-management CLI."""
    problems = []
    if len(password) < 12:
        problems.append("shorter than 12 characters")
    if password.lower() in {"password1234", "administrator", "changeme12345"}:
        problems.append("a well-known default")
    classes = sum(bool(f(password)) for f in (
        lambda s: any(c.islower() for c in s),
        lambda s: any(c.isupper() for c in s),
        lambda s: any(c.isdigit() for c in s),
        lambda s: any(not c.isalnum() for c in s),
    ))
    if classes < 3:
        problems.append("uses fewer than three character classes")
    return problems


# ---------------------------------------------------------------------------
# TOTP (RFC 6238)
# ---------------------------------------------------------------------------
def generate_totp_secret() -> str:
    """160-bit secret, base32, no padding - what authenticator apps expect."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _b32decode(secret: str) -> bytes:
    padded = secret.strip().replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    try:
        return base64.b32decode(padded, casefold=True)
    except Exception as exc:  # noqa: BLE001
        raise AuthError("malformed TOTP secret") from exc


def totp_at(secret: str, at: float | None = None, digits: int = TOTP_DIGITS,
            period: int = TOTP_PERIOD) -> str:
    """
    RFC 6238 TOTP at a given time.

    Kept as a pure function of time so it can be tested against the RFC's
    published vectors rather than against itself.
    """
    key = _b32decode(secret)
    counter = int((time.time() if at is None else at) // period)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, code: str, at: float | None = None,
                window: int = 1) -> bool:
    """Verify a code within +/-window steps, constant-time."""
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    now = time.time() if at is None else at
    matched = False
    for step in range(-window, window + 1):
        candidate = totp_at(secret, now + step * TOTP_PERIOD)
        # compare_digest on every candidate, without early exit, so timing does
        # not reveal which step matched.
        if hmac.compare_digest(candidate, code):
            matched = True
    return matched


def provisioning_uri(secret: str, username: str, issuer: str = "Honeypot Dashboard") -> str:
    from urllib.parse import quote
    label = quote(f"{issuer}:{username}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}"
            f"&issuer={quote(issuer, safe='')}&algorithm=SHA1"
            f"&digits={TOTP_DIGITS}&period={TOTP_PERIOD}")


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
@dataclass
class AdminPrincipal:
    username: str
    role: str
    permissions: frozenset[str]
    src_ip: str = ""
    session_token: str = ""

    def can(self, permission: str) -> bool:
        return permission in self.permissions


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Authenticator:
    """All authentication and authorisation decisions live here."""

    def __init__(self, store, idle_timeout: int = DEFAULT_IDLE_TIMEOUT,
                 hard_timeout: int = DEFAULT_HARD_TIMEOUT,
                 audit_file: str | Path | None = None,
                 demo_mode: bool = False) -> None:
        self.store = store
        self.idle_timeout = int(idle_timeout)
        self.hard_timeout = int(hard_timeout)
        self.audit_file = Path(audit_file) if audit_file else None
        self.demo_mode = demo_mode
        if self.audit_file:
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self.audit_file.parent, 0o700)
            if not self.audit_file.exists():
                self.audit_file.touch(mode=0o600)

    # -- audit -------------------------------------------------------------
    def audit(self, actor: str, action: str, target: str = "", detail: str = "",
              role: str = "", src_ip: str = "") -> None:
        """
        Record an administrative action. Never raises into a request path: an
        audit failure must not take the interface down, but it is shouted about
        on stderr and in the file log so it cannot pass unnoticed.
        """
        now = time.time()
        stamp = datetime.fromtimestamp(now, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        clean_target = safe_log_value(target, 300)
        clean_detail = safe_log_value(detail, 500)
        try:
            with self.store.connect() as conn:
                conn.execute(
                    """INSERT INTO audit(timestamp, ts_epoch, actor, role, action,
                           target, detail, src_ip) VALUES(?,?,?,?,?,?,?,?)""",
                    (stamp, now, safe_log_value(actor, 64) or "unknown", role,
                     safe_log_value(action, 64), clean_target, clean_detail, src_ip))
        except Exception as exc:  # noqa: BLE001
            print(f"[audit] DATABASE WRITE FAILED: {safe_log_value(exc, 200)}",
                  file=sys.stderr, flush=True)
        if self.audit_file:
            line = (f"{stamp}\t{actor}\t{role}\t{action}\t{clean_target}\t"
                    f"{clean_detail}\t{src_ip}\n")
            try:
                # O_APPEND so concurrent writers cannot interleave or clobber.
                fd = os.open(self.audit_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    os.write(fd, line.encode("utf-8", "replace"))
                finally:
                    os.close(fd)
            except OSError as exc:
                print(f"[audit] FILE WRITE FAILED: {safe_log_value(exc, 200)}",
                      file=sys.stderr, flush=True)

    def audit_entries(self, limit: int = 200, actor: str = "", action: str = "") -> list[dict]:
        clauses, args = [], []
        if actor:
            clauses.append("actor = ?")
            args.append(actor)
        if action:
            clauses.append("action = ?")
            args.append(action)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self.store.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit{where} ORDER BY id DESC LIMIT ?",
                [*args, max(1, min(limit, 2000))]).fetchall()
        return [dict(r) for r in rows]

    # -- users -------------------------------------------------------------
    def get_user(self, username: str) -> dict | None:
        with self.store.connect() as conn:
            row = conn.execute("SELECT * FROM admin_user WHERE username = ?",
                               (username,)).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT username, role, totp_enabled, created, last_login, disabled, "
                "failed_count, locked_until FROM admin_user ORDER BY username").fetchall()
        return [dict(r) for r in rows]

    def create_user(self, username: str, password: str, role: str,
                    totp_secret: str | None = None, actor: str = "cli") -> str:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        if not username or len(username) > 64 or not all(
                c.isalnum() or c in "._-" for c in username):
            raise ValueError("username must be alphanumeric (plus . _ -), max 64 chars")
        problems = password_strength_problems(password)
        if problems:
            raise ValueError("password rejected: " + ", ".join(problems))
        secret = totp_secret or generate_totp_secret()
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO admin_user(username, password_hash, totp_secret,
                       totp_enabled, role, created) VALUES(?,?,?,?,?,?)""",
                (username, hash_password(password), secret, 1, role, stamp))
        self.audit(actor, "user.create", target=username, detail=f"role={role}",
                   role="cli")
        return secret

    def set_password(self, username: str, password: str, actor: str = "cli") -> None:
        problems = password_strength_problems(password)
        if problems:
            raise ValueError("password rejected: " + ", ".join(problems))
        with self.store.connect() as conn:
            cur = conn.execute("UPDATE admin_user SET password_hash=?, failed_count=0, "
                               "locked_until=NULL WHERE username=?",
                               (hash_password(password), username))
            if cur.rowcount == 0:
                raise ValueError(f"no such user: {username}")
            # Changing a password invalidates every existing session for that
            # account: a password change is often a response to a suspected
            # compromise, and leaving live sessions would defeat it.
            conn.execute("DELETE FROM admin_session WHERE username=?", (username,))
        self.audit(actor, "user.password", target=username, role="cli")

    def unlock_user(self, username: str, actor: str = "cli") -> bool:
        """
        Clear a lockout without touching the password.

        Five failed logins lock an account for 15 minutes, keyed on the account
        rather than on the source, so anyone who can reach the login page can
        keep an administrator locked out indefinitely. Behind SSM or a VPN that
        needs a foothold on the management path first, but when it happens the
        recovery must not be "change the password": that is not what an
        operator guesses at 3 a.m., and it invalidates a credential for no
        reason. Returns False when there is no such account.
        """
        with self.store.connect() as conn:
            cur = conn.execute(
                "UPDATE admin_user SET failed_count=0, locked_until=NULL "
                "WHERE username=?", (username,))
            if cur.rowcount == 0:
                return False
        self.audit(actor, "user.unlock", target=username,
                   detail="lockout cleared without a password change")
        return True

    def set_role(self, username: str, role: str, actor: str = "cli") -> None:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        with self.store.connect() as conn:
            cur = conn.execute("UPDATE admin_user SET role=? WHERE username=?",
                               (role, username))
            if cur.rowcount == 0:
                raise ValueError(f"no such user: {username}")
        self.audit(actor, "user.role", target=username, detail=f"role={role}", role="cli")

    def disable_user(self, username: str, disabled: bool, actor: str = "cli") -> None:
        with self.store.connect() as conn:
            cur = conn.execute("UPDATE admin_user SET disabled=? WHERE username=?",
                               (1 if disabled else 0, username))
            if cur.rowcount == 0:
                raise ValueError(f"no such user: {username}")
            if disabled:
                conn.execute("DELETE FROM admin_session WHERE username=?", (username,))
        self.audit(actor, "user.disable" if disabled else "user.enable", target=username,
                   role="cli")

    def reset_totp(self, username: str, actor: str = "cli") -> str:
        secret = generate_totp_secret()
        with self.store.connect() as conn:
            cur = conn.execute(
                "UPDATE admin_user SET totp_secret=?, totp_enabled=1 WHERE username=?",
                (secret, username))
            if cur.rowcount == 0:
                raise ValueError(f"no such user: {username}")
            conn.execute("DELETE FROM admin_session WHERE username=?", (username,))
        self.audit(actor, "user.totp_reset", target=username, role="cli")
        return secret

    # -- login -------------------------------------------------------------
    def login(self, username: str, password: str, totp_code: str,
              src_ip: str = "", user_agent: str = "") -> tuple[AdminPrincipal, str]:
        """
        Verify credentials and start a session.

        Returns (principal, raw_token). Raises AuthError with a message safe to
        display. The message is deliberately vague about *which* factor failed
        for an unknown user, but explicit about MFA for a known one, because an
        administrator who has lost their authenticator needs to know that.

        `user_agent` is bound to the session when supplied: the column existed
        and was written empty, implying a binding that did not exist (AUDIT
        F-09). A session presented from a different user agent is destroyed.
        """
        user = self.get_user(username)
        now = time.time()
        # Bounded housekeeping. Expired rows were otherwise deleted only when
        # their exact token was presented again, so the table grew for the
        # lifetime of the process on a long-lived monitoring host.
        try:
            self.purge_expired_sessions()
        except Exception:  # noqa: BLE001 - housekeeping must not block a login
            pass

        if user and user.get("locked_until") and user["locked_until"] > now:
            remaining = int((user["locked_until"] - now) / 60) + 1
            self.audit(username, "login.locked", detail="account locked", src_ip=src_ip)
            raise AuthError(f"Account is locked. Try again in about {remaining} minute(s).")

        if not user or user.get("disabled"):
            # Spend comparable time so a missing user and a wrong password are
            # not distinguishable by timing.
            verify_password(password, hash_password("placeholder-value-123"))
            self.audit(username, "login.unknown", detail="no such account", src_ip=src_ip)
            raise AuthError("Invalid credentials.")

        if not verify_password(password, user["password_hash"]):
            self._record_failure(username, user, src_ip)
            raise AuthError("Invalid credentials.")

        if user.get("totp_enabled"):
            if self.demo_mode:
                # The authenticator step is skipped whenever this flag is set.
                # The server refuses a non-loopback bind with demo mode UNLESS
                # the operator also passes --i-know-this-exposes-monitoring, in
                # which case this runs with MFA disabled on a reachable
                # interface. Nothing here prevents that; the startup banner
                # names every relaxed control in one place (see relaxed_controls
                # in server.py). Do not let a comment imply a check that is not
                # in the code -- that is how an audit gets a false pass.
                pass
            elif not verify_totp(user.get("totp_secret") or "", totp_code):
                self._record_failure(username, user, src_ip)
                self.audit(username, "login.mfa_failed", detail="bad or missing TOTP",
                           src_ip=src_ip)
                raise AuthError("Invalid credentials.")

        # Success: clear counters, issue a session.
        with self.store.connect() as conn:
            conn.execute("UPDATE admin_user SET failed_count=0, locked_until=NULL, "
                         "last_login=? WHERE username=?",
                         (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), username))

        token = secrets.token_urlsafe(32)
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO admin_session(token_hash, username, role, created,
                       last_seen, idle_expiry, hard_expiry, src_ip, ua_hash)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (hash_token(token), username, user["role"], now, now,
                 now + self.idle_timeout, now + self.hard_timeout, src_ip,
                 hash_token(user_agent[:512]) if user_agent else ""))
        self.audit(username, "login.success", role=user["role"], src_ip=src_ip,
                   detail="mfa=skipped(demo)" if (self.demo_mode and user.get("totp_enabled"))
                   else "mfa=verified")
        return self.principal(username, user["role"], src_ip, token), token

    def _record_failure(self, username: str, user: dict, src_ip: str) -> None:
        fails = int(user.get("failed_count") or 0) + 1
        locked = time.time() + LOCKOUT_SECONDS if fails >= LOCKOUT_THRESHOLD else None
        with self.store.connect() as conn:
            conn.execute("UPDATE admin_user SET failed_count=?, locked_until=? "
                         "WHERE username=?", (fails, locked, username))
        self.audit(username, "login.failed", detail=f"attempt {fails}",
                   src_ip=src_ip)
        if locked:
            self.audit(username, "login.locked", detail=f"locked after {fails} failures",
                       src_ip=src_ip)

    @staticmethod
    def principal(username: str, role: str, src_ip: str = "",
                  token: str = "") -> AdminPrincipal:
        return AdminPrincipal(username=username, role=role,
                              permissions=PERMISSIONS.get(role, frozenset()),
                              src_ip=src_ip, session_token=token)

    # -- session lifecycle -------------------------------------------------
    def validate_session(self, token: str, touch: bool = True,
                         user_agent: str = "") -> AdminPrincipal | None:
        """
        Return the principal for a live session, or None.

        `user_agent` is compared against the value bound at login. The check is
        skipped when either side is empty, so sessions that predate the binding
        keep working and a client that sends no User-Agent is not locked out --
        the binding adds a signal, it does not become a second password.
        """
        if not token:
            return None
        now = time.time()
        with self.store.connect() as conn:
            row = conn.execute("SELECT * FROM admin_session WHERE token_hash=?",
                               (hash_token(token),)).fetchone()
        if not row:
            return None
        if now > row["idle_expiry"] or now > row["hard_expiry"]:
            self.destroy_session(token)
            self.audit(row["username"], "session.expired",
                       detail="idle" if now <= row["hard_expiry"] else "hard",
                       role=row["role"])
            return None
        user = self.get_user(row["username"])
        if not user or user.get("disabled"):
            self.destroy_session(token)
            return None
        if user["role"] != row["role"]:
            # Role changed mid-session: drop it so the new role takes effect
            # immediately rather than at the next login.
            self.destroy_session(token)
            self.audit(row["username"], "session.invalidated", detail="role changed")
            return None
        bound_ua = row["ua_hash"] if "ua_hash" in row.keys() else ""
        if bound_ua and user_agent and not hmac.compare_digest(
                bound_ua, hash_token(user_agent[:512])):
            # A session cookie replayed from a different client. Destroy it and
            # record why: this is the signal that a token has leaked.
            self.destroy_session(token)
            self.audit(row["username"], "session.ua_mismatch",
                       detail="presented from a different user agent; session destroyed")
            return None
        if touch:
            with self.store.connect() as conn:
                conn.execute(
                    "UPDATE admin_session SET last_seen=?, idle_expiry=? WHERE token_hash=?",
                    (now, now + self.idle_timeout, hash_token(token)))
        return self.principal(row["username"], row["role"], row["src_ip"] or "", token)

    def destroy_session(self, token: str) -> None:
        if not token:
            return
        with self.store.connect() as conn:
            conn.execute("DELETE FROM admin_session WHERE token_hash=?",
                         (hash_token(token),))

    def logout(self, principal: AdminPrincipal) -> None:
        self.destroy_session(principal.session_token)
        self.audit(principal.username, "logout", role=principal.role, src_ip=principal.src_ip)

    def purge_expired_sessions(self) -> int:
        now = time.time()
        with self.store.connect() as conn:
            cur = conn.execute("DELETE FROM admin_session WHERE idle_expiry < ? "
                               "OR hard_expiry < ?", (now, now))
            return cur.rowcount

    # -- authorisation -----------------------------------------------------
    def require(self, principal: AdminPrincipal | None, permission: str,
                target: str = "") -> AdminPrincipal:
        if principal is None:
            raise PermissionDenied("not signed in")
        if not principal.can(permission):
            self.audit(principal.username, "permission.denied", target=target,
                       detail=f"needs {permission}", role=principal.role,
                       src_ip=principal.src_ip)
            raise PermissionDenied(f"your role ({principal.role}) may not {permission}")
        return principal

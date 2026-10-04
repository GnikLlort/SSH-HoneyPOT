#!/usr/bin/env python3
"""
Administrator account management for the monitoring dashboard.

Run this on the monitoring host, as root or as the account that owns the store.
It is the only way to create an account, change a role, or reset a password or
authenticator: there is no self-service path in the web interface and no
password reset by email, because those are the paths that turn a monitoring tool
into an incident.

Every change is written to the audit trail, attributed to the actor given by
--actor (default "cli"), so a change made out of band still appears in the
record alongside logins, searches and exports.

    python3 manage.py --store /var/lib/honeypot-store init
    python3 manage.py --store /var/lib/honeypot-store adduser --username alice \\
        --role analyst
    python3 manage.py --store /var/lib/honeypot-store list
    python3 manage.py --store /var/lib/honeypot-store passwd --username alice
    python3 manage.py --store /var/lib/honeypot-store role --username alice --role admin
    python3 manage.py --store /var/lib/honeypot-store disable --username alice
    python3 manage.py --store /var/lib/honeypot-store totp --username alice
    python3 manage.py --store /var/lib/honeypot-store totp-code --secret <SECRET>

`adduser` and `passwd` prompt for the password rather than taking it as an
argument: a password in argv is visible in the process table and in shell
history. When there is no terminal to prompt on -- a provisioning script, an
SSM run-command, a container build -- pass `--password-stdin` and write the
password to stdin instead. There is deliberately no `--password` flag.

`init` creates an empty store. The dashboard will not start without one, and
the first real store is normally created by `ingest.py` running over the first
bundle; `init` exists so an account can be created before any evidence has
arrived, which is what a fresh monitoring host actually looks like.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from auth import (Authenticator, ROLES, generate_totp_secret,  # noqa: E402
                  password_strength_problems, provisioning_uri, totp_at)
from store import Store  # noqa: E402

MIN_PASSWORD_LENGTH = 12


def read_password_stdin() -> str:
    """
    One password, read from stdin.

    Used by --password-stdin so an account can be created without a terminal.
    The value is not echoed and not confirmed: there is nothing to echo onto,
    and a typo is caught when the operator logs in (or by `passwd`).
    """
    line = sys.stdin.readline()
    if not line.strip():
        print("error: --password-stdin was given but stdin was empty",
              file=sys.stderr)
        raise SystemExit(2)
    return line.rstrip("\r\n")


def prompt_password(confirm: bool = True) -> str:
    # Without this check, getpass falls back to reading stdin and, when that
    # stdin is closed or exhausted, raises a bare EOFError with a traceback --
    # which is what a first-time install looked like when the reader ran
    # `adduser` from anything other than an interactive shell. A missing
    # terminal is a normal situation with a one-line answer, not a crash.
    if not sys.stdin.isatty():
        print("error: cannot prompt for a password: stdin is not a terminal.\n"
              "       Run this in an interactive session (an SSH or SSM Session\n"
              "       Manager shell), or pass --password-stdin and pipe the password\n"
              "       in:\n"
              "         printf '%s\\n' \"$DASHBOARD_PASSWORD\" | python3 manage.py \\\n"
              "             --store <store> adduser --username <name> --password-stdin",
              file=sys.stderr)
        raise SystemExit(2)
    for _ in range(3):
        try:
            first = getpass.getpass("New password: ")
        except (EOFError, KeyboardInterrupt):
            print("\naborted: no password was read", file=sys.stderr)
            raise SystemExit(2)
        problems = password_strength_problems(first)
        if problems:
            print("  rejected: " + ", ".join(problems), file=sys.stderr)
            continue
        if confirm:
            try:
                second = getpass.getpass("Repeat password: ")
            except (EOFError, KeyboardInterrupt):
                print("\naborted: no password was read", file=sys.stderr)
                raise SystemExit(2)
            if first != second:
                print("  the passwords do not match", file=sys.stderr)
                continue
        return first
    raise SystemExit("giving up after 3 attempts")


def show_secret(username: str, secret: str, issuer: str) -> None:
    print()
    print("  Authenticator secret (add this to your authenticator app):")
    print(f"    {secret}")
    print()
    print("  otpauth URI:")
    print(f"    {provisioning_uri(secret, username, issuer)}")
    print()
    print(f"  Current code, to check the enrolment: {totp_at(secret)}")
    print("  (valid for 30 seconds; the code changes, the secret does not)")
    print()
    print("  This secret is shown once. It is stored so the account can verify")
    print("  codes; treat it like a password.")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", default="/var/lib/honeypot-store")
    ap.add_argument("--actor", default="cli",
                    help="name recorded as the actor for these changes")
    ap.add_argument("--issuer", default="Honeypot Dashboard")
    sub = ap.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create an empty store and exit")

    p_add = sub.add_parser("adduser", help="create an administrator")
    p_add.add_argument("--username", required=True)
    p_add.add_argument("--role", choices=ROLES, default="viewer")
    p_add.add_argument("--password-stdin", action="store_true",
                       help="read the password from stdin instead of prompting "
                            "(for provisioning; still never argv)")

    p_list = sub.add_parser("list", help="list administrators")

    p_pw = sub.add_parser("passwd", help="set a password")
    p_pw.add_argument("--username", required=True)
    p_pw.add_argument("--password-stdin", action="store_true",
                      help="read the password from stdin instead of prompting")

    p_role = sub.add_parser("role", help="change a role")
    p_role.add_argument("--username", required=True)
    p_role.add_argument("--role", choices=ROLES, required=True)

    p_dis = sub.add_parser("disable", help="disable an account")
    p_dis.add_argument("--username", required=True)
    p_en = sub.add_parser("enable", help="re-enable an account")
    p_en.add_argument("--username", required=True)

    p_totp = sub.add_parser("totp", help="reset an authenticator secret")
    p_totp.add_argument("--username", required=True)

    p_unlock = sub.add_parser(
        "unlock", help="clear a lockout without changing the password")
    p_unlock.add_argument("--username", required=True)

    p_code = sub.add_parser("totp-code",
                            help="print the current code for a secret (enrolment check)")
    p_code.add_argument("--secret", required=True)

    p_audit = sub.add_parser("audit", help="recent audit entries")
    p_audit.add_argument("--limit", type=int, default=40)

    args = ap.parse_args()

    store_root = Path(args.store)

    # `init` is the one command that must work when no store exists yet: it is
    # how you get one on a monitoring host that has not received a bundle.
    if args.command == "init":
        existed = (store_root / "store.sqlite3").is_file()
        Store(store_root)
        print(("store already present at " if existed else "store created at ")
              + f"{store_root}/store.sqlite3\n"
              f"next: create the first account:\n"
              f"  python3 manage.py --store {store_root} adduser "
              f"--username <name> --role admin")
        return 0

    if not (store_root / "store.sqlite3").is_file():
        print(f"error: no store at {store_root}/store.sqlite3\n"
              f"       create one with: python3 manage.py --store {store_root} init\n"
              f"       (or run ingest.py over a bundle, which creates it too)",
              file=sys.stderr)
        return 2

    store = Store(store_root)
    auth = Authenticator(store, audit_file=None)

    try:
        if args.command == "adduser":
            if auth.get_user(args.username):
                print(f"error: user {args.username} already exists", file=sys.stderr)
                return 2
            password = (read_password_stdin() if args.password_stdin
                        else prompt_password())
            secret = auth.create_user(args.username, password, args.role,
                                      actor=args.actor)
            print(f"created {args.username} with role {args.role}")
            show_secret(args.username, secret, args.issuer)

        elif args.command == "list":
            users = auth.list_users()
            if not users:
                print("no administrators yet. Create one:\n"
                      f"  python3 manage.py --store {store_root} adduser "
                      f"--username <name> --role admin")
                return 0
            print(f"{'username':<24}{'role':<10}{'mfa':<6}{'state':<10}last login")
            for u in users:
                print(f"{u['username']:<24}{u['role']:<10}"
                      f"{'yes' if u['totp_enabled'] else 'NO':<6}"
                      f"{'disabled' if u['disabled'] else 'active':<10}"
                      f"{u['last_login'] or '-'}")

        elif args.command == "passwd":
            password = (read_password_stdin() if args.password_stdin
                        else prompt_password())
            auth.set_password(args.username, password, actor=args.actor)
            print(f"password updated for {args.username}; existing sessions revoked")

        elif args.command == "role":
            auth.set_role(args.username, args.role, actor=args.actor)
            print(f"{args.username} is now {args.role}")

        elif args.command == "disable":
            auth.disable_user(args.username, True, actor=args.actor)
            print(f"{args.username} disabled; existing sessions revoked")

        elif args.command == "enable":
            auth.disable_user(args.username, False, actor=args.actor)
            print(f"{args.username} enabled")

        elif args.command == "unlock":
            # Five failed logins lock an account for 15 minutes, keyed on the
            # account rather than the source, so anyone who can reach the login
            # page can keep an administrator locked out. The only command that
            # used to clear the lock was `passwd`, because it happens to reset
            # the counter -- not something to guess at 3 a.m.
            if not auth.unlock_user(args.username, actor=args.actor):
                print(f"error: no such user: {args.username}", file=sys.stderr)
                return 2
            print(f"{args.username} unlocked; the password was not changed")

        elif args.command == "totp":
            secret = auth.reset_totp(args.username, actor=args.actor)
            print(f"authenticator reset for {args.username}; existing sessions revoked")
            show_secret(args.username, secret, args.issuer)

        elif args.command == "totp-code":
            secret = args.secret.strip().replace(" ", "")
            # Sanity-check the secret before printing, so a typo is an error
            # rather than a wrong code that looks like a broken account.
            try:
                code = totp_at(secret)
            except Exception as exc:  # noqa: BLE001
                print(f"error: unusable secret ({exc})", file=sys.stderr)
                return 2
            print(code)

        elif args.command == "audit":
            entries = auth.audit_entries(limit=max(1, min(args.limit, 2000)))
            for e in entries:
                print(f"{e['timestamp']}  {e['actor']:<16}{e['action']:<24}"
                      f"{(e['target'] or '')[:40]:<42}{(e['detail'] or '')[:70]}")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

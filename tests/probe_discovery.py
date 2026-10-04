#!/usr/bin/env python3
"""
Reconnaissance sweep against a running honeypot.

Runs the discovery command set a careful human operator would use, and dumps
every raw response to a directory as inert text evidence. Nothing received is
ever executed.

Usage:
    python3 tests/probe_discovery.py --out lab/probe --port 2222
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.cowrie_client import exec_commands, grab_banner, try_logins  # noqa: E402

# Ordered roughly by how an operator would build a picture of the machine:
# identity -> hardware -> storage -> network -> users -> services -> artifacts.
DISCOVERY_COMMANDS: list[str] = [
    # --- identity ---
    "uname -a",
    "uname -r",
    "hostname",
    "cat /etc/hostname",
    "cat /etc/hosts",
    "cat /etc/os-release",
    "cat /etc/debian_version",
    "cat /etc/issue",
    "cat /etc/issue.net",
    "cat /etc/motd",
    "cat /proc/version",
    "lsb_release -a",
    # --- hardware ---
    "nproc",
    "lscpu",
    "cat /proc/cpuinfo",
    "free",
    "free -m",
    "cat /proc/meminfo",
    "uptime",
    "cat /proc/uptime",
    "cat /proc/loadavg",
    # --- storage ---
    "df -h",
    "df",
    "mount",
    "cat /etc/fstab",
    "cat /proc/mounts",
    "lsblk",
    "du -sh /var/log",
    # --- network ---
    "cat /etc/resolv.conf",
    "ifconfig",
    "ip addr",
    "netstat -rn",
    "netstat -tlnp",
    "ss -tlnp",
    "cat /proc/net/route",
    # --- users / identity ---
    "cat /etc/passwd",
    "cat /etc/group",
    "id",
    "whoami",
    "who",
    "w",
    "last",
    "ls -la /home",
    "ls -la /home/{user}",
    "ls -la /root",
    "cat /etc/shadow",
    # --- services / processes ---
    "ps aux",
    "ps -ef",
    "top -bn1",
    "cat /proc/1/cmdline",
    "service --status-all",
    "systemctl status sshd",
    "cat /etc/crontab",
    "crontab -l",
    "ls -la /etc/cron.d",
    # --- ssh config ---
    "cat /etc/ssh/sshd_config",
    "ssh -V",
    "sshd -T",
    "ls -la /etc/ssh",
    # --- logs / history ---
    "ls -la /var/log",
    "cat /var/log/auth.log",
    "cat /var/log/syslog",
    "cat /var/log/dpkg.log",
    "cat /var/log/wtmp",
    "cat ~/.bash_history",
    "cat /root/.bash_history",
    "cat /home/{user}/.bash_history",
    # --- packages ---
    "dpkg -l",
    "dpkg -l openssh-server",
    "apt list --installed",
    "cat /var/lib/dpkg/status",
    # --- misc / environment leakage probes ---
    "env",
    "printenv",
    "ls -la /",
    "ls -la /tmp",
    "ls -la /opt /srv /var/www",
    "dmesg",
    "cat /proc/self/environ",
    "cat /etc/environment",
    "ls -la /var/lib/cowrie",
    "ls -la /home/cowrie",
    "cat /proc/self/cgroup",
    "which cowrie",
    # Bounded: an unbounded `find /` is exercised separately by the
    # resource-exhaustion test, which asserts the honeypot stays responsive.
    "find /tmp /var/tmp -maxdepth 2 -name '*' 2>/dev/null",
]


def discovery_commands(user: str) -> list[str]:
    """The sweep, with the primary account's home directory substituted in."""
    return [cmd.replace("{user}", user) for cmd in DISCOVERY_COMMANDS]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="lab/probe")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    # Defaults match the shipped credential policy (config/userdb.txt), which
    # allows the primary account only. Cowrie's stock phil/fout pair is denied
    # by that policy, so a sweep using it could never authenticate.
    parser.add_argument("--user", default="deploy")
    parser.add_argument("--password", default="Sunrise-Ledger-1972")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    banner = grab_banner(args.host, args.port)
    (out / "banner.txt").write_text(banner + "\n", encoding="utf-8")
    print(f"banner: {banner}")

    # Authentication behaviour: one known-good pair - the account passed in -
    # plus the pairs the credential policy must reject. Each attempt carries
    # the outcome the policy predicts, so a divergence is a finding rather
    # than a line of output nobody reads.
    attempts: list[tuple[str, str, bool]] = [
        (args.user, args.password, True),      # allowed by userdb.txt
        ("root", "root", False),               # PermitRootLogin prohibit-password
        ("admin", "admin", False),             # unknown user
        ("test", "test", False),               # must never hit a wildcard rule
        ("svc-backup", "svc-backup", False),   # shell is /usr/sbin/nologin
        (args.user, "wrongpassword", False),   # wrong password for a real account
    ]
    outcomes = try_logins(
        [(user, password) for user, password, _ in attempts],
        args.host,
        args.port,
    )
    (out / "auth_outcomes.json").write_text(
        json.dumps(
            [
                {"username": u, "password": p, "expected_accepted": expected,
                 "accepted": accepted, "agrees": accepted == expected}
                for (u, p, expected), (_u, _p, accepted) in zip(attempts, outcomes)
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    mismatches = 0
    for (u, p, expected), (_u, _p, accepted) in zip(attempts, outcomes):
        verdict = "PASS" if accepted == expected else "MISMATCH"
        if accepted != expected:
            mismatches += 1
        print(f"auth {u}/{p}: {'ACCEPTED' if accepted else 'rejected'} "
              f"(expected {'accepted' if expected else 'rejected'}) {verdict}")

    log = exec_commands(
        discovery_commands(args.user),
        username=args.user,
        password=args.password,
        host=args.host,
        port=args.port,
    )
    if not log.authenticated:
        print("ERROR: could not authenticate; cannot run discovery", file=sys.stderr)
        print(json.dumps(log.errors, indent=2), file=sys.stderr)
        return 1

    lines = ["# Raw discovery transcript", f"# banner: {log.banner}", ""]
    for res in log.results:
        lines.append("=" * 78)
        lines.append(f"$ {res.command}   [exit={res.exit_status} {res.duration_ms}ms]")
        lines.append("-" * 78)
        if res.stdout:
            lines.append(res.stdout.rstrip("\n"))
        if res.stderr:
            lines.append("--- stderr ---")
            lines.append(res.stderr.rstrip("\n"))
        lines.append("")
    (out / "discovery.txt").write_text("\n".join(lines), encoding="utf-8")

    summary = {r.command: {"exit": r.exit_status, "ms": r.duration_ms, "bytes": len(r.stdout) + len(r.stderr)} for r in log.results}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {out}/discovery.txt ({len(log.results)} commands)")
    if log.errors:
        print("errors:", json.dumps(log.errors, indent=2))
    if mismatches:
        # A credential-policy divergence means the honeypot is either accepting
        # credentials it must not, or refusing ones the operator configured.
        # Either way the sweep's output cannot be trusted without explaining it.
        print(f"\nFAIL: {mismatches} authentication outcome(s) disagreed with the "
              f"credential policy", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

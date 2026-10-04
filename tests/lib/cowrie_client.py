"""
SSH test client for honeypot conformance testing, built on the real
OpenSSH command-line tools.

Why OpenSSH rather than a Python SSH library:

* It is what a human operator actually uses, so the recorded behaviour is
  the behaviour an operator would observe.
* Cowrie v3.1.0 closes an ``exec`` channel ~2 ms after the command
  finishes. Paramiko 5.0.0 raises ``SSHException: Channel closed.`` when
  the close packet wins that race, which made a library-based harness
  report spurious failures. OpenSSH tolerates it. The paramiko path is
  retained in ``paramiko_exec`` purely so the interop test can document
  that difference.

Connection multiplexing (``ssh -M``) lets one authenticated TCP session
carry every command, which is both faster and closer to how an operator
works through a target.

Nothing returned by the honeypot is ever executed. Output is written to
disk as inert text.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 2222
DEFAULT_USER = "phil"
DEFAULT_PASSWORD = "fout"

_SSH_BASE = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "PreferredAuthentications=password",
    "-o", "PubkeyAuthentication=no",
    "-o", "NumberOfPasswordPrompts=1",
    "-o", "ConnectTimeout=10",
]


@dataclass
class ExecResult:
    command: str
    stdout: str
    stderr: str
    exit_status: int | None
    duration_ms: int


@dataclass
class SessionLog:
    username: str
    password: str
    host: str
    port: int
    banner: str = ""
    authenticated: bool = False
    results: list[ExecResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _write_askpass(directory: Path, password: str) -> Path:
    """Create a throwaway askpass helper so ssh can prompt non-interactively."""
    helper = directory / "askpass.sh"
    helper.write_text(f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(password)}\n", encoding="utf-8")
    helper.chmod(0o700)
    return helper


def grab_banner(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = 5.0) -> str:
    """Read the SSH identification string without completing a handshake."""
    import socket

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        data = b""
        deadline = time.time() + timeout
        while b"\n" not in data and time.time() < deadline:
            chunk = sock.recv(256)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", "replace").strip()


class OpenSSHClient:
    """One multiplexed, authenticated OpenSSH session against the honeypot."""

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        username: str = DEFAULT_USER,
        password: str = DEFAULT_PASSWORD,
        workdir: str | os.PathLike[str] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="hp-test-"))
        self._own_tmp = workdir is None
        self.banner = ""
        self.authenticated = False
        self.socket_path = self._tmp / "cm.sock"
        self._askpass = _write_askpass(self._tmp, password)

    # -- lifecycle ---------------------------------------------------------
    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["SSH_ASKPASS"] = str(self._askpass)
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["DISPLAY"] = env.get("DISPLAY", "localhost:0")
        return env

    def start(self) -> bool:
        """Open the multiplexed master connection."""
        self.banner = grab_banner(self.host, self.port)
        cmd = [
            "setsid", "-w", "ssh", "-M", "-S", str(self.socket_path), "-fN",
            *_SSH_BASE, "-p", str(self.port),
            f"{self.username}@{self.host}",
        ]
        proc = subprocess.run(
            cmd, env=self._env(), capture_output=True, text=True, timeout=30,
            stdin=subprocess.DEVNULL,
        )
        self.authenticated = self.socket_path.exists() and proc.returncode == 0
        return self.authenticated

    def close(self) -> None:
        if self.socket_path.exists():
            subprocess.run(
                ["ssh", "-S", str(self.socket_path), "-O", "exit", "-p", str(self.port),
                 f"{self.username}@{self.host}"],
                capture_output=True, text=True, timeout=15,
            )
        if self._own_tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)

    def __enter__(self) -> OpenSSHClient:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- command execution -------------------------------------------------
    def run(self, command: str, timeout: float = 25.0) -> ExecResult:
        """Run one command over the multiplexed connection."""
        started = time.time()
        cmd = [
            "ssh", "-S", str(self.socket_path), *_SSH_BASE,
            "-p", str(self.port), f"{self.username}@{self.host}", command,
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
            return ExecResult(
                command=command,
                stdout=proc.stdout,
                stderr=proc.stderr,
                exit_status=proc.returncode,
                duration_ms=int((time.time() - started) * 1000),
            )
        except subprocess.TimeoutExpired as exc:
            return ExecResult(
                command=command,
                stdout=(exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=f"<<HARNESS: command exceeded {timeout:g}s and was killed>>",
                exit_status=None,
                duration_ms=int((time.time() - started) * 1000),
            )

    def run_many(self, commands: list[str], timeout: float = 25.0) -> list[ExecResult]:
        return [self.run(c, timeout) for c in commands]

    # -- shell mode --------------------------------------------------------
    def interactive(
        self,
        commands: list[str],
        cols: int = 120,
        rows: int = 40,
        timeout: float = 60.0,
        settle: float = 0.35,
    ) -> str:
        """
        Drive an interactive PTY shell with the real ssh client and return
        the raw terminal transcript.

        Commands are fed on stdin with a short pause between them so the
        emulated shell has time to render its prompt, which is what a human
        would see.
        """
        script_lines = []
        for cmd in commands:
            script_lines.append(cmd)
            script_lines.append(f"echo __RC__$?")
        script = "\n".join(script_lines) + "\n"
        cmd = [
            "setsid", "-w", "ssh", "-tt", "-S", str(self.socket_path), *_SSH_BASE,
            "-p", str(self.port), f"{self.username}@{self.host}",
        ]
        env = self._env()
        env["COLUMNS"] = str(cols)
        env["LINES"] = str(rows)
        try:
            proc = subprocess.run(
                cmd, input=script, capture_output=True, text=True,
                timeout=timeout, env=env,
            )
            return proc.stdout + proc.stderr
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            return out + "\n<<HARNESS: interactive session exceeded timeout>>\n"

    # -- file transfer -----------------------------------------------------
    def sftp_upload(self, local_path: str, remote_path: str, timeout: float = 30.0) -> tuple[bool, str]:
        batch = f"put {local_path} {remote_path}\nls -l {remote_path}\nbye\n"
        cmd = [
            "setsid", "-w", "sftp", "-b", "-", "-S", "ssh", *_SSH_BASE,
            "-o", f"ControlPath={self.socket_path}",
            "-P", str(self.port), f"{self.username}@{self.host}",
        ]
        try:
            proc = subprocess.run(
                cmd, input=batch, capture_output=True, text=True,
                timeout=timeout, env=self._env(),
            )
            ok = proc.returncode == 0
            return ok, (proc.stdout + proc.stderr).strip()
        except subprocess.TimeoutExpired:
            return False, "<<HARNESS: sftp timed out>>"

    def scp_upload(self, local_path: str, remote_path: str, timeout: float = 30.0) -> tuple[bool, str]:
        cmd = [
            "setsid", "-w", "scp", *_SSH_BASE,
            "-o", f"ControlPath={self.socket_path}",
            "-P", str(self.port), local_path,
            f"{self.username}@{self.host}:{remote_path}",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=self._env(),
                stdin=subprocess.DEVNULL,
            )
            return proc.returncode == 0, (proc.stdout + proc.stderr).strip()
        except subprocess.TimeoutExpired:
            return False, "<<HARNESS: scp timed out>>"

    def sftp_download(self, remote_path: str, local_path: str, timeout: float = 30.0) -> tuple[bool, str]:
        batch = f"get {remote_path} {local_path}\nbye\n"
        cmd = [
            "setsid", "-w", "sftp", "-b", "-", "-S", "ssh", *_SSH_BASE,
            "-o", f"ControlPath={self.socket_path}",
            "-P", str(self.port), f"{self.username}@{self.host}",
        ]
        try:
            proc = subprocess.run(
                cmd, input=batch, capture_output=True, text=True,
                timeout=timeout, env=self._env(),
            )
            return proc.returncode == 0, (proc.stdout + proc.stderr).strip()
        except subprocess.TimeoutExpired:
            return False, "<<HARNESS: sftp download timed out>>"


# -- helpers used by earlier probes ---------------------------------------

def exec_commands(
    commands: list[str],
    username: str = DEFAULT_USER,
    password: str = DEFAULT_PASSWORD,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = 25.0,
    per_command_timeout: float = 25.0,
) -> SessionLog:
    """Run commands over one multiplexed OpenSSH session."""
    log = SessionLog(username=username, password=password, host=host, port=port)
    client = OpenSSHClient(host=host, port=port, username=username, password=password)
    try:
        log.banner = client.banner or grab_banner(host, port)
        log.authenticated = client.start()
        if not log.authenticated:
            log.errors.append("authentication failed")
            return log
        log.results = client.run_many(commands, timeout=per_command_timeout)
    finally:
        client.close()
    return log


def try_logins(
    attempts: list[tuple[str, str]],
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = 15.0,
) -> list[tuple[str, str, bool]]:
    """Attempt (username, password) pairs and report which were accepted."""
    outcomes: list[tuple[str, str, bool]] = []
    for username, password in attempts:
        client = OpenSSHClient(host=host, port=port, username=username, password=password)
        try:
            outcomes.append((username, password, client.start()))
        except Exception:  # noqa: BLE001
            outcomes.append((username, password, False))
        finally:
            client.close()
    return outcomes


def paramiko_exec(
    command: str,
    username: str = DEFAULT_USER,
    password: str = DEFAULT_PASSWORD,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = 15.0,
) -> tuple[bool, str, str]:
    """
    Run one command via paramiko. Returns (ok, stdout, error).
    Used only by the interop test to document the exec-close race.
    """
    try:
        import paramiko
    except ImportError:
        return False, "", "paramiko not installed"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host, port=port, username=username, password=password,
            allow_agent=False, look_for_keys=False, timeout=timeout,
            banner_timeout=timeout, auth_timeout=timeout,
        )
        _in, out, err = client.exec_command(command, timeout=timeout)
        return True, out.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return False, "", f"{type(exc).__name__}: {exc}"
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass

"""
The actual replacements applied by the realism overlay.

Everything here is a drop-in replacement for a method that Cowrie already
calls. No new behaviour is introduced: the emulated shell can still only
produce text, and nothing a visitor sends reaches the host.
"""

from __future__ import annotations

import configparser
import time
from pathlib import Path

from twisted.logger import Logger

log = Logger()

# ---------------------------------------------------------------------------
# 1. free: stop reading the real host's /proc/meminfo
# ---------------------------------------------------------------------------
# Stock behaviour (cowrie/commands/free.py::get_free_stats) opens the REAL
# /proc/meminfo. Inside container/VM the honeypot therefore reports the host's
# true RAM to the visitor, and it contradicts the emulated /proc/meminfo that
# `cat /proc/meminfo` serves. This replacement parses the *emulated* file so
# the two always agree.
#
# The emulated file is located the same way Cowrie locates any virtual file:
# via [shell] filesystem, through cowrie.shell.honeyfs.
FREE_KEYS = (
    "Buffers",
    "Cached",
    "MemTotal",
    "MemFree",
    "SwapTotal",
    "SwapFree",
    "Shmem",
    "MemAvailable",
)


def _read_emulated_meminfo() -> dict[str, int]:
    """
    Parse /proc/meminfo out of the emulated filesystem.

    Returns an empty dict if the emulated file cannot be read; the caller
    then falls back to stock behaviour rather than inventing numbers.
    """
    try:
        from cowrie.shell import honeyfs

        raw = honeyfs.read_honeyfs_bytes("proc/meminfo")
    except FileNotFoundError:
        return {}
    except Exception:  # noqa: BLE001
        return {}

    values: dict[str, int] = {}
    for line in raw.decode("utf-8", "replace").splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        key = key.strip()
        if key not in FREE_KEYS:
            continue
        token = rest.strip().split(" ")[0]
        try:
            values[key] = int(token)
        except ValueError:
            continue
    return values


FREE_TEMPLATE = (
    "               total        used        free      shared  buff/cache   available\n"
    "Mem:     {MemTotal:>13}{calc_total_used:>12}{MemFree:>12}{Shmem:>12}{calc_total_buffers_and_cache:>12}{MemAvailable:>12}\n"
    "Swap:    {SwapTotal:>13}{calc_swap_used:>12}{SwapFree:>12}\n"
)


def _procps_human(kb: int) -> str:
    """
    Render a kB value the way procps-ng `free -h` does.

    procps uses binary units but prints the short suffix without the "i":
    3959 MiB of memory is shown as "3.9Gi". Cowrie's stock implementation
    divides by 1000 and labels the result "M", so `free -h` on a 4 GiB machine
    reports "4.1G" - close enough to be unnoticeable, and wrong.
    """
    value = float(kb)
    for unit in ("Ki", "Mi", "Gi", "Ti", "Pi"):
        if value < 1024 or unit == "Pi":
            if unit == "Ki":
                return f"{int(value)}Ki"
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}Pi"


def install_free_patch() -> bool:
    from cowrie.commands import free as cmd_free

    def get_free_stats(self) -> dict[str, int]:  # noqa: ANN001
        stats = _read_emulated_meminfo()
        if stats:
            return stats
        # Fall back to the original implementation so behaviour degrades to
        # stock rather than to an empty response.
        return _ORIGINAL_GET_FREE_STATS(self)

    def do_free(self, fmt: str = "kilobytes") -> None:  # noqa: ANN001
        try:
            _render_free(self, fmt)
        except Exception:  # noqa: BLE001
            log.warn("[cowrie-realism-overlay] free render failed, using stock output")
            _ORIGINAL_FREE_DO(self, fmt)

    def _render_free(self, fmt: str = "kilobytes") -> None:  # noqa: ANN001
        raw = self.get_free_stats()
        if not raw:
            return
        raw = dict(raw)
        raw["calc_total_buffers_and_cache"] = raw["Buffers"] + raw["Cached"]
        raw["calc_total_used"] = raw["MemTotal"] - (
            raw["MemFree"] + raw["calc_total_buffers_and_cache"]
        )
        raw["calc_swap_used"] = raw["SwapTotal"] - raw["SwapFree"]

        if fmt == "megabytes":
            # procps divides by 1024 for -m, not 1000.
            rendered = {k: str(int(v / 1024)) for k, v in raw.items()}
        elif fmt == "human":
            rendered = {k: _procps_human(v) for k, v in raw.items()}
        else:
            rendered = {k: str(v) for k, v in raw.items()}
        self.write(FREE_TEMPLATE.format(**rendered))

    global _ORIGINAL_FREE_DO
    if _ORIGINAL_FREE_DO is None:
        _ORIGINAL_FREE_DO = cmd_free.Command_free.do_free
    if not hasattr(cmd_free.Command_free, "_overlay_original_get_free_stats"):
        cmd_free.Command_free._overlay_original_get_free_stats = cmd_free.Command_free.get_free_stats  # type: ignore[attr-defined]
        cmd_free.Command_free.get_free_stats = get_free_stats  # type: ignore[assignment]
        cmd_free.Command_free.do_free = do_free  # type: ignore[assignment]
        log.info("[cowrie-realism-overlay] patched Command_free.get_free_stats and do_free")
    return True


# ---------------------------------------------------------------------------
# 2 and 3. ps: restore the missing columns and honour the configured table
# ---------------------------------------------------------------------------
# Stock `ps aux` renders USER PID %CPU %MEM VSZ RSS TTY STAT START and stops
# there: TIME and COMMAND are dropped. It then appends two hardcoded rows
# dated "Jul22" and "06:30" whatever the emulated boot time is.
#
# Stock `ps -ef` / `ps -e` / `ps -f` bypass the configured table entirely and
# print a two-line list containing only the current shell and the ps command.
#
# Both replacements render the table the operator configured in
# [shell] processes, and derive the current-session rows from the live session
# so their start time is consistent with everything else.
PS_COLUMNS_AUX = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
PS_COLUMNS_EF = "UID        PID  PPID  C STIME TTY          TIME CMD"


def _fmt_elapsed_start(seconds_ago: float, now: float) -> str:
    """Render the ps START column the way procps does."""
    started = now - seconds_ago
    lt = time.localtime(started)
    age = seconds_ago
    if age < 24 * 3600:
        return time.strftime("%H:%M", lt)
    if age < 365 * 24 * 3600:
        return time.strftime("%b%d", lt)
    return time.strftime("%Y", lt)


def install_ps_patch() -> bool:
    from cowrie.commands import base as cmd_base

    def _session_rows(self, now: float) -> list[tuple[str, str, str, str, str, str, str, str, str, str]]:
        """
        Rows describing this session, consistent with the configured table.

        The stock code hardcodes "06:30" and a fixed PID pair; we derive the
        start time from the session's login time instead.
        """
        try:
            logintime = getattr(self.protocol, "logintime", None) or now
            elapsed = max(0.0, now - logintime)
        except Exception:  # noqa: BLE001
            elapsed = 0.0
        start = _fmt_elapsed_start(elapsed, now)
        user = getattr(self.protocol, "user", None) or "root"
        # A session shell is a child of the listening sshd, so its PID sits
        # in the same numeric region as the rest of the table.
        base_pid = 1044
        return [
            (user, str(base_pid), "0.0", "0.1", "5416", "1024", "pts/0", "Ss", start, "0:00"),
            (user, str(base_pid + 2), "0.0", "0.1", "2435", "929", "pts/0", "Ss", start, "0:00"),
        ]

    def _emit(self, line: str, width: int | None) -> None:  # noqa: ANN001
        """
        Write one line, honouring COLUMNS only when it is actually set.

        Stock Cowrie always truncates to ``int(environ["COLUMNS"])`` with an
        80-column default. Real procps truncates to the terminal width when
        attached to one, and does not truncate when writing to a pipe or file.
        Since an exec channel has no terminal, lines must not be cut at 80
        characters - doing so silently deletes the TIME and COMMAND columns,
        which is what made stock `ps aux` look like a five-column command.
        """
        if width is not None and len(line) > width:
            line = line[:width]
        self.write(line + "\n")

    def call(self) -> None:  # noqa: ANN001
        try:
            _render_ps(self, now=time.time())
        except Exception:  # noqa: BLE001
            # Never wedge a session: fall back to the stock renderer, whose
            # worst case is the output this overlay exists to improve.
            log.warn("[cowrie-realism-overlay] ps render failed, using stock output")
            _ORIGINAL_PS_CALL(self)

    def _render_ps(self, now: float) -> None:  # noqa: ANN001
        args = [a for a in self.args if a.strip()]

        # A real terminal width, if one is attached; otherwise do not truncate.
        width: int | None = None
        try:
            width = int(self.environ["COLUMNS"])
        except (KeyError, TypeError, ValueError):
            width = None

        wants_full = any(a.startswith("-") and ("e" in a or "f" in a) for a in args)
        wants_aux = (not wants_full) and (not args or any(c in "axu" for a in args for c in a))

        # The configured process table lives on the server object.
        table = []
        try:
            table = self.protocol.user.server.process or []
        except Exception:  # noqa: BLE001
            table = []

        if wants_full:
            _emit(self, PS_COLUMNS_EF, width)
            for row in table:
                pid = str(row.get("PID", 0))
                try:
                    ppid = str(max(1, int(pid) - 1))
                except ValueError:
                    ppid = "1"
                _emit(self, 
                    f"{str(row.get('USER', 'root')):<8} {pid:>6} {ppid:>6}   0 "
                    f"{str(row.get('START', '?')):<5} {str(row.get('TTY', '?')):<12} "
                    f"{str(row.get('TIME', '0:00')):<8} {row.get('COMMAND', '')}",
                    width,
                )
            for user, pid, _cpu, _mem, _vsz, _rss, tty, _st, start, tm in _session_rows(self, now):
                _emit(self, f"{user:<8} {pid:>6} {str(max(1, int(pid) - 1)):>6}   0 {start:<5} "
                           f"{tty:<12} {tm:<8} ps -ef", width)
            return

        if wants_aux:
            _emit(self, PS_COLUMNS_AUX, width)
            for row in table:
                _emit(self, 
                    f"{str(row.get('USER', 'root')):<8} {str(row.get('PID', 0)):>5} "
                    f"{str(row.get('CPU', 0.0)):>4} {str(row.get('MEM', 0.0)):>4} "
                    f"{str(row.get('VSZ', 0)):>6} {str(row.get('RSS', 0)):>5} "
                    f"{str(row.get('TTY', '?')):<8} {str(row.get('STAT', 'S')):<4} "
                    f"{str(row.get('START', '?')):<5} {str(row.get('TIME', '0:00')):<7} "
                    f"{row.get('COMMAND', '')}",
                    width,
                )
            for user, pid, cpu, mem, vsz, rss, tty, st, start, tm in _session_rows(self, now):
                _emit(self, f"{user:<8} {pid:>5} {cpu:>4} {mem:>4} {vsz:>6} {rss:>5} "
                           f"{tty:<8} {st:<4} {start:<5} {tm:<7} ps aux", width)
            return

        # Bare `ps`: the current session's processes only.
        _emit(self, "    PID TTY          TIME CMD", width)
        for _user, pid, _cpu, _mem, _vsz, _rss, tty, _st, _start, tm in _session_rows(self, now):
            _emit(self, f"{pid:>7} {tty:<12} {tm:<8} bash", width)

    global _ORIGINAL_PS_CALL
    if _ORIGINAL_PS_CALL is None:
        _ORIGINAL_PS_CALL = cmd_base.Command_ps.call
    if not hasattr(cmd_base.Command_ps, "_overlay_original_call"):
        cmd_base.Command_ps._overlay_original_call = _ORIGINAL_PS_CALL  # type: ignore[attr-defined]
        cmd_base.Command_ps.call = call  # type: ignore[assignment]
        log.info("[cowrie-realism-overlay] patched Command_ps.call")
    return True


# ---------------------------------------------------------------------------
# 4. service --status-all: a systemd-appropriate service list
# ---------------------------------------------------------------------------
# Stock returns a hardcoded Debian-7-era SysV list. On a host whose
# /etc/init.d contains three scripts and whose systemctl output lists
# systemd units, that list is a direct contradiction.
SYSTEMD_SERVICES: tuple[tuple[str, str], ...] = (
    ("[ + ]", "apparmor"),
    ("[ + ]", "cron"),
    ("[ + ]", "dbus"),
    ("[ + ]", "nginx"),
    ("[ + ]", "rsyslog"),
    ("[ + ]", "ssh"),
    ("[ + ]", "systemd-journald"),
    ("[ + ]", "systemd-logind"),
    ("[ + ]", "systemd-networkd"),
    ("[ + ]", "systemd-resolved"),
    ("[ + ]", "systemd-timesyncd"),
    ("[ + ]", "systemd-udevd"),
    ("[ - ]", "apt-daily"),
    ("[ - ]", "apt-daily-upgrade"),
    ("[ - ]", "e2scrub_reap"),
    ("[ - ]", "unattended-upgrades"),
)


def install_service_patch() -> bool:
    from cowrie.commands import service as cmd_service

    def status_all(self) -> None:  # noqa: ANN001
        # Same "--status-all" spelling a real `service` uses on a systemd
        # host: a blank line, then the SysV-style compatibility list.
        self.write("\n")
        for marker, name in SYSTEMD_SERVICES:
            self.write(f" {marker}  {name}\n")

    if not hasattr(cmd_service.Command_service, "_overlay_original_status_all"):
        cmd_service.Command_service._overlay_original_status_all = cmd_service.Command_service.status_all  # type: ignore[attr-defined]
        cmd_service.Command_service.status_all = status_all  # type: ignore[assignment]
        log.info("[cowrie-realism-overlay] patched Command_service.status_all")
    return True


# ---------------------------------------------------------------------------
_ORIGINAL_GET_FREE_STATS = None
_ORIGINAL_PS_CALL = None
_ORIGINAL_FREE_DO = None


def install() -> None:
    """Apply every patch, capturing originals for the fallback paths."""
    global _ORIGINAL_GET_FREE_STATS

    from cowrie.commands import free as cmd_free

    if _ORIGINAL_GET_FREE_STATS is None:
        _ORIGINAL_GET_FREE_STATS = cmd_free.Command_free.get_free_stats

    install_free_patch()
    install_ps_patch()
    install_service_patch()
    log.info("[cowrie-realism-overlay] all patches applied")

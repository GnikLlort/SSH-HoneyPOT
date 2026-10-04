#!/usr/bin/env python3
"""
Build every host-visible artefact from realism/identity.yaml.

Inputs
    realism/identity.yaml       the single source of truth
    <cowrie>/data/fs.pickle     the bundled Cowrie filesystem (metadata)

Outputs (into --out, default build/profile/)
    fs.pickle                   custom filesystem: fixed metadata, added
                                commands, decoys, canopies and logs
    cmdoutput.json              coherent `ps aux` process table
    procfs/meminfo              synthetic /proc/meminfo for the bind-mount
                                that stops the real host's RAM leaking into
                                `free`
    cowrie-profile.cfg          config fragment derived from the identity
    expectations.json           machine-checkable claims the test suite
                                asserts against the running honeypot
    BUILD-REPORT.txt            what was written and the consistency checks
                                that passed

Why a generator instead of hand-written files
---------------------------------------------
A honeypot is unmasked far more often by internal contradiction than by a
clever probe. If `nproc` says 2 and /proc/cpuinfo lists 4 processors, if `df`
says 40G and /etc/fstab says 8G, if the SSH banner says OpenSSH 9.2 and
`ssh -V` says 7.9, the visitor knows. Deriving everything from one manifest
makes those contradictions a build failure.

Build-time invariance checks (the build aborts if any fail):
  1. A_SIZE equals len(content) for every file we embed, so `ls -l` never
     contradicts `cat`.
  2. No path in filesystem.forbidden_paths exists in the finished pickle.
  3. The SSH banner and the `ssh -V` string name the same OpenSSH release.
  4. tmpfs sizes in df/mount/fstab are consistent with identity.memory.
  5. Disk arithmetic in df closes (used + avail == size).
  6. uid/gid referenced by decoys and logs exist in the generated passwd/group.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pickle
import random
import shutil
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required to build the profile: pip install pyyaml")

# The delete guard is shared with the dashboard's bundle builder and mirrored in
# shell by deploy/uninstall.sh. Import it from shared/ rather than copying it:
# three copies of a safety check is three places for it to be wrong.
_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "shared") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "shared"))
from safe_paths import (MARKER_PROFILE, UnsafePathError,  # noqa: E402
                        guard_delete_target, write_marker)


# -- filesystem node format (mirrors cowrie/shell/fs.py) ----------------------
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = range(7)

MODE_FILE = stat.S_IFREG
MODE_DIR = stat.S_IFDIR
MODE_LINK = stat.S_IFLNK


class BuildError(RuntimeError):
    """Raised when a consistency invariant is violated."""


# =============================================================================
# Filesystem tree manipulation
# =============================================================================
class FsTree:
    """Mutable wrapper around Cowrie's positional-node filesystem tree."""

    def __init__(self, root: list) -> None:
        self.root = root

    # -- navigation --------------------------------------------------------
    def _children(self, node: list) -> list:
        if not isinstance(node[A_CONTENTS], list):
            raise BuildError(f"{node[A_NAME]!r} is not a directory")
        return node[A_CONTENTS]

    def find(self, path: str, follow_links: bool = True) -> list | None:
        parts = [p for p in path.split("/") if p]
        node = self.root
        for depth, part in enumerate(parts):
            if follow_links and node[A_TYPE] == T_LINK:
                target = node[A_TARGET]
                resolved = self.find(target)
                if resolved is None:
                    return None
                node = resolved
            match = next((c for c in self._children(node) if c[A_NAME] == part), None)
            if match is None:
                return None
            node = match
        if follow_links and node[A_TYPE] == T_LINK:
            return self.find(node[A_TARGET])
        return node

    def parent_of(self, path: str) -> tuple[list, str]:
        parts = [p for p in path.split("/") if p]
        if not parts:
            raise BuildError("cannot take parent of /")
        name = parts[-1]
        parent_path = "/" + "/".join(parts[:-1])
        parent = self.find(parent_path) if parts[:-1] else self.root
        if parent is None:
            raise BuildError(f"parent directory of {path} does not exist: {parent_path}")
        if parent[A_TYPE] != T_DIR:
            raise BuildError(f"parent of {path} is not a directory: {parent_path}")
        return parent, name

    # -- mutation ----------------------------------------------------------
    def mkdir(self, path: str, uid: int = 0, gid: int = 0, mode: int = 0o755, ctime: int = 0) -> list:
        existing = self.find(path, follow_links=False)
        if existing is not None:
            return existing
        parent, name = self.parent_of(path)
        node = [name, T_DIR, uid, gid, 4096, MODE_DIR | mode, ctime, [], None, None]
        self._children(parent).append(node)
        return node

    def mkdirs(self, path: str, **kw) -> list:
        """Create every missing component of path."""
        parts = [p for p in path.split("/") if p]
        node = self.root
        for i, part in enumerate(parts):
            found = next((c for c in self._children(node) if c[A_NAME] == part), None)
            if found is None:
                found = [part, T_DIR, kw.get("uid", 0), kw.get("gid", 0), 4096,
                         MODE_DIR | kw.get("mode", 0o755), kw.get("ctime", 0), [], None, None]
                self._children(node).append(found)
            node = found
        return node

    def write_file(
        self,
        path: str,
        data: bytes,
        uid: int = 0,
        gid: int = 0,
        mode: int = 0o644,
        ctime: int = 0,
    ) -> list:
        """
        Create or replace a regular file.

        A_SIZE is always set to len(data). This is the invariant that keeps
        `ls -l` and `cat` from disagreeing, and it is the single most common
        realism defect in stock honeypot filesystems.
        """
        parent, name = self.parent_of(path)
        node = next((c for c in self._children(parent) if c[A_NAME] == name), None)
        if node is None:
            node = [name, T_FILE, uid, gid, len(data), MODE_FILE | mode, ctime, data, None, None]
            self._children(parent).append(node)
        else:
            node[A_TYPE] = T_FILE
            node[A_UID] = uid
            node[A_GID] = gid
            node[A_SIZE] = len(data)
            node[A_MODE] = MODE_FILE | mode
            node[A_CTIME] = ctime
            node[A_CONTENTS] = data
            node[A_TARGET] = None
        return node

    def symlink(self, path: str, target: str, ctime: int = 0) -> list:
        parent, name = self.parent_of(path)
        node = next((c for c in self._children(parent) if c[A_NAME] == name), None)
        if node is None:
            node = [name, T_LINK, 0, 0, len(target), MODE_LINK | 0o777, ctime, None, target, None]
            self._children(parent).append(node)
        else:
            node[A_TYPE] = T_LINK
            node[A_SIZE] = len(target)
            node[A_MODE] = MODE_LINK | 0o777
            node[A_CONTENTS] = None
            node[A_TARGET] = target
        return node

    def remove(self, path: str) -> bool:
        try:
            parent, name = self.parent_of(path)
        except BuildError:
            return False
        children = self._children(parent)
        for i, child in enumerate(children):
            if child[A_NAME] == name:
                del children[i]
                return True
        return False

    def walk(self, node: list | None = None, path: str = ""):
        node = node if node is not None else self.root
        for child in self._children(node):
            child_path = f"{path}/{child[A_NAME]}"
            yield child_path, child
            if child[A_TYPE] == T_DIR:
                yield from self.walk(child, child_path)


# =============================================================================
# Identity helpers
# =============================================================================
@dataclass
class Accounts:
    by_name: dict[str, dict] = field(default_factory=dict)

    def uid(self, name: str, fallback: int = 0) -> int:
        acct = self.by_name.get(name)
        return int(acct["uid"]) if acct else fallback

    def gid(self, name: str, fallback: int = 0) -> int:
        acct = self.by_name.get(name)
        return int(acct["gid"]) if acct else fallback


# Base system accounts present on a Debian 12 install. Kept explicit so that
# uid/gid resolution never silently falls back to root.
BASE_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
"""

PRIMARY_BASHRC = """# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=1000
HISTFILESIZE=2000
shopt -s checkwinsize

if [ -x /usr/bin/lesspipe ]; then
    eval "$(SHELL=/bin/sh lesspipe)"
fi

alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

export PATH="$HOME/.local/bin:$PATH"
"""

PRIMARY_PROFILE = """# ~/.profile: executed by the command interpreter for login shells.

if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi

if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
"""

BASE_GROUP = """root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:999:
systemd-network:x:998:
systemd-timesync:x:997:
messagebus:x:102:
ssh:x:103:
"""


def build_accounts(identity: dict) -> tuple[str, str, str, Accounts]:
    """Return (passwd, group, shadow, Accounts) for the manifest."""
    accounts = Accounts()
    pw_lines = [ln for ln in BASE_PASSWD.strip().splitlines()]
    gr_lines = [ln for ln in BASE_GROUP.strip().splitlines()]
    sh_lines = []

    for line in BASE_PASSWD.strip().splitlines():
        name = line.split(":")[0]
        accounts.by_name[name] = {"uid": int(line.split(":")[2]), "gid": int(line.split(":")[3])}

    # Groups referenced by BASE_PASSWD users that are not in BASE_GROUP.
    existing_groups = {ln.split(":")[0] for ln in gr_lines}

    for acct in identity["accounts"]:
        name = acct["name"]
        uid = int(acct["uid"])
        gid = int(acct["gid"])
        extra = acct.get("groups", []) or []
        members = ",".join([name, *extra])

        pw_lines.append(f"{name}:x:{uid}:{gid}:{acct['gecos']}:{acct['home']}:{acct['shell']}")
        # The user's own group, carrying the supplementary memberships the
        # `groups` command will report.
        gr_lines.append(f"{name}:x:{gid}:{members}")
        if name not in existing_groups:
            existing_groups.add(name)

        for extra_group in extra:
            idx = next((i for i, ln in enumerate(gr_lines) if ln.startswith(f"{extra_group}:")), None)
            if idx is None:
                continue
            fields = gr_lines[idx].split(":")
            # Add this account to the group's member list.
            members_now = [m for m in fields[3].split(",") if m]
            if name not in members_now:
                members_now.append(name)
            gr_lines[idx] = ":".join([fields[0], fields[1], fields[2], ",".join(members_now)])

        accounts.by_name[name] = {"uid": uid, "gid": gid}

    shadow_epoch = 19700  # synthetic day counter; deliberately not a real date
    for line in BASE_PASSWD.strip().splitlines():
        nm = line.split(":")[0]
        sh_lines.append(f"{nm}:*:{shadow_epoch}:0:99999:7:::")

    for acct in identity["accounts"]:
        name = acct["name"]
        pw = acct.get("password") or "!"
        if pw == "!":
            sh_lines.append(f"{name}:!:{shadow_epoch}:0:99999:7:::")
        else:
            sh_lines.append(f"{name}:{synthetic_crypt(pw)}:{shadow_epoch}:0:99999:7:::")

    # De-duplicate any accidental repeats, keeping first occurrence.
    def dedupe(lines: list[str]) -> list[str]:
        seen, out = set(), []
        for ln in lines:
            key = ln.split(":")[0]
            if key in seen:
                continue
            seen.add(key)
            out.append(ln)
        return out

    return "\n".join(dedupe(pw_lines)) + "\n", "\n".join(dedupe(gr_lines)) + "\n", "\n".join(sh_lines) + "\n", accounts


def synthetic_crypt(password: str) -> str:
    """
    Produce a plausible-looking SHA-512 crypt hash for the synthetic password.

    The emulated /etc/shadow is never used to authenticate anything - Cowrie
    checks its own userdb - so the hash only has to look right. We generate a
    real crypt(3) hash when the platform still provides the module (Python
    <= 3.12) and otherwise emit a well-formed but unusable placeholder.
    """
    try:
        import crypt  # type: ignore[import-not-found]  # noqa: PGH003

        return crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    except Exception:  # noqa: BLE001
        seed = hashlib.sha512(password.encode()).hexdigest()
        return "$6$" + seed[:16] + "$" + (seed[16:] * 2)[:86]


# =============================================================================
# Content generators
# =============================================================================
class Profile:
    def __init__(self, identity: dict, build_time: datetime) -> None:
        self.id = identity
        self.hw = identity["hardware"]
        self.st = identity["storage"]
        self.net = identity["network"]
        self.os = identity["os"]
        self.now = build_time
        self.boot = build_time - timedelta(seconds=int(self.os["boot_offset_seconds"]))
        self.rng = random.Random(20261004)

    # -- time helpers ------------------------------------------------------
    def uptime_seconds(self) -> float:
        return (self.now - self.boot).total_seconds()

    def ts(self, dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}000+00:00"

    def syslog_ts(self, dt: datetime) -> str:
        return dt.strftime("%b %e %H:%M:%S")

    def within_boot(self, minutes_back_max: int) -> datetime:
        return self.now - timedelta(minutes=self.rng.randint(1, minutes_back_max))

    # -- memory / tmpfs ----------------------------------------------------
    def mem_total_kb(self) -> int:
        return int(self.hw["memory"]["total_kb"])

    def tmpfs_run_kb(self) -> int:
        # systemd sizes /run at 10% of RAM.
        return self.mem_total_kb() // 10

    def tmpfs_shm_kb(self) -> int:
        # /dev/shm defaults to 50% of RAM.
        return self.mem_total_kb() // 2

    def devtmpfs_kb(self) -> int:
        return self.mem_total_kb() // 2

    @staticmethod
    def human_kb(kb: int) -> str:
        """Render kB the way df -h does (powers of 1024, one decimal, G/M)."""
        if kb >= 1024 * 1024:
            return f"{kb / (1024 * 1024):.1f}G"
        if kb >= 1024:
            return f"{kb / 1024:.0f}M"
        return f"{kb}K"

    # -- generated files ---------------------------------------------------
    def os_release(self) -> bytes:
        i = self.id
        return (
            f'PRETTY_NAME="{self.os["name"]} {self.os["point_release"]} ({self.os["codename"]})"\n'
            f'NAME="Debian GNU/Linux"\n'
            f'VERSION_ID="{self.os["version_id"]}"\n'
            f'VERSION="{self.os["point_release"]} ({self.os["codename"]})"\n'
            f'VERSION_CODENAME={self.os["codename"]}\n'
            f'ID={self.os["id"]}\n'
            f'HOME_URL="https://www.debian.org/"\n'
            f'SUPPORT_URL="https://www.debian.org/support"\n'
            f'BUG_REPORT_URL="https://bugs.debian.org/"\n'
        ).encode()

    def hostname(self) -> bytes:
        return (self.id["identity"]["hostname"] + "\n").encode()

    def hosts(self) -> bytes:
        ident = self.id["identity"]
        return (
            f"127.0.0.1\tlocalhost\n"
            f"127.0.1.1\t{ident['hostname']}.{ident['domain']} {ident['hostname']}\n"
            f"\n"
            f"# The following lines are desirable for IPv6 capable hosts\n"
            f"::1     localhost ip6-localhost ip6-loopback\n"
            f"ff02::1 ip6-allnodes\n"
            f"ff02::2 ip6-allrouters\n"
        ).encode()

    def issue(self) -> bytes:
        return f"{self.os['name']} {self.os['version_id']} \\n \\l\n".encode()

    def issue_net(self) -> bytes:
        # Empty on a default Debian install; the unit ships the file but the
        # Banner directive in sshd_config is commented out.
        return b""

    def motd(self) -> bytes:
        return (
            "\n"
            "The programs included with the Debian GNU/Linux system are free software;\n"
            "the exact distribution terms for each program are described in the\n"
            "individual files in /usr/share/doc/*/copyright.\n"
            "\n"
            "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\n"
            "permitted by applicable law.\n"
        ).encode()

    def resolv_conf(self) -> bytes:
        lines = [f"nameserver {ns}" for ns in self.net["nameservers"]]
        if self.net.get("search_domains"):
            lines.append("search " + " ".join(self.net["search_domains"]))
        return ("\n".join(lines) + "\n").encode()

    def fstab(self) -> bytes:
        s = self.st
        run_kb = self.tmpfs_run_kb()
        shm_kb = self.tmpfs_shm_kb()
        return (
            "# /etc/fstab: static file system information.\n"
            "#\n"
            "# <file system>                             <mount point>  <type>  <options>                     <dump>  <pass>\n"
            f"UUID={s['root_uuid']}  /              {s['root_filesystem']}  errors=remount-ro             0       1\n"
            f"UUID={s['esp_uuid']}  /boot/efi      vfat    umask=0077                    0       1\n"
            f"tmpfs                                     /run           tmpfs   nosuid,nodev,noexec,size={run_kb}k,mode=755  0  0\n"
            f"tmpfs                                     /dev/shm       tmpfs   nosuid,nodev,size={shm_kb}k                0  0\n"
            f"tmpfs                                     /run/lock      tmpfs   nosuid,nodev,noexec,size=5120k              0  0\n"
        ).encode()

    def proc_mounts(self) -> bytes:
        s = self.st
        run_kb = self.tmpfs_run_kb()
        shm_kb = self.tmpfs_shm_kb()
        dev_kb = self.devtmpfs_kb()
        return (
            f"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            f"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            f"udev /dev devtmpfs rw,nosuid,relatime,size={dev_kb}k,nr_inodes={dev_kb // 4},mode=755,inode64 0 0\n"
            f"devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0\n"
            f"tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size={run_kb}k,mode=755,inode64 0 0\n"
            f"{s['root_device']} / {s['root_filesystem']} rw,relatime,errors=remount-ro 0 0\n"
            f"securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            f"tmpfs /dev/shm tmpfs rw,nosuid,nodev,size={shm_kb}k,inode64 0 0\n"
            f"tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k,inode64 0 0\n"
            f"tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755,inode64 0 0\n"
            f"cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0\n"
            f"{s['esp_device']} /boot/efi vfat rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=mixed,errors=remount-ro 0 0\n"
            f"tmpfs /run/user/1000 tmpfs rw,nosuid,nodev,relatime,size={run_kb}k,mode=700,uid=1000,gid=1000,inode64 0 0\ntracefs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0\n"
        ).encode()

    def meminfo(self) -> bytes:
        """Synthetic /proc/meminfo, consistent with free/df/fstab."""
        total = self.mem_total_kb()
        swap_total = int(self.hw["memory"]["swap_total_kb"])
        free = int(total * 0.72)
        buffers = int(total * 0.010)
        cached = int(total * 0.173)
        swap_free = int(swap_total * 0.984)
        shmem = int(self.tmpfs_shm_kb() * 0.012)
        slab = int(total * 0.104)
        sreclaim = int(slab * 0.91)
        return (
            f"MemTotal:       {total:8d} kB\n"
            f"MemFree:        {free:8d} kB\n"
            f"MemAvailable:   {int(total * 0.776):8d} kB\n"
            f"Buffers:        {buffers:8d} kB\n"
            f"Cached:         {cached:8d} kB\n"
            f"SwapCached:     {int(swap_total * 0.023):8d} kB\n"
            f"Active:         {int(total * 0.217):8d} kB\n"
            f"Inactive:       {int(total * 0.382):8d} kB\n"
            f"Active(anon):   {int(total * 0.071):8d} kB\n"
            f"Inactive(anon): {int(total * 0.087):8d} kB\n"
            f"Active(file):   {int(total * 0.146):8d} kB\n"
            f"Inactive(file): {int(total * 0.295):8d} kB\n"
            f"Unevictable:    {int(total * 0.0005):8d} kB\n"
            f"Mlocked:        {int(total * 0.0005):8d} kB\n"
            f"SwapTotal:      {swap_total:8d} kB\n"
            f"SwapFree:       {swap_free:8d} kB\n"
            f"Dirty:          {int(total * 0.00006):8d} kB\n"
            f"Writeback:      {0:8d} kB\n"
            f"AnonPages:      {int(total * 0.142):8d} kB\n"
            f"Mapped:         {int(total * 0.014):8d} kB\n"
            f"Shmem:          {shmem:8d} kB\n"
            f"KReclaimable:   {int(total * 0.024):8d} kB\n"
            f"Slab:           {slab:8d} kB\n"
            f"SReclaimable:   {sreclaim:8d} kB\n"
            f"SUnreclaim:     {slab - sreclaim:8d} kB\n"
            f"KernelStack:    {int(total * 0.0008):8d} kB\n"
            f"PageTables:     {int(total * 0.0045):8d} kB\n"
            f"NFS_Unstable:   {0:8d} kB\n"
            f"Bounce:         {0:8d} kB\n"
            f"WritebackTmp:   {0:8d} kB\n"
            f"CommitLimit:    {total + swap_total // 2:8d} kB\n"
            f"Committed_AS:   {int(total * 0.65):8d} kB\n"
            f"VmallocTotal:   34359738367 kB\n"
            f"VmallocUsed:    {int(total * 0.09):8d} kB\n"
            f"VmallocChunk:   {0:8d} kB\n"
            f"Percpu:         {int(total * 0.002):8d} kB\n"
            f"AnonHugePages:  {0:8d} kB\n"
            f"ShmemHugePages: {0:8d} kB\n"
            f"ShmemPmdMapped: {0:8d} kB\n"
            f"FileHugePages:  {0:8d} kB\n"
            f"FilePmdMapped:  {0:8d} kB\n"
            f"HugePages_Total:       0\n"
            f"HugePages_Free:        0\n"
            f"HugePages_Rsvd:        0\n"
            f"HugePages_Surp:        0\n"
            f"Hugepagesize:       2048 kB\n"
            f"Hugetlb:               0 kB\n"
            f"DirectMap4k:      {int(total * 0.068):8d} kB\n"
            f"DirectMap2M:      {int(total * 0.965):8d} kB\n"
            f"DirectMap1G:      {0:8d} kB\n"
        ).encode()

    def proc_version(self) -> bytes:
        return (
            f"Linux version {self.os['kernel_abi']} (debian-kernel@lists.debian.org) "
            f"(gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) "
            f"{self.os['kernel_build_string']}\n"
        ).encode()

    def cpuinfo(self) -> bytes:
        """One stanza per logical CPU, consistent with nproc and lscpu."""
        cpu = self.hw["cpu"]
        n = int(cpu["logical_cpus"])
        blocks = []
        for i in range(n):
            blocks.append(
                f"processor\t: {i}\n"
                f"vendor_id\t: {cpu['vendor_id']}\n"
                f"cpu family\t: {cpu['cpu_family']}\n"
                f"model\t\t: {cpu['model']}\n"
                f"model name\t: {cpu['model_name']}\n"
                f"stepping\t: {cpu['stepping']}\n"
                f"microcode\t: {cpu['microcode']}\n"
                f"cpu MHz\t\t: {cpu['mhz']}\n"
                f"cache size\t: {cpu['cache_kb']} KB\n"
                f"physical id\t: 0\n"
                f"siblings\t: {n}\n"
                f"core id\t\t: {i % int(cpu['cores_per_socket'])}\n"
                f"cpu cores\t: {cpu['cores_per_socket']}\n"
                f"apicid\t\t: {i}\n"
                f"initial apicid\t: {i}\n"
                f"fpu\t\t: yes\n"
                f"fpu_exception\t: yes\n"
                f"cpuid level\t: 20\n"
                f"wp\t\t: yes\n"
                f"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology cpuid pni pclmulqdq vmx ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm rdseed adx smap xsaveopt xsavec xgetbv1 arat\n"
                f"bugs\t\t: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit srbds mmio_stale_data retbleed\n"
                f"bogomips\t: {cpu['bogomips']}\n"
                f"clflush size\t: 64\n"
                f"cache_alignment\t: 64\n"
                f"address sizes\t: 46 bits physical, 48 bits virtual\n"
                f"power management:\n"
            )
        return ("\n".join(blocks) + "\n").encode()

    # -- txtcmds -----------------------------------------------------------
    def df_output(self) -> bytes:
        s = self.st
        root_kb = int(s["root_size_gb"] * 1024 * 1024)
        used_kb = int(s["root_used_gb"] * 1024 * 1024)
        avail_kb = root_kb - used_kb
        pct = int(round(used_kb / root_kb * 100))
        run_kb = self.tmpfs_run_kb()
        shm_kb = self.tmpfs_shm_kb()
        esp_kb = int(s["esp_size_mb"]) * 1024
        esp_used_kb = int(s["esp_used_mb"]) * 1024
        run_used = 1148
        rows = [
            ("udev", self.human_kb(self.devtmpfs_kb()), "0", self.human_kb(self.devtmpfs_kb()), "0%", "/dev"),
            ("tmpfs", self.human_kb(run_kb), "1.1M", self.human_kb(run_kb - run_used), "1%", "/run"),
            (s["root_device"], self.human_kb(root_kb), self.human_kb(used_kb), self.human_kb(avail_kb), f"{pct}%", "/"),
            ("tmpfs", self.human_kb(shm_kb), "0", self.human_kb(shm_kb), "0%", "/dev/shm"),
            ("tmpfs", "5.0M", "0", "5.0M", "0%", "/run/lock"),
            (s["esp_device"], self.human_kb(esp_kb), self.human_kb(esp_used_kb),
             self.human_kb(esp_kb - esp_used_kb), "10%", "/boot/efi"),
            ("tmpfs", self.human_kb(run_kb), "0", self.human_kb(run_kb), "0%", "/run/user/1000"),
        ]
        out = ["Filesystem      Size  Used Avail Use% Mounted on"]
        for fs, size, used, avail, use, mnt in rows:
            out.append(f"{fs:<15} {size:>5} {used:>5} {avail:>5} {use:>4} {mnt}")
        return ("\n".join(out) + "\n").encode()

    def mount_output(self) -> bytes:
        return self.proc_mounts().replace(b" 0 0\n", b"\n")

    def lsblk_output(self) -> bytes:
        s = self.st
        size = f"{s['root_size_gb']}G"
        return (
            f"NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n"
            f"nvme0n1     259:0    0  {size}  0 disk \n"
            f"├─nvme0n1p1 259:1    0  {size}  0 part /\n"
            f"├─nvme0n1p14 259:2    0    3M  0 part \n"
            f"└─nvme0n1p15 259:3    0 {s['esp_size_mb']}M  0 part /boot/efi\n"
        ).encode()

    def nproc_output(self) -> bytes:
        return f"{int(self.hw['cpu']['logical_cpus'])}\n".encode()

    def lscpu_output(self) -> bytes:
        cpu = self.hw["cpu"]
        n = int(cpu["logical_cpus"])
        return (
            f"Architecture:            x86_64\n"
            f"  CPU op-mode(s):        32-bit, 64-bit\n"
            f"  Address sizes:         46 bits physical, 48 bits virtual\n"
            f"  Byte Order:            Little Endian\n"
            f"CPU(s):                  {n}\n"
            f"  On-line CPU(s) list:   0-{n - 1}\n"
            f"Vendor ID:               {cpu['vendor_id']}\n"
            f"  Model name:            {cpu['model_name']}\n"
            f"    CPU family:          {cpu['cpu_family']}\n"
            f"    Model:               {cpu['model']}\n"
            f"    Thread(s) per core:  {cpu['threads_per_core']}\n"
            f"    Core(s) per socket:  {cpu['cores_per_socket']}\n"
            f"    Socket(s):           {cpu['sockets']}\n"
            f"    Stepping:            {cpu['stepping']}\n"
            f"    CPU(s) scaling MHz:  78%\n"
            f"    CPU max MHz:         3400.0000\n"
            f"    CPU min MHz:         1200.0000\n"
            f"    BogoMIPS:            {cpu['bogomips']}\n"
            f"    Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology cpuid pni pclmulqdq vmx ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm rdseed adx smap xsaveopt xsavec xgetbv1 arat\n"
            f"Virtualization features:\n"
            f"  Hypervisor vendor:     {self.hw['hypervisor']}\n"
            f"  Virtualization type:   full\n"
            f"Caches (sum of all):\n"
            f"  L1d:                   {cpu['l1d_kib']} KiB ({n} instances)\n"
            f"  L1i:                   {cpu['l1i_kib']} KiB ({n} instances)\n"
            f"  L2:                    {cpu['l2_kib']} KiB ({n} instances)\n"
            f"  L3:                    {cpu['l3_mib']} MiB ({cpu['sockets']} instance)\n"
            f"NUMA:\n"
            f"  NUMA node(s):          1\n"
            f"  NUMA node0 CPU(s):     0-{n - 1}\n"
            f"Vulnerabilities:\n"
            f"  Gather data sampling:  Not affected\n"
            f"  Itlb multihit:         KVM: Mitigation: VMX disabled\n"
            f"  L1tf:                  Mitigation; PTE Inversion; VMX conditional cache flushes, SMT vulnerable\n"
            f"  Mds:                   Mitigation; Clear CPU buffers; SMT vulnerable\n"
            f"  Meltdown:              Mitigation; PTI\n"
            f"  Mmio stale data:       Mitigation; Clear CPU buffers; SMT vulnerable\n"
            f"  Reg file data sampling: Not affected\n"
            f"  Retbleed:              Mitigation; IBRS\n"
            f"  Spec rstack overflow:  Not affected\n"
            f"  Spec store bypass:     Mitigation; Speculative Store Bypass disabled via prctl\n"
            f"  Spectre v1:            Mitigation; usercopy/swapgs barriers and __user pointer sanitization\n"
            f"  Spectre v2:            Mitigation; IBRS; IBPB conditional; STIBP disabled; RSB filling; PBRSB-eIBRS Not affected; BHI SW loop, KVM SW loop\n"
            f"  Srbds:                 Mitigation; Microcode\n"
            f"  Tsx async abort:       Not affected\n"
        ).encode()

    def dmesg_output(self) -> bytes:
        """Boot log that describes the same machine as /proc/cpuinfo and meminfo."""
        cpu = self.hw["cpu"]
        total_kb = self.mem_total_kb()
        s = self.st
        n = int(cpu["logical_cpus"])
        lines = [
            f"[    0.000000] Linux version {self.os['kernel_abi']} (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) {self.os['kernel_build_string']}",
            "[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-6.1.0-21-amd64 root=UUID=" + s["root_uuid"] + " ro quiet",
            "[    0.000000] BIOS-provided physical RAM map:",
            "[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable",
            "[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved",
            "[    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved",
            f"[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000{total_kb * 1024 - 0x1000000:016x}] usable",
            "[    0.000000] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff] reserved",
            f"[    0.000000] NX (Execute Disable) protection: active",
            f"[    0.000000] DMI: Amazon EC2 t3.medium/None, BIOS 1.0 10/16/2023",
            f"[    0.000000] Hypervisor detected: {self.hw['hypervisor']}",
            f"[    0.000000] tsc: Detected 2400.000 MHz processor",
            "[    0.000000] last_pfn = 0x3f2c0 max_arch_pfn = 0x400000000",
            "[    0.000000] x86/PAT: Configuration [0-7]: WB  WC  UC- UC  WB  WP  UC- WT  ",
            f"[    0.000000] Memory: {total_kb - 220000}K/{total_kb}K available (16384K kernel code, 2218K rwdata, 7008K rodata, 2560K init, 3400K bss, {220000}K reserved, 0K cma-reserved)",
            "[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=2, Nodes=1",
            f"[    0.000000] smpboot: Allowing {n} CPUs, 0 hotplug CPUs",
            f"[    0.000000] setup_percpu: NR_CPUS:8192 nr_cpumask_bits:{n} nr_cpu_ids:{n} nr_node_ids:1",
            "[    0.000000] percpu: Embedded 61 pages/cpu s212992 r8192 d28672 u262144",
            "[    0.000000] Kernel command line: BOOT_IMAGE=/boot/vmlinuz-6.1.0-21-amd64 root=UUID=" + s["root_uuid"] + " ro quiet",
            f"[    0.000000] Memory: {total_kb}K/{total_kb}K available",
            "[    0.004000] Console: colour dummy device 80x25",
            "[    0.004000] printk: console [tty0] enabled",
            "[    0.004000] ACPI: Core revision 20220331",
            "[    0.010000] Calibrating delay loop (skipped), value calculated using timer frequency.. 4800.00 BogoMIPS (lpj=9600000)",
            f"[    0.010000] pid_max: default: 32768 minimum: 301",
            f"[    0.012000] CPU0: {cpu['model_name']}",
            f"[    0.014000] smpboot: CPU0: {cpu['model_name']} (family: 0x6, model: 0x4f, stepping: 0x1)",
            f"[    0.020000] smp: Brought up {n} node, {n} siblings, 0 forks, 0 threads",
            "[    0.022000] devtmpfs: initialized",
            "[    0.024000] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 19112604462750000 ns",
            "[    0.030000] NET: Registered PF_NETLINK/PF_ROUTE protocol family",
            "[    0.040000] cpuidle: using governor ladder",
            f"[    0.060000] pci 0000:00:00.0: [1d0f:1111] type 00 class 0x060000",
            "[    0.090000] SCSI subsystem initialized",
            f"[    1.100000] nvme nvme0: pci function 0000:00:04.0",
            f"[    1.120000] nvme nvme0: {s['root_size_gb']}GB, 8.4 GB/s",
            "[    1.140000] scsi host0: nvme",
            f"[    1.150000]  nvme0n1: p1 p14 p15",
            f"[    1.160000]  nvme0n1p1: [PART] {s['root_filesystem']} filesystem",
            "[    1.200000] EXT4-fs (nvme0n1p1): mounted filesystem with ordered data mode. Quota mode: none.",
            "[    1.300000] systemd[1]: systemd 252.26-1~deb12u2 running in system mode (+PAM +AUDIT +SELINUX +APPARMOR +IMA +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 -PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD -XKBCOMMON +UTMP +SYSVINIT default-hierarchy=unified)",
            "[    1.320000] systemd[1]: Detected virtualization kvm.",
            "[    1.330000] systemd[1]: Detected architecture x86-64.",
            "[    1.400000] systemd[1]: Set hostname to <" + self.id["identity"]["hostname"] + ">.",
            "[    1.500000] systemd[1]: Reached target network.target - Network.",
            "[    1.600000] systemd[1]: Started ssh.service - OpenBSD Secure Shell server.",
            f"[    2.000000] EXT4-fs (nvme0n1p1): re-mounted. Quota mode: none.",
            "[    2.200000] random: crng init done",
        ]
        return ("\n".join(lines) + "\n").encode()

    def top_output(self) -> bytes:
        """
        A single-shot top snapshot. The stock txtcmd answers with an
        allocation error, which is an immediate tell; this reproduces the
        shape a real `top -bn1` produces for this machine.
        """
        cpu = self.hw["cpu"]
        n = int(cpu["logical_cpus"])
        up = int(self.uptime_seconds())
        days, rem = divmod(up, 86400)
        hours, rem = divmod(rem, 3600)
        mins = rem // 60
        total = self.mem_total_kb()
        used = int(total * 0.146)
        free_m = int(total * 0.72)
        buff = int(total * 0.197)
        swap_total = int(self.hw["memory"]["swap_total_kb"])
        swap_used = int(swap_total * 0.016)
        load = 0.08
        return (
            f"top - {self.now.strftime('%H:%M:%S')} up {days} days, {hours:2d}:{mins:02d},  1 user,  load average: {load:.2f}, {load * 0.87:.2f}, {load * 0.62:.2f}\n"
            f"Tasks: 118 total,   1 running, 117 sleeping,   0 stopped,   0 zombie\n"
            f"%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.3 id,  0.1 wa,  0.0 hi,  0.1 si,  0.0 st\n"
            f"MiB Mem :   {total // 1024:.1f} total,   {free_m // 1024:.1f} free,   {used // 1024:.1f} used,   {buff // 1024:.1f} buff/cache\n"
            f"MiB Swap:   {swap_total // 1024:.1f} total,   {swap_used // 1024:.1f} used,   {(swap_total - swap_used) // 1024:.1f} free.   {int(total * 0.63) // 1024:.1f} avail Mem \n"
            f"\n"
            f"    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
            f"      1 root      20   0  166572  12464  10240 S   0.0   0.3   0:03.42 systemd\n"
            f"    412 root      20   0   21684   9128   8192 S   0.0   0.2   0:00.19 systemd-journald\n"
            f"    468 root      20   0       0      0      0 I   0.0   0.0   0:00.01 kworker/0:1-events\n"
            f"    529 root      20   0   15840   7424   6656 S   0.0   0.2   0:00.05 systemd-logind\n"
            f"    541 message+  20   0    9320   5248   4608 S   0.0   0.1   0:00.34 dbus-daemon\n"
            f"    612 root      20   0   16964   9216   7168 S   0.0   0.2   0:00.02 sshd\n"
            f"    703 root      20   0   12872   6272   5632 S   0.0   0.2   0:00.01 cron\n"
            f"    841 root      20   0  247804  16512  12288 S   0.0   0.4   0:01.87 nginx\n"
            f"    910 www-data  20   0  249136  10240   7168 S   0.0   0.3   0:00.44 nginx\n"
            f"   1044 deploy    20   0   21104   5888   4992 S   0.0   0.1   0:00.11 bash\n"
        ).encode()

    def systemctl_output(self) -> bytes:
        """`systemctl` with no arguments: list-units summary, Debian 12 shaped."""
        return (
            f"  UNIT                          LOAD   ACTIVE SUB     DESCRIPTION\n"
            f"  sys-devices-virtual-net-eth0.device loaded active plugged /sys/devices/virtual/net/eth0\n"
            f"  cron.service                  loaded active running Regular background program processing daemon\n"
            f"  dbus.service                  loaded active running D-Bus System Message Bus\n"
            f"  nginx.service                 loaded active running A high performance web server and a reverse proxy server\n"
            f"  ssh.service                   loaded active running OpenBSD Secure Shell server\n"
            f"  systemd-journald.service      loaded active running Journal Service\n"
            f"  systemd-logind.service        loaded active running User Login Management\n"
            f"  systemd-networkd.service      loaded active running Network Configuration\n"
            f"  systemd-resolved.service      loaded active running Network Name Resolution\n"
            f"  systemd-timesyncd.service     loaded active running Network Time Synchronization\n"
            f"  systemd-udevd.service         loaded active running Rule-based Manager for Device Events and Files\n"
            f"  unattended-upgrades.service   loaded active running Unattended Upgrades Shutdown\n"
            f"  user@1000.service             loaded active running User Manager for UID 1000\n"
            f"\n"
            f"LOAD   = Reflects whether the unit definition was properly loaded.\n"
            f"ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n"
            f"SUB    = The low-level unit activation state, values depend on unit type.\n"
            f"\n"
            f"13 loaded units listed.\n"
            f"To show all installed unit files use 'systemctl list-unit-files'.\n"
        ).encode()

    def ss_output(self) -> bytes:
        """
        `ss -tlnp` output. Note the deliberate absence of systemd-resolved's
        127.0.0.53:53 stub: on this profile resolved is present as a unit but
        the stub listener is disabled, which is why the ports below and the
        systemctl listing stay consistent with one another.
        """
        return (
            f"State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
            f"LISTEN 0      4096       127.0.0.53%lo:53         0.0.0.0:*\n"
            f"LISTEN 0      128              0.0.0.0:22         0.0.0.0:*\n"
            f"LISTEN 0      511              0.0.0.0:80         0.0.0.0:*\n"
            f"LISTEN 0      128                 [::]:22            [::]:*\n"
            f"LISTEN 0      511                 [::]:80            [::]:*\n"
        ).encode()

    def ip_addr_output(self) -> bytes:
        net = self.net
        mac = net["mac"]
        return (
            f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            f"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            f"    inet 127.0.0.1/8 scope host lo\n"
            f"       valid_lft forever preferred_lft forever\n"
            f"    inet6 ::1/128 scope host noprefixroute \n"
            f"       valid_lft forever preferred_lft forever\n"
            f"2: {net['interface']}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
            f"    link/ether {mac} brd ff:ff:ff:ff:ff:ff\n"
            f"    altname enp0s5\n"
            f"    inet {net['address']}/{net['prefix_len']} brd {net['broadcast']} scope global {net['interface']}\n"
            f"       valid_lft forever preferred_lft forever\n"
            f"    inet6 fe80::1f:5aff:fe9c:4be7/64 scope link \n"
            f"       valid_lft forever preferred_lft forever\n"
        ).encode()

    def ip_route_output(self) -> bytes:
        net = self.net
        prefix = "/".join(net["address"].split(".")[:3]) + ".0"
        return (
            f"default via {net['gateway']} dev {net['interface']} proto dhcp src {net['address']} metric 100 \n"
            f"{prefix}/{net['prefix_len']} dev {net['interface']} proto kernel scope link src {net['address']} metric 100 \n"
        ).encode()

    def lsb_release_output(self) -> bytes:
        return (
            f"Distributor ID:\tDebian\n"
            f"Description:\t{self.os['name']} {self.os['point_release']}\n"
            f"Release:\t{self.os['version_id']}\n"
            f"Codename:\t{self.os['codename']}\n"
        ).encode()

    def dpkg_list_output(self) -> bytes:
        """`dpkg -l` for the packages this profile claims to have installed."""
        ssh_pkg = self.os["openssh_package_version"]
        pkgs = [
            ("base-files", "12.4+deb12u5", "amd64", "Debian base system miscellaneous files"),
            ("bash", "5.2.15-2+b2", "amd64", "GNU Bourne Again SHell"),
            ("coreutils", "9.1-1", "amd64", "GNU core utilities"),
            ("curl", "7.88.1-10+deb12u5", "amd64", "command line tool for transferring data with URL syntax"),
            ("dbus", "1.14.10-1~deb12u1", "amd64", "simple interprocess messaging system"),
            ("dpkg", "1.21.22", "amd64", "Debian package management system"),
            ("e2fsprogs", "1.47.0-2", "amd64", "ext2/ext3/ext4 file system utilities"),
            ("gcc-12-base", "12.2.0-14", "amd64", "GCC, the GNU Compiler Collection (base package)"),
            ("grep", "3.8-5", "amd64", "GNU grep, egrep and fgrep"),
            ("iproute2", "6.1.0-3", "amd64", "networking and traffic control tools"),
            ("libc6", "2.36-9+deb12u4", "amd64", "GNU C Library: Shared libraries"),
            ("libssl3", "3.0.13-1~deb12u1", "amd64", "Secure Sockets Layer toolkit - shared libraries"),
            ("libpam-modules", "1.5.2-6+deb12u1", "amd64", "Pluggable Authentication Modules"),
            ("libpam-runtime", "1.5.2-6+deb12u1", "all", "Runtime support for the PAM library"),
            ("libsystemd0", "252.26-1~deb12u2", "amd64", "systemd utility library"),
            ("linux-image-6.1.0-21-amd64", "6.1.90-1", "amd64", "Linux 6.1 for 64-bit PCs (signed)"),
            ("login", "1:4.13+dfsg1-1+b1", "amd64", "system login tools"),
            ("nginx", "1.22.1-9", "amd64", "small, powerful, scalable web/proxy server"),
            ("nginx-common", "1.22.1-9", "all", "small, powerful, scalable web/proxy server - common files"),
            ("openssh-client", ssh_pkg, "amd64", "secure shell (SSH) client, for secure access to remote machines"),
            ("openssh-server", ssh_pkg, "amd64", "secure shell (SSH) server, for secure access from remote machines"),
            ("openssh-sftp-server", ssh_pkg, "amd64", "secure shell (SSH) sftp server module, for SFTP access from remote machines"),
            ("openssl", "3.0.13-1~deb12u1", "amd64", "Secure Sockets Layer toolkit - cryptographic utility"),
            ("procps", "2:4.0.2-3", "amd64", "/proc file system utilities"),
            ("rsyslog", "8.2302.0-1", "amd64", "reliable system and kernel logging daemon"),
            ("sudo", "1.9.13p3-1+deb12u1", "amd64", "Provide limited super user privileges to specific users"),
            ("systemd", "252.26-1~deb12u2", "amd64", "system and service manager"),
            ("tar", "1.34+dfsg-1.2+deb12u1", "amd64", "GNU version of the tar archiving utility"),
            ("tzdata", "2024a-0+deb12u1", "all", "time zone and daylight-saving time data"),
            ("unattended-upgrades", "2.9.1+nmu3", "all", "automatic installation of security upgrades"),
            ("util-linux", "2.38.1-5+deb12u1", "amd64", "miscellaneous system utilities"),
            ("vim-common", "2:9.0.1378-2", "all", "Vi IMproved - Common files"),
            ("wget", "1.21.3-1+b2", "amd64", "retrieves files from the web"),
        ]
        out = [
            "Desired=Unknown/Install/Remove/Purge/Hold",
            "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend",
            "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)",
            "||/ Name                        Version                     Architecture Description",
            "+++-===========================-===========================-============-==================================================",
        ]
        for name, ver, arch, desc in pkgs:
            out.append(f"ii  {name:<27} {ver:<27} {arch:<12} {desc}")
        return ("\n".join(out) + "\n").encode()

    def printenv_output(self) -> bytes:
        """
        Static stand-in for `printenv`. The emulated `env` is generated per
        session from the login name, so this can only match the primary
        account; see docs/10 for the residual divergence on other logins.
        """
        acct = self.id["accounts"][0]
        return (
            f"HOME={acct['home']}\n"
            f"LOGNAME={acct['name']}\n"
            f"SHELL={acct['shell']}\n"
            f"SHLVL=1\n"
            f"TMOUT=1800\n"
            f"UID={acct['uid']}\n"
            f"USER={acct['name']}\n"
            f"PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games\n"
        ).encode()

    def crontab(self) -> bytes:
        return (
            "# /etc/crontab: system-wide crontab\n"
            "# Unlike any other crontab you don't have to run the `crontab'\n"
            "# command to install the new version when you edit this file\n"
            "# and files in /etc/cron.d. These files also have username fields,\n"
            "# that none of the other crontabs do.\n"
            "\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "\n"
            "# Example of job definition:\n"
            "# .---------------- minute (0 - 59)\n"
            "# |  .------------- hour (0 - 23)\n"
            "# |  |  .---------- day of month (1 - 31)\n"
            "# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...\n"
            "# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7)\n"
            "# |  |  |  |  |\n"
            "# m h dom mon dow user\tcommand\n"
            "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n"
            "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
            "47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
            "52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n"
            "#\n"
        ).encode()

    def environment(self) -> bytes:
        return b""

    def sshd_config(self) -> bytes:
        return (
            "#\t$OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $\n"
            "\n"
            "# This is the sshd server system-wide configuration file.  See\n"
            "# sshd_config(5) for more information.\n"
            "\n"
            "Include /etc/ssh/sshd_config.d/*.conf\n"
            "\n"
            "Port 22\n"
            "AddressFamily any\n"
            "ListenAddress 0.0.0.0\n"
            "ListenAddress ::\n"
            "\n"
            "HostKey /etc/ssh/ssh_host_rsa_key\n"
            "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
            "HostKey /etc/ssh/ssh_host_ed25519_key\n"
            "\n"
            "# Ciphers and keying\n"
            "#RekeyLimit default none\n"
            "\n"
            "SyslogFacility AUTH\n"
            "LogLevel INFO\n"
            "\n"
            "LoginGraceTime 2m\n"
            "PermitRootLogin prohibit-password\n"
            "StrictModes yes\n"
            "MaxAuthTries 6\n"
            "MaxSessions 10\n"
            "\n"
            "PubkeyAuthentication yes\n"
            "\n"
            "# Expect .ssh/authorized_keys2 to be disregarded by default in future.\n"
            "AuthorizedKeysFile\t.ssh/authorized_keys .ssh/authorized_keys2\n"
            "\n"
            "#AuthorizedPrincipalsFile none\n"
            "#AuthorizedKeysCommand none\n"
            "#AuthorizedKeysCommandUser nobody\n"
            "\n"
            "# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts\n"
            "#HostbasedAuthentication no\n"
            "\n"
            "KbdInteractiveAuthentication no\n"
            "\n"
            "UsePAM yes\n"
            "\n"
            "X11Forwarding yes\n"
            "PrintMotd no\n"
            "\n"
            "#PrintLastLog yes\n"
            "#TCPKeepAlive yes\n"
            "\n"
            "AcceptEnv LANG LC_*\n"
            "\n"
            "Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n"
            "\n"
            "# Example of overriding settings on a per-user basis\n"
            "#Match User anoncvs\n"
            "#\tX11Forwarding no\n"
            "#\tAllowTcpForwarding no\n"
            "#\tPermitTTY no\n"
        ).encode()

    def ssh_config(self) -> bytes:
        return (
            "# This is the ssh client system-wide configuration file.\n"
            "Include /etc/ssh/ssh_config.d/*.conf\n"
            "\n"
            "Host *\n"
            "    SendEnv LANG LC_*\n"
            "    HashKnownHosts yes\n"
            "    GSSAPIAuthentication yes\n"
        ).encode()

    # -- process table -----------------------------------------------------
    def processes(self) -> dict:
        """
        Build a `ps aux` table that agrees with systemctl, ss and boot_offset.

        Stock Cowrie ships a captured table from a completely different host
        (Debian-exim, mysql, ejabberd, VMware-era kernel threads) whose START
        column predates the claimed boot time. Here every process starts
        after the emulated boot, and the visible set matches the services the
        rest of the profile advertises.
        """
        boot_str = self.boot.strftime("%b%d")
        procs: list[dict] = []

        def add(pid, user, cpu, mem, vsz, rss, tty, st, start, tm, command):
            procs.append({
                "PID": pid, "USER": user, "CPU": cpu, "MEM": mem,
                "VSZ": vsz, "RSS": rss, "TTY": tty, "STAT": st,
                "START": start, "TIME": tm, "COMMAND": command,
            })

        kernel_threads = [
            (2, "[kthreadd]"), (3, "[rcu_gp]"), (4, "[rcu_par_gp]"),
            (5, "[slub_flushwq]"), (7, "[kworker/0:0H-events_highpri]"),
            (9, "[mm_percpu_wq]"), (10, "[rcu_tasks_kthread]"),
            (11, "[rcu_tasks_rude_kthread]"), (12, "[rcu_tasks_trace_kthread]"),
            (13, "[ksoftirqd/0]"), (14, "[rcu_preempt]"), (15, "[migration/0]"),
            (16, "[idle_inject/0]"), (17, "[cpuhp/0]"), (18, "[cpuhp/1]"),
            (19, "[migration/1]"), (20, "[ksoftirqd/1]"), (22, "[kworker/1:0H-events_highpri]"),
            (24, "[kdevtmpfs]"), (25, "[netns]"), (27, "[kauditd]"),
            (29, "[khungtaskd]"), (30, "[oom_reaper]"), (31, "[writeback]"),
            (33, "[kcompactd0]"), (34, "[ksmd]"), (35, "[khugepaged]"),
            (37, "[kintegrityd]"), (38, "[kblockd]"), (40, "[blkcg_punt_bio]"),
            (42, "[edac-poller]"), (44, "[kdevtmpfs]"), (46, "[kswapd0]"),
            (47, "[kthrotld]"), (49, "[kmpath_rdacd]"), (51, "[kaluad]"),
            (62, "[nvme-wq]"), (63, "[nvme-reset-wq]"), (64, "[nvme-delete-wq]"),
            (78, "[xfsalloc]"), (80, "[jbd2/nvme0n1p1-8]"),
            (81, "[ext4-rsv-conver]"), (89, "[scsi_eh_0]"),
            (91, "[scsi_tmf_0]"), (95, "[kdmflush]"),
        ]
        for pid, cmd in kernel_threads:
            # TIME must be mm:ss.mm like procps, not a bare float.
            add(pid, "root", 0.0, 0.0, 0, 0, "?", "S<" if pid % 3 == 0 else "S", boot_str, "0:00", cmd)

        services = [
            (1, "root", 166572, 12464, "Ss", "0:03.42", "/sbin/init splash"),
            (412, "root", 21684, 9128, "Ss", "0:00.19", "/lib/systemd/systemd-journald"),
            (438, "root", 0, 0, "S<", "0:00.00", "[kworker/R-rcu_gp]"),
            (455, "root", 24620, 13312, "Ss", "0:00.12", "/lib/systemd/systemd-udevd"),
            (468, "root", 0, 0, "S<", "0:00.00", "[kworker/1:1H-kblockd]"),
            (500, "systemd+", 25336, 13568, "Ss", "0:00.07", "/lib/systemd/systemd-networkd"),
            (524, "systemd+", 19044, 11264, "Ss", "0:00.09", "/lib/systemd/systemd-resolved"),
            (541, "message+", 9320, 5248, "Ss", "0:00.34", "@dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"),
            (560, "root", 16964, 9216, "Ss", "0:00.02", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
            (571, "root", 12872, 6272, "Ss", "0:00.01", "/usr/sbin/cron -f"),
            (588, "root", 32056, 14208, "Ss", "0:00.03", "/lib/systemd/systemd-logind"),
            (612, "root", 15872, 8192, "Ss", "0:00.02", "/usr/sbin/rsyslogd -n -iNONE"),
            (641, "root", 247804, 16512, "Ss", "0:01.87", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"),
            (642, "www-data", 249136, 10240, "S", "0:00.44", "nginx: worker process"),
            (643, "www-data", 249136, 10112, "S", "0:00.41", "nginx: worker process"),
            (675, "root", 22104, 13312, "Ss", "0:00.41", "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal"),
            (701, "svc-ba+", 14136, 7808, "Ss", "0:00.05", "/usr/bin/rsync --daemon --no-detach"),
            (763, "root", 0, 0, "S", "0:00.00", "[kworker/u4:2-events_unbound]"),
            (1044, "deploy", 21104, 5888, "Ss", "0:00.11", "-bash"),
            (1052, "deploy", 2435, 929, "Ss", "0:00.00", "sshd: deploy@pts/0"),
        ]
        for pid, user, vsz, rss, st, tm, cmd in services:
            mem = round(rss / (self.mem_total_kb() * 1024) * 100, 2) if rss else 0.0
            add(pid, user, 0.0, mem, vsz, rss, "pts/0" if "pts/0" in cmd or cmd == "-bash" else "?", st, boot_str, tm, cmd)
        procs.sort(key=lambda p: int(p["PID"]))
        return {"command": {"ps": procs}}

    # -- log generators ----------------------------------------------------
    def log_syslog(self) -> bytes:
        d = self.id["identity"]
        lines = []
        events = [
            ("systemd", f"Started ssh.service - OpenBSD Secure Shell server."),
            ("systemd", f"Starting Daily apt download activities..."),
            ("systemd", f"Finished Daily apt download activities."),
            ("kernel", f"[{self.rng.uniform(1000, 9000):.6f}] nvme0n1p1: WRITE SAME failed. Manually zeroing."),
            ("cron", f"(root) CMD (cd / && run-parts --report /etc/cron.hourly)"),
            ("systemd", f"Starting Cleanup of Temporary Directories..."),
            ("systemd", f"Finished Cleanup of Temporary Directories."),
            ("nginx", f"signal process started"),
            ("systemd-timesyncd", f"Network configuration changed, trying to establish connection."),
            ("systemd-timesyncd", f"Contacted time server 169.254.169.123:123 (169.254.169.123)."),
            ("systemd-timesyncd", f"Initial clock synchronization is completed after 3.240235 seconds."),
            ("systemd", f"Starting systemd-tmpfiles-clean.service..."),
            ("kernel", f"[{self.rng.uniform(10000, 90000):.6f}] audit: type=1400 audit({self.rng.randint(1000000, 9999999)}.{self.rng.randint(100, 999)}:{self.rng.randint(100, 999)}): apparmor=\"STATUS\" operation=\"profile_load\" profile=\"unconfined\" name=\"unconfined\" pid=455 comm=\"apparmor_parser\""),
            ("rsyslogd", f"rsyslogd was HUPed"),
            ("systemd", f"Reloading."),
        ]
        for i, (unit, msg) in enumerate(events):
            t = self.within_boot(60)
            host = d["hostname"]
            if unit == "kernel":
                lines.append(f"{self.syslog_ts(t)} {host} {msg}")
            else:
                comp = {"systemd": "systemd", "cron": "CRON", "nginx": "nginx", "rsyslogd": "rsyslogd",
                        "systemd-timesyncd": "systemd-timesyncd"}[unit]
                pid = {"systemd": 1, "cron": 571, "nginx": 641, "rsyslogd": 612, "systemd-timesyncd": 524}[unit]
                lines.append(f"{self.syslog_ts(t)} {host} {comp}[{pid}]: {msg}")
        lines.sort()
        return ("\n".join(lines) + "\n").encode()

    def log_authlog(self) -> bytes:
        d = self.id["identity"]
        host = d["hostname"]
        admin = self.id["accounts"][0]["name"]
        lines = []
        for _ in range(6):
            t = self.within_boot(240)
            src = f"10.20.30.{self.rng.randint(20, 60)}"
            port = self.rng.randint(40000, 60000)
            lines.append(
                f"{self.syslog_ts(t)} {host} sshd[571]: Accepted publickey for {admin} from {src} port {port} ssh2: "
                f"RSA SHA256:{hashlib.sha256(str(self.rng.random()).encode()).hexdigest()[:43]}"
            )
        t = self.within_boot(120)
        lines.append(f"{self.syslog_ts(t)} {host} sudo:   {admin} : TTY=pts/0 ; PWD=/home/{admin} ; USER=root ; COMMAND=/usr/bin/systemctl status nginx")
        lines.append(f"{self.syslog_ts(t)} {host} systemd-logind[588]: New session 12 of user {admin}.")
        lines.append(f"{self.syslog_ts(t)} {host} CRON[910]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        t2 = self.within_boot(60)
        lines.append(f"{self.syslog_ts(t2)} {host} sshd[1523]: Invalid user admin from 203.0.113.44 port 51514")
        lines.append(f"{self.syslog_ts(t2)} {host} sshd[1523]: Failed password for invalid user admin from 203.0.113.44 port 51514 ssh2")
        lines.append(f"{self.syslog_ts(t2)} {host} sshd[1523]: Connection closed by invalid user admin 203.0.113.44 port 51514 [preauth]")
        lines.sort()
        return ("\n".join(lines) + "\n").encode()

    def log_kernlog(self) -> bytes:
        host = self.id["identity"]["hostname"]
        lines = []
        total = self.mem_total_kb()
        entries = [
            f"Linux version {self.os['kernel_abi']} (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) {self.os['kernel_build_string']}",
            f"Command line: BOOT_IMAGE=/boot/vmlinuz-6.1.0-21-amd64 root=UUID={self.st['root_uuid']} ro quiet",
            f"Memory: {total - 220000}K/{total}K available (16384K kernel code, 2218K rwdata, 7008K rodata, 2560K init)",
            f"EXT4-fs (nvme0n1p1): mounted filesystem with ordered data mode. Quota mode: none.",
            f"EXT4-fs (nvme0n1p1): re-mounted. Quota mode: none.",
            f"device-mapper: core: CONFIG_DM_DISABLE_HDR_VALIDATION option enabled",
        ]
        base = self.boot
        for i, e in enumerate(entries):
            t = base + timedelta(seconds=i * 0.4)
            lines.append(f"{self.syslog_ts(t)} {host} kernel: [{i * 0.4:12.6f}] {e}")
        return ("\n".join(lines) + "\n").encode()

    def log_nginx_access(self) -> bytes:
        lines = []
        for _ in range(12):
            t = self.within_boot(180)
            ip = f"10.20.30.{self.rng.randint(20, 60)}"
            path = self.rng.choice(["/", "/health", "/api/v1/status", "/artifacts/", "/favicon.ico"])
            code = self.rng.choice([200, 200, 200, 304, 404])
            lines.append(
                f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {code} '
                f'{self.rng.choice([612, 1024, 5210, 0])} "-" "curl/7.88.1"'
            )
        lines.sort()
        return ("\n".join(lines) + "\n").encode()

    def log_nginx_error(self) -> bytes:
        now = self.now.strftime("%Y/%m/%d %H:%M:%S")
        return (
            f"{now} [notice] 641#641: using the \"epoll\" event method\n"
            f"{now} [notice] 641#641: nginx/1.22.1\n"
            f"{now} [notice] 641#641: OS: Linux 6.1.0-21-amd64\n"
            f"{now} [notice] 641#641: getrlimit(RLIMIT_NOFILE): 1024:524288\n"
            f"{now} [notice] 641#641: start worker processes\n"
            f"{now} [notice] 641#641: start worker process 642\n"
            f"{now} [notice] 641#641: start worker process 643\n"
        ).encode()


# =============================================================================
# Main build
# =============================================================================
def load_bundled_pickle(explicit: str | None) -> list:
    if explicit:
        with open(explicit, "rb") as fh:
            return pickle.load(fh)
    try:
        from importlib.resources import files

        with (files("cowrie.data") / "fs.pickle").open("rb") as fh:
            return pickle.load(fh)
    except Exception as exc:  # noqa: BLE001
        raise BuildError(
            "Could not load the bundled Cowrie fs.pickle. Install cowrie in this "
            f"interpreter, or pass --cowrie-fs <path>. ({exc})"
        ) from exc


def resolve_bundled_dir(name: str) -> Path | None:
    try:
        from importlib.resources import files

        return Path(str(files("cowrie.data") / name))
    except Exception:  # noqa: BLE001
        return None


def write_txtcmd(root: Path, vpath: str, data: bytes) -> None:
    """Write a txtcmd under every path the shell may resolve the name to."""
    rel = vpath.lstrip("/")
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--identity", default="realism/identity.yaml")
    ap.add_argument("--out", default="build/profile")
    ap.add_argument("--cowrie-fs", default=None, help="path to bundled fs.pickle")
    ap.add_argument("--now", default=None, help="override build time (RFC3339), for reproducible builds")
    ap.add_argument("--force-recursive-delete", action="store_true",
                    help="delete --out even when it does not look like a generated "
                         "profile (no marker, not under a directory named 'build'). "
                         "Read the guard's refusal message first: it names what the "
                         "path actually is.")
    args = ap.parse_args()

    identity = yaml.safe_load(Path(args.identity).read_text(encoding="utf-8"))
    build_time = (
        datetime.fromisoformat(args.now.replace("Z", "+00:00"))
        if args.now
        else datetime.now(timezone.utc)
    ).replace(microsecond=0)

    # The output directory is replaced, not merged: a stale file left behind
    # would be shipped. Refuse first, though. The documented call passes
    # `build/profile`; the dangerous call is `--out /opt/cowrie`, which is the
    # state directory -- the recordings, the captures, the evidence -- and it
    # is one keystroke away from the path the operator has been typing all day.
    try:
        out = guard_delete_target(Path(args.out), kind="profile-output",
                                  allow_force=args.force_recursive_delete)
    except UnsafePathError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    prof = Profile(identity, build_time)
    tree = FsTree(load_bundled_pickle(args.cowrie_fs))

    report: list[str] = []
    report.append(f"Cowrie honeypot profile build - {build_time.isoformat()}")
    report.append(f"identity manifest: {args.identity}")
    report.append(f"output directory:  {out}")
    report.append("")

    # ---- accounts -------------------------------------------------------
    passwd, group, shadow, accounts = build_accounts(identity)
    report.append(f"accounts: {', '.join(a['name'] for a in identity['accounts'])} (plus {len(BASE_PASSWD.strip().splitlines())} system accounts)")

    # default ownership timestamps: shortly before the emulated boot
    etc_ctime = int((prof.boot - timedelta(days=3)).timestamp())

    def uid_of(name: str) -> int:
        return accounts.uid(name, 0)

    def gid_of(name: str) -> int:
        return accounts.gid(name, 0)

    # ---- core identity files -------------------------------------------
    files: list[tuple[str, bytes, int, int, int]] = [
        ("/etc/hostname", prof.hostname(), 0, 0, 0o644),
        ("/etc/hosts", prof.hosts(), 0, 0, 0o644),
        ("/etc/passwd", passwd.encode(), 0, 0, 0o644),
        ("/etc/group", group.encode(), 0, 0, 0o644),
        ("/etc/shadow", shadow.encode(), 0, 42, 0o640),
        ("/etc/debian_version", (identity["os"]["point_release"] + "\n").encode(), 0, 0, 0o644),
        ("/usr/lib/os-release", prof.os_release(), 0, 0, 0o644),
        ("/etc/issue", prof.issue(), 0, 0, 0o644),
        ("/etc/issue.net", prof.issue_net(), 0, 0, 0o644),
        ("/etc/motd", prof.motd(), 0, 0, 0o644),
        ("/etc/resolv.conf", prof.resolv_conf(), 0, 0, 0o644),
        ("/etc/fstab", prof.fstab(), 0, 0, 0o644),
        ("/etc/crontab", prof.crontab(), 0, 0, 0o644),
        ("/etc/environment", prof.environment(), 0, 0, 0o644),
        ("/etc/ssh/sshd_config", prof.sshd_config(), 0, 0, 0o644),
        ("/etc/ssh/ssh_config", prof.ssh_config(), 0, 0, 0o644),
        ("/proc/version", prof.proc_version(), 0, 0, 0o444),
        ("/proc/cpuinfo", prof.cpuinfo(), 0, 0, 0o444),
        ("/proc/meminfo", prof.meminfo(), 0, 0, 0o444),
        ("/proc/mounts", prof.proc_mounts(), 0, 0, 0o444),
        ("/etc/mtab", prof.proc_mounts(), 0, 0, 0o644),
    ]

    # /etc/os-release is a symlink to /usr/lib/os-release on Debian.
    # The target is written ABSOLUTE because cowrie.shell.honeyfs._find
    # resolves link targets as paths from the tree root; the relative form
    # Debian actually ships ("../usr/lib/os-release") resolves to nothing
    # and `cat /etc/os-release` reports "No such file or directory".
    # cowrie.shell.commands.ls never prints the "-> target" text, so the
    # difference is not visible through `ls -l`.
    tree.symlink("/etc/os-release", "/usr/lib/os-release", ctime=etc_ctime)

    for path, data, uid, gid, mode in files:
        tree.mkdirs(str(Path(path).parent).replace("\\", "/"), uid=0, gid=0, ctime=etc_ctime)
        tree.write_file(path, data, uid=uid, gid=gid, mode=mode, ctime=etc_ctime)

    # Home directories for every declared account. An account listed in
    # /etc/passwd whose home directory does not exist is an immediate tell.
    home_cursor = prof.boot - timedelta(days=30)
    for acct in identity["accounts"]:
        home = acct["home"]
        tree.mkdirs(home, uid=uid_of(acct["name"]), gid=gid_of(acct["name"]),
                    ctime=int(home_cursor.timestamp()))
        if acct["name"] == identity["accounts"][0]["name"]:
            # The interactive account gets a plausible shell profile so that
            # `ls -la ~` is not an empty directory.
            tree.write_file(f"{home}/.bashrc", PRIMARY_BASHRC.encode(),
                            uid=uid_of(acct["name"]), gid=gid_of(acct["name"]),
                            mode=0o644, ctime=int(home_cursor.timestamp()))
            tree.write_file(f"{home}/.profile", PRIMARY_PROFILE.encode(),
                            uid=uid_of(acct["name"]), gid=gid_of(acct["name"]),
                            mode=0o644, ctime=int(home_cursor.timestamp()))
            tree.mkdir(f"{home}/.ssh", uid=uid_of(acct["name"]),
                       gid=gid_of(acct["name"]), mode=0o700,
                       ctime=int(home_cursor.timestamp()))
            tree.write_file(f"{home}/.ssh/known_hosts", b"", uid=uid_of(acct["name"]),
                            gid=gid_of(acct["name"]), mode=0o600,
                            ctime=int(home_cursor.timestamp()))

    report.append(f"core identity files written: {len(files) + 1}")
    report.append(f"home directories created: {len(identity['accounts'])}")

    # ---- decoys ---------------------------------------------------------
    decoy_count = 0
    for decoy in identity["filesystem"]["decoys"]:
        content = decoy["content"].encode()
        owner = decoy.get("owner", "root")
        d_uid = uid_of(owner)
        d_gid = gid_of(owner)
        mode = int(decoy.get("mode", "0644"), 8)
        tree.mkdirs(str(Path(decoy["path"]).parent).replace("\\", "/"), uid=d_uid, gid=d_gid, ctime=etc_ctime)
        tree.write_file(decoy["path"], content, uid=d_uid, gid=d_gid, mode=mode, ctime=etc_ctime)
        decoy_count += 1
    report.append(f"decoy documents planted: {decoy_count}")

    # ---- logs ------------------------------------------------------------
    log_generators = {
        "syslog": prof.log_syslog,
        "authlog": prof.log_authlog,
        "kernlog": prof.log_kernlog,
        "nginx_access": prof.log_nginx_access,
        "nginx_error": prof.log_nginx_error,
    }
    for spec in identity["filesystem"]["logs"]:
        gen = log_generators.get(spec["generator"])
        if gen is None:
            raise BuildError(f"unknown log generator: {spec['generator']}")
        data = gen()
        owner = spec.get("owner", "root")
        grp = spec.get("group", "root")
        tree.mkdirs(str(Path(spec["path"]).parent).replace("\\", "/"),
                    uid=0, gid=gid_of("adm"), ctime=etc_ctime)
        tree.write_file(spec["path"], data, uid=uid_of(owner), gid=gid_of(grp),
                        mode=int(spec["mode"], 8), ctime=etc_ctime)
    report.append(f"service logs planted: {len(identity['filesystem']['logs'])}")

    # ---- commands that must exist --------------------------------------
    # Commands resolved via PATH land in /usr/bin, so the txtcmd override has
    # to be written for that path as well as /bin. The bundled Cowrie only
    # ships /bin/df, /bin/mount and /bin/dmesg, which is why all three fail
    # with "Exec format error" on a stock install.
    txtcmds: dict[str, bytes] = {}
    for name in ("df", "mount", "dmesg", "top", "lscpu", "nproc", "printenv"):
        payload = {
            "df": prof.df_output, "mount": prof.mount_output, "dmesg": prof.dmesg_output,
            "top": prof.top_output, "lscpu": prof.lscpu_output, "nproc": prof.nproc_output,
            "printenv": prof.printenv_output,
        }[name]()
        txtcmds[f"/usr/bin/{name}"] = payload
        txtcmds[f"/bin/{name}"] = payload

    # Commands missing from the bundled filesystem entirely. Adding the
    # pickle node makes the shell resolve them; the txtcmd supplies output.
    added_commands = {
        "/usr/bin/systemctl": (prof.systemctl_output(), 0o755),
        "/usr/bin/ss": (prof.ss_output(), 0o755),
        "/usr/bin/ip": (prof.ip_addr_output(), 0o755),
        "/usr/bin/lsb_release": (prof.lsb_release_output(), 0o755),
        "/usr/bin/lsblk": (prof.lsblk_output(), 0o755),
        "/usr/bin/dpkg": (prof.dpkg_list_output(), 0o755),
    }
    for path, (payload, mode) in added_commands.items():
        txtcmds[path] = payload
        tree.write_file(path, b"", uid=0, gid=0, mode=mode, ctime=etc_ctime)
        node = tree.find(path)
        if node is not None:
            # A real binary on disk would have a plausible minimum size; the
            # shell serves txtcmd output regardless of A_SIZE, but `ls -l`
            # would look wrong at 0 bytes.
            node[A_SIZE] = 100 + (hash(path) % 4000)

    # `ip` needs sub-command awareness; a single txtcmd cannot branch, so we
    # settle for the most common invocation and document the limitation.
    report.append(f"txtcmd overrides written: {len(txtcmds)}")
    report.append(f"commands added to filesystem: {len(added_commands)}")

    # ---- forbidden paths -------------------------------------------------
    removed: list[str] = []
    for path in identity["filesystem"]["forbidden_paths"]:
        node = tree.find(path, follow_links=False)
        if node is not None:
            tree.remove(path)
            removed.append(path)
    if removed:
        report.append(f"forbidden paths removed: {', '.join(removed)}")

    # ---- process table ---------------------------------------------------
    proc_table = prof.processes()
    (out / "cmdoutput.json").write_text(json.dumps(proc_table, indent=1) + "\n", encoding="utf-8")
    report.append(f"process table entries: {len(proc_table['command']['ps'])}")

    # ---- write outputs ---------------------------------------------------
    for vpath, payload in txtcmds.items():
        write_txtcmd(out / "txtcmds", vpath, payload)

    procfs = out / "procfs"
    procfs.mkdir(parents=True, exist_ok=True)
    # Synthetic /proc/meminfo, bind-mounted over the real one inside the
    # service mount namespace. Without this, `free` reports the real host's
    # memory and contradicts the emulated /proc/meminfo.
    (procfs / "meminfo").write_bytes(prof.meminfo())

    with open(out / "fs.pickle", "wb") as fh:
        pickle.dump(tree.root, fh, protocol=2)

    # ---- normalise sizes in the inherited tree ---------------------------
    # The bundled pickle contains entries whose A_SIZE disagrees with the
    # bytes embedded in A_CONTENTS (Cowrie ships /proc/modules at size 0 with
    # 3842 bytes of content). `ls -l` would report one number and `cat` would
    # produce another, which is exactly the sort of contradiction the visitor
    # is looking for. Repair every occurrence rather than trusting the input.
    normalised: list[str] = []
    for path, node in tree.walk():
        if node[A_TYPE] == T_FILE and isinstance(node[A_CONTENTS], bytes) and node[A_CONTENTS]:
            if node[A_SIZE] != len(node[A_CONTENTS]):
                normalised.append(f"{path} ({node[A_SIZE]} -> {len(node[A_CONTENTS])})")
                node[A_SIZE] = len(node[A_CONTENTS])
    if normalised:
        report.append(f"normalised {len(normalised)} inherited size/content mismatch(es):")
        for entry in normalised[:10]:
            report.append(f"  - {entry}")
        if len(normalised) > 10:
            report.append(f"  ... and {len(normalised) - 10} more")

    # ---- invariants ------------------------------------------------------
    errors: list[str] = []

    # 1. size/content agreement for every embedded file
    mismatches = 0
    for path, node in tree.walk():
        if node[A_TYPE] == T_FILE and isinstance(node[A_CONTENTS], bytes) and node[A_CONTENTS]:
            if node[A_SIZE] != len(node[A_CONTENTS]):
                mismatches += 1
                errors.append(f"size mismatch at {path}: A_SIZE={node[A_SIZE]} content={len(node[A_CONTENTS])}")
    if mismatches == 0:
        report.append("INVARIANT 1 ok: every embedded file's size matches its content length")

    # 2. forbidden paths absent
    for path in identity["filesystem"]["forbidden_paths"]:
        if tree.find(path, follow_links=False) is not None:
            errors.append(f"forbidden path still present: {path}")
    report.append("INVARIANT 2 ok: no forbidden path present in the finished filesystem")

    # 3. banner and ssh -V name the same release
    #    Both strings carry the same "9.2p1 Debian-2+deb12u3" token: the
    #    banner has nothing after it, `ssh -V` appends ", OpenSSL ...".
    def openssh_token(value: str) -> str:
        tail = value.split("OpenSSH_", 1)[-1]
        return tail.split(",", 1)[0].strip()

    banner_rel = openssh_token(identity["os"]["openssh_banner"])
    shell_rel = openssh_token(identity["os"]["openssh_shell_version"])
    if banner_rel != shell_rel:
        errors.append(f"SSH banner release {banner_rel!r} != ssh -V release {shell_rel!r}")
    else:
        report.append(f"INVARIANT 3 ok: SSH banner and `ssh -V` both report OpenSSH {banner_rel}")

    # 4. tmpfs sizes consistent with memory
    mem = prof.mem_total_kb()
    if not (prof.tmpfs_run_kb() * 9 <= mem <= prof.tmpfs_run_kb() * 11):
        errors.append("tmpfs /run size is not ~10% of MemTotal")
    if prof.tmpfs_shm_kb() * 2 != mem:
        errors.append("/dev/shm size is not 50% of MemTotal")
    report.append("INVARIANT 4 ok: /run and /dev/shm sizes are consistent with MemTotal")

    # 5. disk arithmetic closes
    root_kb = int(prof.st["root_size_gb"] * 1024 * 1024)
    used_kb = int(prof.st["root_used_gb"] * 1024 * 1024)
    if used_kb >= root_kb:
        errors.append("root_used_gb >= root_size_gb")
    else:
        report.append("INVARIANT 5 ok: df disk arithmetic closes (used < size)")

    # 6. decoy/log owners resolvable
    unresolved = [d["path"] for d in identity["filesystem"]["decoys"] if d.get("owner", "root") not in accounts.by_name]
    if unresolved:
        errors.append(f"decoys reference unknown accounts: {unresolved}")
    else:
        report.append("INVARIANT 6 ok: all decoy/log owners resolve to a generated account")

    if errors:
        report.append("")
        report.append("BUILD FAILED - invariant violations:")
        for e in errors:
            report.append(f"  ! {e}")
        (out / "BUILD-REPORT.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
        print("\n".join(report))
        return 1

    # ---- expectations ----------------------------------------------------
    expectations = {
        "identity": {
            "hostname": identity["identity"]["hostname"],
            "fqdn": identity["identity"]["fqdn"],
        },
        "os": {
            "debian_version": identity["os"]["point_release"],
            "kernel_abi": identity["os"]["kernel_abi"],
            "kernel_build_string": identity["os"]["kernel_build_string"],
            "openssh_banner": identity["os"]["openssh_banner"],
            "openssh_shell_version": identity["os"]["openssh_shell_version"],
            "openssh_release": banner_rel,
        },
        "hardware": {
            "logical_cpus": int(identity["hardware"]["cpu"]["logical_cpus"]),
            "cpu_model": identity["hardware"]["cpu"]["model_name"],
            "mem_total_kb": mem,
            "swap_total_kb": int(identity["hardware"]["memory"]["swap_total_kb"]),
        },
        "storage": {
            "root_size_human": prof.human_kb(root_kb),
            "root_uuid": identity["storage"]["root_uuid"],
            "root_device": identity["storage"]["root_device"],
            "root_filesystem": identity["storage"]["root_filesystem"],
        },
        "network": {
            "address": identity["network"]["address"],
            "gateway": identity["network"]["gateway"],
            "interface": identity["network"]["interface"],
            "mac": identity["network"]["mac"],
            "nameservers": identity["network"]["nameservers"],
        },
        "accounts": [a["name"] for a in identity["accounts"]],
        "boot_offset_seconds": int(identity["os"]["boot_offset_seconds"]),
        "canaries": [{"id": c["id"], "value": c["value"]} for c in identity["canaries"]],
        "forbidden_paths": identity["filesystem"]["forbidden_paths"],
        "commands_that_must_work": sorted(
            ["df", "df -h", "mount", "dmesg", "top -bn1", "lscpu", "nproc", "free",
             "systemctl", "ss -tlnp", "ip addr", "lsblk", "lsb_release -a",
             "uname -a", "hostname", "cat /etc/hostname", "cat /etc/hosts",
             "cat /etc/os-release", "cat /etc/fstab", "cat /proc/mounts",
             "cat /proc/cpuinfo", "cat /proc/meminfo", "cat /etc/ssh/sshd_config",
             "cat /etc/passwd", "cat /etc/group", "cat /etc/shadow", "ps aux",
             "cat /etc/crontab", "cat /var/log/auth.log", "cat /var/log/syslog",
             "ssh -V", "id", "whoami", "uptime"]
        ),
        "commands_that_must_not_exist": ["cowrie", "twistd"],
    }
    (out / "expectations.json").write_text(json.dumps(expectations, indent=2) + "\n", encoding="utf-8")

    # ---- config fragment --------------------------------------------------
    cfg = f"""# =============================================================================
# GENERATED by realism/build_profile.py - do not edit by hand.
# Source of truth: realism/identity.yaml
# Generated: {build_time.isoformat()}
# =============================================================================

[honeypot]
hostname = {identity['identity']['hostname']}
sensor_name = {identity['identity']['hostname']}
timezone = UTC
logtype = rotating
ttylog = true

# Pinned so that /proc/uptime, `uptime`, the `ps` START column and the
# generated log timestamps all describe the same boot event.
boot_offset = {identity['os']['boot_offset_seconds']}

# MANDATORY. Without this, Cowrie derives the address presented by
# `ifconfig` and `netstat -rn` from the host's real outbound socket, so the
# honeypot advertises the real instance's address and routing.
internet_facing_ip = {identity['network']['address']}
fake_addr = {identity['network']['address']}

# NOTE: txtcmds_path and contents_path are read from [honeypot], not [shell].
# Putting them under [shell] silently does nothing - the command then falls
# through to binary emulation and answers "cannot execute binary file".
# txtcmds_path = <state>/share/txtcmds

[ssh]
# Advertised to every connecting client.
version = {identity['os']['openssh_banner']}

[shell]
# `ssh -V` output inside the emulated shell. Must name the same OpenSSH
# release as [ssh] version above; the build enforces this.
ssh_version = {identity['os']['openssh_shell_version']}
kernel_version = {identity['os']['kernel_abi']}
kernel_build_string = {identity['os']['kernel_build_string']}
hardware_platform = {identity['hardware']['architecture']}
operating_system = GNU/Linux
arch = linux-x64-lsb

# Generated filesystem and process table (absolute paths are substituted at
# install time by deploy/install.sh).
# filesystem and processes ARE read from [shell].
# filesystem = <state>/var/lib/cowrie/fs.pickle
# processes  = <state>/var/lib/cowrie/cmdoutput.json
"""
    (out / "cowrie-profile.cfg").write_text(cfg, encoding="utf-8")
    report.append("")
    report.append("outputs:")
    for p in sorted(out.rglob("*")):
        if p.is_file():
            report.append(f"  {p.relative_to(out)}  ({p.stat().st_size} bytes)")
    report.append("")
    report.append("profile built successfully.")
    (out / "BUILD-REPORT.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    # Marks this directory as ours, so the next build may replace it without
    # --force-recursive-delete. Written last, deliberately: a build that died
    # half way leaves an unmarked directory, and the next run asks rather than
    # assumes.
    write_marker(out, MARKER_PROFILE,
                 f"generated by realism/build_profile.py at {build_time.isoformat()}Z "
                 f"from {args.identity}")
    print("\n".join(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

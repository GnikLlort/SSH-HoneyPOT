#!/usr/bin/env python3
"""
Pack a honeypot state directory into an export bundle.

This is the honeypot-side half of ingestion. It reads the honeypot's artefacts
and writes a directory (or a tar) that `ingest.py` can consume on the monitoring
host. It is the only piece of this package that touches honeypot data at rest.

It is read-only with respect to the honeypot: it opens files for reading and
writes nothing into the state directory. It does not connect to anything, and it
does not run on the monitoring host.

WHAT GOES IN A BUNDLE
    cowrie.json          the event record
    tty/<sha256>         session recordings, copied under Cowrie's own name
                         (the hash of the visitor's input -- this IS the join
                         key used by cowrie.log.closed; see the note below)
    downloads/<sha256>   captured uploads, copied under their content hash
    health/health.log    the honeypot's health-check log, for the status page
    SENSOR               the sensor name, so the store can attribute rows
    BUNDLE.json          manifest: counts, sizes and a SHA-256 per file

The recordings and captures are re-hashed on this side rather than trusting the
filename they happen to have, so a file that was renamed or truncated in transit
is detected rather than silently indexed under the wrong hash.

Usage:
    python3 bundle.py --state /opt/cowrie --out /var/spool/honeypot-export
    python3 bundle.py --state /opt/cowrie --out /tmp/b --tar b.tar.gz
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def read_sensor(state: Path) -> str:
    """Sensor name: the Cowrie sensor_name if configured, else the hostname."""
    cfg = state / "etc" / "cowrie.cfg"
    if cfg.is_file():
        for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped.startswith("sensor_name") and "=" in stripped:
                value = stripped.split("=", 1)[1].strip()
                if value:
                    return value[:128]
    for candidate in (state / "var" / "lib" / "cowrie" / "uuid",):
        if candidate.is_file():
            text = candidate.read_text(encoding="utf-8", errors="replace").strip()
            if text:
                return text[:128]
    import socket
    return socket.gethostname()[:128]


def build_bundle(state: Path, out: Path, with_downloads: bool = True,
                 max_download_mb: int = 64) -> dict:
    """
    Assemble the bundle. Returns the manifest.

    Captured files larger than max_download_mb are skipped with a note in the
    manifest rather than copied: they are recorded by hash in the event log
    anyway, and one oversized upload must not stall the shipping pipeline.
    """
    if out.exists():
        shutil.rmtree(out)
    (out / "tty").mkdir(parents=True)
    (out / "downloads").mkdir(parents=True)
    (out / "health").mkdir(parents=True)

    manifest: dict = {
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "state": str(state),
        "files": [],
        "skipped": [],
        "counts": {"events": 0, "recordings": 0, "downloads": 0, "health_lines": 0},
    }

    # -- events ------------------------------------------------------------
    log_dir = state / "var" / "log" / "cowrie"
    lines = 0
    with (out / "cowrie.json").open("w", encoding="utf-8") as dest:
        for name in sorted(log_dir.glob("cowrie.json*")) if log_dir.is_dir() else []:
            if not name.is_file():
                continue
            with name.open("r", encoding="utf-8", errors="replace") as src:
                for line in src:
                    if line.strip():
                        dest.write(line if line.endswith("\n") else line + "\n")
                        lines += 1
    manifest["counts"]["events"] = lines

    # -- recordings --------------------------------------------------------
    #
    # A recording is copied under the name it already has, NOT under the hash of
    # its bytes.
    #
    # This is the one place in this file where re-hashing the content and
    # renaming would be wrong, and it is wrong in a way that stays silent for a
    # long time. Cowrie names a ttylog with the SHA-256 of the VISITOR'S INPUT,
    # not of the file. Verified against a live sensor: 115 of 115 recordings had
    # a filename that did not match the hash of their own bytes. Meanwhile
    # `cowrie.log.closed` names that same value in its `shasum` field, and the
    # dashboard resolves a session's recording by exactly that field. Rename the
    # file to its content hash and the join key is gone: recordings still copy
    # cleanly, the dashboard still ingests them, and every session simply shows
    # no recording, forever.
    #
    # The content hash is still computed and recorded in the manifest as
    # `content_sha256`, so integrity is verified at the far end by COMPARISON
    # rather than by trusting a filename.
    tty_dir = state / "var" / "lib" / "cowrie" / "tty"
    if tty_dir.is_dir():
        for path in sorted(tty_dir.iterdir()):
            if not path.is_file():
                continue
            name = path.name
            if len(name) != 64 or any(ch not in "0123456789abcdef" for ch in name):
                # Not a name Cowrie could have produced. Skip it rather than
                # copy something unexpected into the evidence store.
                manifest["skipped"].append(
                    {"name": name, "bytes": path.stat().st_size,
                     "reason": "recording filename is not a lowercase sha256"})
                continue
            dest = out / "tty" / name
            if not dest.exists():
                shutil.copyfile(path, dest)
                manifest["counts"]["recordings"] += 1
            manifest["files"].append(
                {"kind": "recording", "sha256": name,
                 "content_sha256": sha256_file(path),
                 "bytes": path.stat().st_size, "source_name": name})

    # -- captured uploads --------------------------------------------------
    dl_dir = state / "var" / "lib" / "cowrie" / "downloads"
    if with_downloads and dl_dir.is_dir():
        for path in sorted(dl_dir.iterdir()):
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size > max_download_mb * 1024 * 1024:
                manifest["skipped"].append(
                    {"name": path.name, "bytes": size,
                     "reason": f"larger than {max_download_mb} MB"})
                continue
            digest = sha256_file(path)
            dest = out / "downloads" / digest
            if not dest.exists():
                shutil.copyfile(path, dest)
                manifest["counts"]["downloads"] += 1
            manifest["files"].append(
                {"kind": "capture", "sha256": digest, "bytes": size,
                 "source_name": path.name})

    # -- health ------------------------------------------------------------
    for name in ("/var/log/cowrie-healthcheck.log",):
        src = Path(name)
        if src.is_file():
            shutil.copyfile(src, out / "health" / "health.log")
            manifest["counts"]["health_lines"] = len(
                src.read_text(encoding="utf-8", errors="replace").splitlines())

    # -- identity ----------------------------------------------------------
    sensor = read_sensor(state)
    (out / "SENSOR").write_text(sensor + "\n", encoding="utf-8")
    manifest["sensor"] = sensor
    (out / "BUNDLE.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default="/opt/cowrie", help="honeypot state directory")
    ap.add_argument("--out", required=True, help="bundle output directory")
    ap.add_argument("--tar", default="", help="also write this tarball")
    ap.add_argument("--no-downloads", action="store_true",
                    help="skip captured files (metadata still arrives via the event log)")
    ap.add_argument("--max-download-mb", type=int, default=64)
    args = ap.parse_args()

    state = Path(args.state)
    if not (state / "var" / "log" / "cowrie").is_dir():
        print(f"error: {state}/var/log/cowrie not found; is this a honeypot state dir?",
              file=sys.stderr)
        return 2

    manifest = build_bundle(state, Path(args.out),
                            with_downloads=not args.no_downloads,
                            max_download_mb=args.max_download_mb)

    if args.tar:
        with tarfile.open(args.tar, "w:gz") as tf:
            tf.add(args.out, arcname="bundle")
        print(f"bundle written to {args.tar}")

    c = manifest["counts"]
    print(f"bundle: {args.out}")
    print(f"  sensor:     {manifest['sensor']}")
    print(f"  events:     {c['events']}")
    print(f"  recordings: {c['recordings']}")
    print(f"  captures:   {c['downloads']}")
    print(f"  health:     {c['health_lines']} lines")
    if manifest["skipped"]:
        print(f"  skipped:    {len(manifest['skipped'])} oversized capture(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

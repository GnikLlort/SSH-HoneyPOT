#!/usr/bin/env python3
"""
Tests for the deployment scripts themselves.

Everything here is about the gap between what a script claims and what it does
when it is run a second time:

  TestPinnedCheckout      -- deploy/lib/checkout.sh. `git clone` into a
                             directory that already exists fails with exit 128,
                             which is what the installer did at stage 4. The
                             installer advertises itself as safe to re-run and
                             the documented update path is "re-run it", so an
                             update aborted in the middle of the build and
                             looked like a crash. The helper is tested against
                             throwaway repositories, including the case that
                             broke it: the same call, twice.
  TestUpdateScript        -- deploy/update.sh must show a plan and change
                             nothing without --apply, refuse an uninstalled
                             host, and never touch evidence.
  TestDashboardInstaller  -- deploy/install-dashboard.sh must show a plan and
                             change nothing without --apply, and must refuse a
                             honeypot host.
  TestShippedUnits        -- systemd units: the file: documents they point at
                             have to exist, the dashboard unit must be
                             AF_UNIX-only by default, and the honeypot units
                             must not quietly enable anything.
  TestDocumentationLinks  -- every docs/*.md is in the index, and every
                             relative link in the documentation resolves. A
                             doc that points at a page nobody wrote is worse
                             than no doc.

Run from the repository root:

    python3 tests/test_deployment_scripts.py
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(args: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=180, **kw)


def git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return run(["git", "-C", str(cwd), *args])


class TestPinnedCheckout(unittest.TestCase):
    """deploy/lib/checkout.sh: clone, refresh, and verify a pinned commit."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="checkout-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "--quiet", "-b", "main")
        git(self.repo, "config", "user.email", "test@example.invalid")
        git(self.repo, "config", "user.name", "test")
        self.commits = [self.commit("first")]

    def commit(self, message: str, filename: str = "file.txt") -> str:
        (self.repo / filename).write_text(message + "\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "--quiet", "-m", message)
        return git(self.repo, "rev-parse", "HEAD").stdout.strip()

    def ensure(self, dest: Path, commit: str, *extra: str) -> subprocess.CompletedProcess:
        # shellcheck-style invocation of the sourced function, the same way
        # install.sh uses it.
        return run(["bash", "-c",
                    'set -euo pipefail; source "$1"; ensure_pinned_checkout "$2" "$3" "$4" %s'
                    % " ".join(extra),
                    "bash", str(ROOT / "deploy" / "lib" / "checkout.sh"),
                    str(dest), str(self.repo), commit])

    def test_fresh_clone_checks_out_the_pin(self) -> None:
        dest = self.tmp / "build" / "cowrie"
        proc = self.ensure(dest, self.commits[0])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(git(dest, "rev-parse", "HEAD").stdout.strip(), self.commits[0])
        self.assertEqual((dest / "file.txt").read_text(), "first\n")

    def test_the_same_call_twice_is_the_update_path(self) -> None:
        """
        This is the bug: the second call is what an update does, and the old
        implementation (`git clone`) exited 128 without touching anything.
        """
        dest = self.tmp / "build" / "cowrie"
        first = self.ensure(dest, self.commits[0])
        self.assertEqual(first.returncode, 0, first.stderr)

        second = self.ensure(dest, self.commits[0])
        self.assertEqual(second.returncode, 0,
                         "re-running the checkout failed, so the installer's "
                         "second run aborts at stage 4:\n" + second.stderr)
        self.assertEqual(git(dest, "rev-parse", "HEAD").stdout.strip(), self.commits[0])

    def test_a_new_upstream_commit_is_fetched(self) -> None:
        """A pin that moved after the first install has to be reachable."""
        dest = self.tmp / "build" / "cowrie"
        self.assertEqual(self.ensure(dest, self.commits[0]).returncode, 0)

        second_commit = self.commit("second")
        proc = self.ensure(dest, second_commit)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(git(dest, "rev-parse", "HEAD").stdout.strip(), second_commit)
        self.assertEqual((dest / "file.txt").read_text(), "second\n")

    def test_local_edits_in_the_build_clone_do_not_survive(self) -> None:
        dest = self.tmp / "build" / "cowrie"
        self.ensure(dest, self.commits[0])
        (dest / "file.txt").write_text("hand-edited\n", encoding="utf-8")
        proc = self.ensure(dest, self.commits[0])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((dest / "file.txt").read_text(), "first\n",
                         "a hand-edited build tree was built anyway")
        self.assertIn("discarding local changes", proc.stderr)

    def test_an_unknown_commit_fails_loudly(self) -> None:
        dest = self.tmp / "build" / "cowrie"
        proc = self.ensure(dest, "0" * 40)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not present", proc.stderr)

    def test_a_directory_that_is_not_a_checkout_is_refused(self) -> None:
        dest = self.tmp / "build" / "cowrie"
        dest.mkdir(parents=True)
        (dest / "important.txt").write_text("not a clone\n", encoding="utf-8")
        proc = self.ensure(dest, self.commits[0])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not a git checkout", proc.stderr)
        self.assertTrue((dest / "important.txt").is_file(),
                        "the helper deleted a directory it did not recognise")
        forced = self.ensure(dest, self.commits[0], "--force")
        self.assertEqual(forced.returncode, 0, forced.stderr)


class TestUpdateScript(unittest.TestCase):
    """deploy/update.sh: plan by default, refuse what it should."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="update-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.source = self.tmp / "src"
        shutil.copytree(ROOT, self.source,
                        ignore=shutil.ignore_patterns(".git", ".venv", "build",
                                                      "lab", "__pycache__", "*.pyc"))
        git(self.source, "init", "--quiet", "-b", "main")
        git(self.source, "config", "user.email", "test@example.invalid")
        git(self.source, "config", "user.name", "test")
        git(self.source, "add", "-A")
        git(self.source, "commit", "--quiet", "-m", "first")
        self.state = self.tmp / "state"
        (self.state / "etc").mkdir(parents=True)

    def working_tree(self) -> list[str]:
        """
        Files git can see, excluding .git itself.

        `git fetch` updates .git/FETCH_HEAD; that is a legitimate side effect of
        asking what is available, and it is not the source tree.
        """
        listing = git(self.source, "status", "--porcelain", "-uall").stdout
        return sorted(line for line in listing.splitlines() if line.strip())

    def test_dry_run_prints_a_rollback_path_and_changes_nothing(self) -> None:
        before = self.working_tree()
        proc = run(["bash", str(self.source / "deploy" / "update.sh"),
                    "--source", str(self.source), "--ref", "main"],
                   env=dict(os.environ, STATE_DIR=str(self.state)), cwd=str(self.tmp))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("dry run", proc.stdout)
        self.assertIn("install.sh --apply", proc.stdout)
        self.assertIn("--rollback", proc.stdout)
        self.assertEqual(self.working_tree(), before,
                         "the dry run modified the source tree")

    def test_it_refuses_a_dirty_tree_by_default(self) -> None:
        (self.source / "README.md").write_text("edited by hand\n", encoding="utf-8")
        proc = run(["bash", str(self.source / "deploy" / "update.sh"),
                    "--source", str(self.source), "--ref", "main"],
                   env=dict(os.environ, STATE_DIR=str(self.state)), cwd=str(self.tmp))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("uncommitted changes", proc.stderr)

    def test_it_refuses_a_host_that_was_never_installed(self) -> None:
        empty = self.tmp / "not-installed"
        proc = run(["bash", str(self.source / "deploy" / "update.sh"),
                    "--source", str(self.source), "--ref", "main",
                    "--apply", "--no-restart"],
                   env=dict(os.environ, STATE_DIR=str(empty)), cwd=str(self.tmp))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not an installed honeypot", proc.stderr)

    def test_it_refuses_an_unknown_ref(self) -> None:
        proc = run(["bash", str(self.source / "deploy" / "update.sh"),
                    "--source", str(self.source), "--ref", "no-such-branch"],
                   env=dict(os.environ, STATE_DIR=str(self.state)), cwd=str(self.tmp))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not a branch, tag or commit", proc.stderr)


class TestDashboardInstaller(unittest.TestCase):
    """deploy/install-dashboard.sh: plan by default, refuse a honeypot host."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="dash-install-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.install_dir = self.tmp / "opt"
        self.store = self.tmp / "store"
        self.spool = self.tmp / "spool"
        self.path = os.environ.get("PATH", "")
        if shutil.which("rsync") is None:
            # The installer (rightly) refuses to run without rsync, and the
            # sandbox this suite was written in has none. A stand-in lets the
            # script's own logic be tested -- plan, refusals, option handling --
            # without pretending rsync itself was exercised.
            shim = self.tmp / "shim"
            shim.mkdir()
            (shim / "rsync").write_text("#!/usr/bin/env bash\nexit 0\n",
                                        encoding="utf-8")
            (shim / "rsync").chmod(0o755)
            self.path = f"{shim}:{self.path}"

    def run_installer(self, *args: str, env: dict | None = None):
        return run(["bash", str(ROOT / "deploy" / "install-dashboard.sh"), *args],
                   env=dict(os.environ, PATH=self.path, **(env or {})),
                   cwd=str(self.tmp))

    def test_dry_run_changes_nothing(self) -> None:
        proc = self.run_installer("--install-dir", str(self.install_dir),
                                  "--store", str(self.store), "--spool", str(self.spool))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("DRY RUN", proc.stdout)
        self.assertIn("Monitoring dashboard - installation", proc.stdout)
        self.assertIn(str(self.install_dir), proc.stdout)
        self.assertIn("dry run: not executed", proc.stdout,
                      "the plan does not mark its actions as unexecuted")
        self.assertFalse(self.install_dir.exists(), "the dry run created directories")
        self.assertFalse(self.store.exists(), "the dry run created the store")

    def test_option_values_reach_the_plan(self) -> None:
        proc = self.run_installer("--install-dir", str(self.install_dir),
                                  "--store", str(self.store), "--spool", str(self.spool),
                                  "--user", "someone", "--listen", "127.0.0.1:9443")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for value in (str(self.install_dir), str(self.store), str(self.spool),
                      "someone", "127.0.0.1:9443"):
            self.assertIn(value, proc.stdout)

    def test_it_refuses_to_bind_a_non_loopback_address(self) -> None:
        proc = self.run_installer("--listen", "0.0.0.0:8443",
                                  "--install-dir", str(self.install_dir))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refusing to bind", proc.stderr)

    def test_it_refuses_a_honeypot_host(self) -> None:
        """
        The separation is the design: the reviewer does not live on the host it
        reviews. The check is a path probe, so the test can create the path.
        """
        if os.geteuid() == 0:
            self.skipTest("running as root: the probe path is the real state dir")
        fake = Path("/opt/cowrie/var/lib/cowrie")
        try:
            fake.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self.skipTest("no permission to create /opt/cowrie for the probe")
        self.addCleanup(lambda: shutil.rmtree("/opt/cowrie", ignore_errors=True))
        proc = self.run_installer("--install-dir", str(self.install_dir))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("looks like the honeypot host", proc.stderr)
        allowed = self.run_installer("--allow-on-honeypot",
                                     "--install-dir", str(self.install_dir))
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertIn("--allow-on-honeypot", allowed.stdout + allowed.stderr)


class TestShippedUnits(unittest.TestCase):
    """The units and the documents they point at."""

    UNIT_DIR = ROOT / "deploy" / "systemd"

    def units(self) -> list[Path]:
        return sorted(self.UNIT_DIR.glob("*.service")) + \
            sorted(self.UNIT_DIR.glob("*.timer"))

    # Written by install.sh into the state directory; there is no such file in
    # the repository, and there should not be.
    GENERATED = {"DEPLOYMENT.txt"}

    def test_documentation_targets_exist(self) -> None:
        """
        Installed units name absolute paths under /opt/cowrie. Check the
        longest tail of each that does exist in the repository: that is how
        docs/16 and docs/17 are kept honest, without the test hard-coding the
        install prefix.
        """
        missing = []
        for unit in self.units():
            for line in unit.read_text(encoding="utf-8").splitlines():
                if not line.startswith("Documentation=file:"):
                    continue
                target = Path(line.split("file:", 1)[1].strip())
                parts = target.parts
                if any(ROOT.joinpath(*parts[i:]).exists()
                       for i in range(len(parts))):
                    continue
                if target.name in self.GENERATED:
                    continue
                missing.append(f"{unit.name}: {target}")
        self.assertEqual(missing, [],
                         "a unit documents a file that does not exist:\n  "
                         + "\n  ".join(missing))

    def test_the_dashboard_unit_cannot_open_a_network_socket(self) -> None:
        text = (self.UNIT_DIR / "honeypot-dashboard.service").read_text(encoding="utf-8")
        active = [ln for ln in text.splitlines()
                  if ln.startswith("RestrictAddressFamilies=")]
        self.assertEqual(active, ["RestrictAddressFamilies=AF_UNIX"],
                         "the shipped dashboard unit is no longer AF_UNIX-only")

    def test_the_dashboard_unit_does_not_run_as_root(self) -> None:
        text = (self.UNIT_DIR / "honeypot-dashboard.service").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^User=(?!root)\S+")

    def test_the_honeypot_unit_never_gets_the_exposure_flag(self) -> None:
        """
        `--i-know-this-exposes-evidence` / `--i-know-this-exposes-monitoring`
        exist for a person to type in front of a terminal. In a unit file they
        are a standing decision nobody revisits.
        """
        for unit in self.units():
            for line in unit.read_text(encoding="utf-8").splitlines():
                if line.lstrip().startswith("#"):
                    continue  # a comment telling the reader not to use the flag
                self.assertNotIn("i-know-this-exposes", line,
                                 f"{unit.name} ships an exposure acknowledgement flag")

    def test_the_bundle_timer_is_not_enabled_by_the_installer(self) -> None:
        """
        The bundle ship timer moves captured credentials to a second host. It
        is opt-in: install.sh installs the unit and says nothing about
        enabling it, and the plan must not contain an `enable` for it.
        """
        text = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
        for line in text.splitlines():
            if "enable --now cowrie-bundle-ship" in line:
                self.assertIn("note", line,
                              "install.sh enables the bundle shipment, rather than "
                              "telling the operator how to:" + line)

    def test_install_sh_installs_the_units_it_ships(self) -> None:
        text = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
        for name in ("cowrie-healthcheck.service", "cowrie-healthcheck.timer",
                     "cowrie-logship.service", "cowrie-logship.timer",
                     "cowrie.service", "cowrie-playback.service",
                     "cowrie-bundle-ship.service", "cowrie-bundle-ship.timer"):
            self.assertIn(name, text,
                          f"{name} is shipped but never installed by install.sh")


class TestDocumentationLinks(unittest.TestCase):
    """A doc that points at a page nobody wrote is worse than no doc."""

    DOCS = ROOT / "docs"

    def test_every_doc_is_in_the_index(self) -> None:
        index = (self.DOCS / "README.md").read_text(encoding="utf-8")
        missing = [p.name for p in sorted(self.DOCS.glob("*.md"))
                   if p.name != "README.md" and p.name not in index]
        self.assertEqual(missing, [], "docs not listed in docs/README.md: "
                         + ", ".join(missing))

    def test_every_relative_link_resolves(self) -> None:
        missing = []
        sources = sorted(self.DOCS.glob("*.md")) + [ROOT / "README.md", ROOT / "AUDIT.md"]
        for doc in sources:
            text = doc.read_text(encoding="utf-8", errors="replace")
            for match in re.finditer(r"\[[^\]]*\]\(([^)#\s]+)(#[^)]*)?\)", text):
                target = match.group(1)
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                if not (doc.parent / target).exists():
                    missing.append(f"{doc.relative_to(ROOT)} -> {target}")
        self.assertEqual(missing, [], "these links point at nothing:\n  "
                         + "\n  ".join(missing))


if __name__ == "__main__":
    unittest.main(verbosity=2)

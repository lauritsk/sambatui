"""Fixture safety tests; no Samba provisioning, credentials or network required."""

import ast
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name("server.py")
SPECIFICATION = importlib.util.spec_from_file_location("fixture_server", SOURCE)
SERVER = importlib.util.module_from_spec(SPECIFICATION)
sys.modules[SPECIFICATION.name] = SERVER
SPECIFICATION.loader.exec_module(SERVER)


class FixtureTests(unittest.TestCase):
    def test_provisioning_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker, state = root / "container", root / "state"
            marker.touch()
            with self.assertRaises(RuntimeError):
                SERVER.validate_fixture({}, marker, state)
            environment = {"SAMBATUI_SERVER_FIXTURE": "DISPOSABLE"}
            with self.assertRaises(RuntimeError):
                SERVER.validate_fixture(environment, root / "missing", state)
            SERVER.validate_fixture(environment, marker, state)
            state.mkdir()
            with self.assertRaises(RuntimeError):
                SERVER.validate_fixture(environment, marker, state)

    def test_configuration_requires_exactly_one_global_section(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "smb.conf"
            for contents in ("[other]", "[global]\n[global]", "x" * (SERVER.CONFIG_BYTES_MAX + 1)):
                path.write_text(contents, encoding="utf-8")
                with self.assertRaises(RuntimeError):
                    SERVER.configure_samba(path)
                self.assertEqual(path.read_text(encoding="utf-8"), contents)
            path.write_text("[global]\n[sysvol]\n", encoding="utf-8")
            SERVER.configure_samba(path)
            result = path.read_text(encoding="utf-8")
            self.assertIn("interfaces = 127.0.0.1", result)
            self.assertIn("bind interfaces only = yes", result)
            self.assertEqual(result.count("[global]"), 1)

    def test_commands_propagate_failures_and_time_out(self):
        with self.assertRaises(subprocess.CalledProcessError):
            SERVER.run_command([sys.executable, "-I", "-c", "raise SystemExit(7)"])
        with self.assertRaises(subprocess.TimeoutExpired):
            SERVER.run_command(
                [sys.executable, "-I", "-c", "import time; time.sleep(60)"],
                timeout_seconds=0.05,
            )
        SERVER.run_command([sys.executable, "-I", "-c", "pass"])

    def test_readiness_and_lifetime_are_finite(self):
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(SERVER, "run_command", side_effect=subprocess.TimeoutExpired([], 2)):
            with mock.patch.object(SERVER.time, "sleep"):
                with self.assertRaises(RuntimeError):
                    SERVER.wait_for_kerberos(process, SERVER.Shutdown())
        with self.assertRaises(RuntimeError):
            SERVER.wait_for_shutdown(process, SERVER.Shutdown(), 0)
        SERVER.wait_for_shutdown(process, SERVER.Shutdown(requested=True), 0)

    def test_fixture_source_contracts(self):
        source = SOURCE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self.assertLessEqual(node.end_lineno - node.lineno + 1, 70, node.name)
                for child in ast.walk(node):
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                        self.assertNotEqual(child.func.id, node.name, "recursive fixture function")
            self.assertNotIsInstance(node, ast.While, "fixture loops require explicit ranges")
        for line in source.splitlines():
            self.assertLessEqual(len(line), 100)

    def test_commands_require_positive_bounded_budgets(self):
        for arguments, timeout in (([], 1), (["unused"], 0), (["unused"], 61)):
            with self.assertRaises(AssertionError):
                SERVER.run_command(arguments, timeout_seconds=timeout)


if __name__ == "__main__":
    unittest.main()

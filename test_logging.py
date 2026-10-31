"""Check logging in clean processes without altering the test runner's logs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


MODULE = Path(__file__).with_name("logging_config.py")


class LoggingTests(unittest.TestCase):
    def run_logging(self, script, *, environment=None, module_directory=None):
        env = os.environ.copy()
        env.pop("LOG_LEVEL", None)
        env.pop("DIAGDISCOVER_LOG_DIR", None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = str(module_directory or MODULE.parent)
        env.update(environment or {})
        completed = subprocess.run(
            [sys.executable, "-c", script], env=env,
            cwd=module_directory or MODULE.parent,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed

    def test_messages_and_exceptions_are_one_json_record_each(self):
        completed = self.run_logging('''
import logging
from logging_config import configure_logging
configure_logging()
logger = logging.getLogger("diagdiscover.test")
logger.info('quoted "value"\\nforged line\\t' + chr(0),
            extra={"access_token": "must-not-be-serialized"})
try:
    raise ValueError('bad "input"\\nsecond line')
except ValueError:
    logger.exception("Operation failed")
''')
        lines = completed.stderr.splitlines()
        self.assertEqual(len(lines), 2)
        first, second = map(json.loads, lines)
        self.assertEqual(first["msg"], 'quoted "value"\nforged line\t\x00')
        self.assertEqual(first["module"], "diagdiscover.test")
        self.assertTrue(first["time"].endswith("Z"))
        self.assertNotIn("must-not-be-serialized", completed.stderr)
        self.assertEqual(second["msg"], "Operation failed")
        self.assertIn('ValueError: bad "input"\nsecond line', second["exception"])
        self.assertEqual(completed.stdout, "")

    def test_default_never_writes_even_beside_a_read_only_module(self):
        with tempfile.TemporaryDirectory() as directory:
            module = Path(directory) / MODULE.name
            shutil.copyfile(MODULE, module)
            module.chmod(0o444)
            try:
                # chmod cannot make a Windows directory or root-owned Docker
                # directory unwritable reliably. Enforce the no-write promise
                # with an audit hook as well, allowing imports to read files.
                result = self.run_logging('''
import os
import sys
def deny_writes(event, args):
    if event == "os.mkdir":
        raise PermissionError("read-only application directory")
    if event == "open":
        mode, flags = args[1], args[2]
        if ((isinstance(mode, str) and any(c in mode for c in "wax+"))
                or (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))):
            raise PermissionError("read-only application directory")
sys.addaudithook(deny_writes)
from logging_config import configure_logging
configure_logging().info("Ready on read-only filesystem")
''', module_directory=directory)
                self.assertEqual(json.loads(result.stderr)["msg"],
                                 "Ready on read-only filesystem")
                self.assertEqual(list(Path(directory).iterdir()), [module])
            finally:
                module.chmod(0o644)

    def test_configuration_is_idempotent_and_preserves_root_logger(self):
        result = self.run_logging('''
import io
import logging
from logging_config import configure_logging
root = logging.getLogger()
root.setLevel(logging.ERROR)
existing = logging.StreamHandler(io.StringIO())
root.addHandler(existing)
before = list(root.handlers)
first = configure_logging()
second = configure_logging()
assert first is second
assert len(first.handlers) == 1
assert root.handlers == before
assert root.level == logging.ERROR
assert not first.propagate
logging.getLogger("diagdiscover.child").info("Exactly once")
''')
        self.assertEqual(len(result.stderr.splitlines()), 1)
        self.assertEqual(json.loads(result.stderr)["msg"], "Exactly once")

    def test_invalid_log_level_falls_back_without_echoing_input(self):
        result = self.run_logging('''
import logging
from logging_config import configure_logging
logger = configure_logging()
assert logger.level == logging.INFO
logger.debug("hidden")
logger.info("visible")
''', environment={"LOG_LEVEL": '__dict__\nprivate-input'})
        records = [json.loads(line) for line in result.stderr.splitlines()]
        self.assertEqual([record["msg"] for record in records],
                         ["Invalid LOG_LEVEL; using INFO", "visible"])
        self.assertNotIn("private-input", result.stderr)

    def test_valid_level_filters_records(self):
        result = self.run_logging('''
from logging_config import configure_logging
logger = configure_logging()
logger.info("hidden")
logger.error("visible")
''', environment={"LOG_LEVEL": " error "})
        self.assertEqual(json.loads(result.stderr)["msg"], "visible")

    def test_windowed_executable_without_console_does_not_crash(self):
        result = self.run_logging('''
import logging
import sys
sys.stderr = None
sys.stdout = None
from logging_config import configure_logging
logger = configure_logging()
assert isinstance(logger.handlers[0], logging.NullHandler)
logger.error("There is no console")
''', environment={"DIAGDISCOVER_LOG_DIR": "relative-and-invalid"})
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_optional_file_is_rotating_and_records_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            log_directory = Path(directory) / "logs"
            result = self.run_logging('''
from logging.handlers import RotatingFileHandler
from logging_config import configure_logging
logger = configure_logging()
handler = next(h for h in logger.handlers if isinstance(h, RotatingFileHandler))
assert handler.maxBytes == 5 * 1024 * 1024
assert handler.backupCount == 3
logger.info('one "record"\\nwith newline')
handler.doRollover()
logger.info("after rotation")
''', environment={"DIAGDISCOVER_LOG_DIR": str(log_directory)})
            self.assertEqual(json.loads((log_directory / "demo.log.1").read_text())["msg"],
                             'one "record"\nwith newline')
            self.assertEqual(json.loads((log_directory / "demo.log").read_text())["msg"],
                             "after rotation")
            self.assertEqual(len(result.stderr.splitlines()), 2)

    def test_unavailable_optional_directory_does_not_prevent_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            not_a_directory = Path(directory) / "file"
            not_a_directory.write_text("existing data", encoding="utf-8")
            result = self.run_logging('''
from logging_config import configure_logging
configure_logging().info("Application started")
''', environment={"DIAGDISCOVER_LOG_DIR": str(not_a_directory)})
            records = [json.loads(line) for line in result.stderr.splitlines()]
            self.assertEqual(records[0]["level"], "WARNING")
            self.assertEqual(records[1]["msg"], "Application started")
            self.assertNotIn(str(not_a_directory), result.stderr)
            self.assertEqual(not_a_directory.read_text(), "existing data")


if __name__ == "__main__":
    unittest.main()

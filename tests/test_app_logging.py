import tempfile
import unittest
from pathlib import Path

from utils.app_logging import log_exception_to_file


class AppLoggingTests(unittest.TestCase):
    def test_logs_exception_message_and_full_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "output" / "nmap_automator.log"
            try:
                raise RuntimeError("mock provider failure")
            except RuntimeError:
                log_exception_to_file(log_path, "Narrative generation failed")

            content = log_path.read_text(encoding="utf-8")
            self.assertIn("Narrative generation failed", content)
            self.assertIn("Traceback (most recent call last)", content)
            self.assertIn("RuntimeError: mock provider failure", content)


if __name__ == "__main__":
    unittest.main()

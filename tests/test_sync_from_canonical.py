import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MIRROR = Path(__file__).parents[1]
SCRIPT = MIRROR / "scripts" / "sync_from_canonical.py"


class MirrorSyncTests(unittest.TestCase):
    def test_mirror_state_is_valid(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--mirror", str(MIRROR), "--verify-state"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_tool_rejects_manifest_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, mirror = root / "source", root / "mirror"
            source.mkdir()
            mirror.mkdir()
            (source / "SKILL.md").write_text("safe\n")
            (mirror / "mirror-manifest.json").write_text(
                '{"schema_version":1,"canonical":{"skill":"fixture"},'
                '"files":[{"source":"SKILL.md","destination":"../outside"}]}'
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--mirror",
                    str(mirror),
                    "--source",
                    str(source),
                    "--check",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("normalized relative path", result.stderr)


if __name__ == "__main__":
    unittest.main()

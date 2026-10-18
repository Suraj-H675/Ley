import os
import unittest
from pathlib import Path
from unittest.mock import patch

from run_gate7_benchmark import ROOT, release_binary_path


class ReleaseBinaryPathTests(unittest.TestCase):
    def test_uses_workspace_target_directory_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(release_binary_path(), ROOT / "target/release/ley")

    def test_resolves_relative_cargo_target_directory_from_workspace(self) -> None:
        with patch.dict(
            os.environ, {"CARGO_TARGET_DIR": ".audit/cargo-target"}, clear=True
        ):
            self.assertEqual(
                release_binary_path(), ROOT / ".audit/cargo-target/release/ley"
            )

    def test_preserves_absolute_cargo_target_directory(self) -> None:
        configured_target_dir = Path("/tmp/ley-cargo-target")
        with patch.dict(
            os.environ,
            {"CARGO_TARGET_DIR": str(configured_target_dir)},
            clear=True,
        ):
            self.assertEqual(
                release_binary_path(), configured_target_dir / "release/ley"
            )


if __name__ == "__main__":
    unittest.main()

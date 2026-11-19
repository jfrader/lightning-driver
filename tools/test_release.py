import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import release


class ReleaseTests(unittest.TestCase):
    packages = [("lightning-client", "1.0.0"), ("lightning-driver-api", "1.0.0")]

    def test_manifest_versions_must_both_match_before_any_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for manifest, (name, version) in zip(release.MANIFESTS, self.packages):
                path = root / manifest
                path.parent.mkdir()
                path.write_text(f'[package]\nname = "{name}"\nversion = "{version}"\n')
            self.assertEqual(release.release_packages(root, "v1.0.0"), self.packages)
            for tag in ("v1.0.1", "v1.1.0", "master"):
                with self.subTest(tag=tag), self.assertRaises(ValueError):
                    release.release_packages(root, tag)
            second = root / release.MANIFESTS[1]
            second.write_text(second.read_text().replace("1.0.0", "1.0.1"))
            with self.assertRaisesRegex(ValueError, "must equal v1.0.1"):
                release.release_packages(root, "v1.0.0")
            first = root / release.MANIFESTS[0]
            first.write_text(first.read_text().replace("1.0.0", "1.0.1"))
            self.assertEqual(
                release.release_packages(root, "v1.0.1"),
                [(name, "1.0.1") for name, _ in self.packages],
            )

    @patch("release.subprocess.run")
    @patch("release.subprocess.check_output", side_effect=["404", "404"])
    def test_missing_versions_publish_in_dependency_order(self, curl, cargo):
        release.publish_missing(self.packages)
        self.assertEqual(cargo.call_args_list, [
            call(["cargo", "publish", "--locked", "-p", crate], check=True)
            for crate, _ in self.packages
        ])
        for actual, (crate, version) in zip(curl.call_args_list, self.packages):
            self.assertEqual(actual.args[0], [
                "curl", "-sS", "-H", f"User-Agent: {release.UA}", "-o", "/dev/null",
                "-w", "%{http_code}", f"{release.REGISTRY_API}/{crate}/{version}",
            ])

    @patch("release.subprocess.run")
    @patch("release.subprocess.check_output", side_effect=["200", "200"])
    def test_bootstrap_or_rerun_skips_both(self, curl, cargo):
        release.publish_missing(self.packages)
        self.assertEqual(curl.call_count, 2)
        cargo.assert_not_called()

    @patch("release.subprocess.run")
    @patch("release.subprocess.check_output", side_effect=["200", "404"])
    def test_partial_publish_resumes(self, curl, cargo):
        release.publish_missing(self.packages)
        cargo.assert_called_once_with(
            ["cargo", "publish", "--locked", "-p", "lightning-driver-api"], check=True,
        )

    @patch("release.subprocess.run")
    @patch("release.subprocess.check_output")
    def test_registry_errors_fail_closed(self, curl, cargo):
        for status in ("403", "429", "500", "000", ""):
            curl.return_value = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                release.publish_missing(self.packages)
        curl.side_effect = subprocess.CalledProcessError(7, "curl")
        with self.assertRaises(subprocess.CalledProcessError):
            release.publish_missing(self.packages)
        cargo.assert_not_called()

    @patch("release.subprocess.run", side_effect=subprocess.CalledProcessError(1, "cargo"))
    @patch("release.subprocess.check_output", return_value="404")
    def test_publish_failure_prevents_dependent_publish(self, curl, cargo):
        with self.assertRaises(subprocess.CalledProcessError):
            release.publish_missing(self.packages)
        self.assertEqual(curl.call_count, 1)
        self.assertEqual(cargo.call_count, 1)


if __name__ == "__main__":
    unittest.main()

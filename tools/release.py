#!/usr/bin/env python3
"""Validate a release tag and publish missing crate versions in dependency order."""

import argparse
import os
from pathlib import Path
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parent.parent
MANIFESTS = ("lightning-client/Cargo.toml", "api-server/Cargo.toml")
UA = "jfrader-release-check (github.com/jfrader/lightning-driver)"
REGISTRY_API = "https://crates.io/api/v1/crates"


def release_packages(root, tag):
    packages = []
    for manifest in MANIFESTS:
        with (root / manifest).open("rb") as source:
            package = tomllib.load(source)["package"]
        name, version = package["name"], package["version"]
        if tag != f"v{version}":
            raise ValueError(f"{manifest}: tag {tag!r} must equal v{version}")
        packages.append((name, version))
    return packages


def publish_missing(packages):
    for crate, version in packages:
        status = subprocess.check_output(
            ["curl", "-sS", "-H", f"User-Agent: {UA}", "-o", "/dev/null",
             "-w", "%{http_code}", f"{REGISTRY_API}/{crate}/{version}"],
            text=True,
        ).strip()
        if status == "200":
            print(f"Skipping {crate} {version}: already published", flush=True)
        elif status == "404":
            subprocess.run(["cargo", "publish", "--locked", "-p", crate], check=True)
        else:
            raise ValueError(f"{crate} {version}: unexpected crates.io HTTP {status}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    packages = release_packages(ROOT, os.environ["GITHUB_REF_NAME"])
    if args.publish:
        publish_missing(packages)
    else:
        for crate, version in packages:
            print(f"Validated {crate} {version}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Publish staged Codex npm tarballs from a directory."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


ALREADY_PUBLISHED_RE = re.compile(
    r"previously published|cannot publish over|version already exists",
    re.IGNORECASE,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir",
        dest="root",
        type=Path,
        required=True,
        help="Directory containing staged npm tarballs.",
    )
    parser.add_argument(
        "--version",
        required=True,
        help="Release version that should be published (e.g. 0.111.0 or 0.111.0-alpha.1).",
    )
    parser.add_argument(
        "--npm-tag",
        default="",
        help="Base npm dist-tag for the meta package (default: latest). Use alpha for prereleases.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Pass --dry-run through to npm publish.",
    )
    return parser.parse_args()


def classify_tarball(filename: str, version: str, npm_tag: str) -> str | None:
    suffix = f"-{version}.tgz"
    prefix = f"{npm_tag}-" if npm_tag else ""

    if filename in {
        f"codex-npm-{version}.tgz",
        f"codex-responses-api-proxy-npm-{version}.tgz",
        f"codex-sdk-npm-{version}.tgz",
    }:
        return npm_tag

    for platform_prefix in (
        "codex-npm-linux-",
        "codex-npm-darwin-",
        "codex-npm-win32-",
    ):
        if filename.startswith(platform_prefix) and filename.endswith(suffix):
            platform = filename.removeprefix("codex-npm-").removesuffix(suffix)
            return f"{prefix}{platform}"

    return None


def tarball_publish_rank(filename: str, version: str) -> tuple[int, str]:
    suffix = f"-{version}.tgz"

    for platform_prefix in (
        "codex-npm-linux-",
        "codex-npm-darwin-",
        "codex-npm-win32-",
    ):
        if filename.startswith(platform_prefix) and filename.endswith(suffix):
            return (0, filename)

    if filename == f"codex-npm-{version}.tgz":
        return (2, filename)

    if filename == f"codex-sdk-npm-{version}.tgz":
        return (3, filename)

    return (1, filename)


def run_publish(tarball: Path, *, npm_tag: str, dry_run: bool) -> int:
    cmd = ["npm", "publish", str(tarball), "--access", "public"]
    if npm_tag:
        cmd.extend(["--tag", npm_tag])
    if dry_run:
        cmd.append("--dry-run")

    print("+ " + " ".join(cmd))
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)

    if proc.returncode == 0:
        return 0

    combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
    if ALREADY_PUBLISHED_RE.search(combined):
        print(f"Skipping already-published package version for {tarball.name}")
        return 0

    return proc.returncode


def main() -> int:
    args = parse_args()
    root = args.root.expanduser().resolve()
    if not root.is_dir():
        raise SystemExit(f"Tarball directory not found: {root}")

    tarballs = sorted(
        (
            path
            for path in root.iterdir()
            if path.is_file() and path.name.endswith(f"-{args.version}.tgz")
        ),
        key=lambda path: tarball_publish_rank(path.name, args.version),
    )
    if not tarballs:
        raise SystemExit(f"No npm tarballs found in {root} for version {args.version}")

    for tarball in tarballs:
        npm_tag = classify_tarball(tarball.name, args.version, args.npm_tag)
        if npm_tag is None:
            raise SystemExit(f"Unexpected npm tarball: {tarball.name}")
        status = run_publish(tarball, npm_tag=npm_tag, dry_run=args.dry_run)
        if status != 0:
            return status

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

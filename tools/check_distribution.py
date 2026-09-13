#!/usr/bin/env python3
"""Verify that SmartThings-Local wheel and sdist contents are intentional."""

from __future__ import annotations

import argparse
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


class DistributionError(RuntimeError):
    """An artifact contains a missing, unexpected, or unsafe member."""


def _tracked_files() -> set[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z", "--", "smartthings_local"],
        capture_output=True,
        check=True,
    )
    return {value.decode("utf-8") for value in proc.stdout.split(b"\0") if value}


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts


def _expected_package_files() -> set[str]:
    tracked = {
        path for path in _tracked_files() if path.startswith("smartthings_local/")
    }
    tracked.add("smartthings_local/_version.py")
    return tracked


def check_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
    if not names or any(not _safe_member(name) for name in names):
        raise DistributionError("wheel has an unsafe member")

    package_files = {name for name in names if name.startswith("smartthings_local/")}
    if package_files != _expected_package_files():
        raise DistributionError(
            "wheel package contents differ from the tracked package"
        )

    metadata = names - package_files
    roots = {name.split("/", 1)[0] for name in metadata}
    if len(roots) != 1:
        raise DistributionError("wheel must contain one dist-info directory")
    dist_info = roots.pop()
    if not dist_info.endswith(".dist-info"):
        raise DistributionError("wheel metadata directory is invalid")
    expected_metadata = {
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/licenses/LICENSE",
        f"{dist_info}/licenses/NOTICE",
        f"{dist_info}/RECORD",
    }
    if metadata != expected_metadata:
        raise DistributionError("wheel metadata contents are unexpected")


def check_sdist(path: Path) -> None:
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
    if not members or any(
        not member.isfile() or member.issym() or member.islnk() for member in members
    ):
        raise DistributionError("sdist must contain regular files only")
    names = {member.name for member in members}
    if any(not _safe_member(name) for name in names):
        raise DistributionError("sdist has an unsafe member")

    roots = {name.split("/", 1)[0] for name in names}
    if len(roots) != 1:
        raise DistributionError("sdist must contain one top-level directory")
    root = roots.pop()
    relative = {name[len(root) + 1 :] for name in names if name.startswith(f"{root}/")}
    required = _tracked_files() | {
        "LICENSE",
        "NOTICE",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "smartthings_local/_version.py",
    }
    # hatchling bundles the VCS ignore files it finds, but which ones ship
    # depends on the hatchling version (newer releases drop .hgignore), so
    # treat them as optional rather than exact members.
    optional = {".gitignore", ".hgignore"}
    if not required <= relative <= required | optional:
        raise DistributionError("sdist contents differ from the intended source set")


def check_directory(directory: Path) -> None:
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise DistributionError("expected exactly one wheel and one sdist")
    check_wheel(wheels[0])
    check_sdist(sdists[0])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        check_directory(args.directory)
    except (
        DistributionError,
        OSError,
        subprocess.SubprocessError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ):
        print("distribution check failed")
        return 1
    print("distribution contents verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

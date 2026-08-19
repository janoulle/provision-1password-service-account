#!/usr/bin/env python3
"""Synchronize an allowlisted public mirror with a private canonical skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath


STATE_NAME = ".mirror-state.json"
MANIFEST_NAME = "mirror-manifest.json"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mirror", type=Path, default=Path.cwd())
    parser.add_argument("--source", type=Path)
    parser.add_argument("--manifest", type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--verify-state", action="store_true")
    return parser.parse_args(argv)


def safe_relative(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or "." in candidate.parts or ".." in candidate.parts:
        raise ValueError(f"{label} must be a normalized relative path: {value}")
    return Path(*candidate.parts)


def inside(root: Path, relative: Path, label: str) -> Path:
    target = root / relative
    resolved = target.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} escapes its repository boundary") from error
    return target


def reject_symlink_path(root: Path, relative: Path, label: str) -> None:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symbolic link: {relative.as_posix()}")


def load_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as error:
        raise ValueError(f"{label} is missing: {path.name}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"{label} is not valid JSON: {error}") from error


def load_manifest(mirror: Path, manifest_path: Path) -> tuple[dict[str, str], list[tuple[Path, Path]]]:
    raw = load_json(manifest_path, "mirror manifest")
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("mirror manifest must use schema_version 1")
    canonical = raw.get("canonical")
    if not isinstance(canonical, dict) or not isinstance(canonical.get("skill"), str):
        raise ValueError("mirror manifest canonical.skill is required")
    files = raw.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("mirror manifest files must be a non-empty list")

    mappings: list[tuple[Path, Path]] = []
    destinations: set[Path] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise ValueError(f"files[{index}] must be an object")
        source = safe_relative(item.get("source"), f"files[{index}].source")
        destination = safe_relative(item.get("destination"), f"files[{index}].destination")
        if destination in destinations:
            raise ValueError(f"duplicate mirror destination: {destination.as_posix()}")
        destinations.add(destination)
        inside(mirror, destination, "mirror destination")
        reject_symlink_path(mirror, destination, "mirror destination")
        mappings.append((source, destination))
    return {"skill": canonical["skill"]}, mappings


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".mirror-copy-", dir=destination.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".mirror-state-", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def expected_state(skill: str, mirror: Path, mappings: list[tuple[Path, Path]]) -> dict[str, object]:
    hashes = {
        destination.as_posix(): digest(inside(mirror, destination, "mirror destination"))
        for _, destination in mappings
    }
    return {"schema_version": 1, "canonical_skill": skill, "files": hashes}


def verify_state(mirror: Path, skill: str, mappings: list[tuple[Path, Path]]) -> list[str]:
    state_path = mirror / STATE_NAME
    raw = load_json(state_path, "mirror state")
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("mirror state must use schema_version 1")
    if raw.get("canonical_skill") != skill:
        raise ValueError("mirror state canonical skill does not match the manifest")
    hashes = raw.get("files")
    if not isinstance(hashes, dict):
        raise ValueError("mirror state files must be an object")
    expected_destinations = {destination.as_posix() for _, destination in mappings}
    if set(hashes) != expected_destinations:
        raise ValueError("mirror state file inventory does not match the manifest")
    differences: list[str] = []
    for destination in sorted(expected_destinations):
        target = inside(mirror, Path(destination), "mirror destination")
        if not target.is_file() or digest(target) != hashes[destination]:
            differences.append(destination)
    return differences


def synchronize(
    source_root: Path,
    mirror: Path,
    skill: str,
    mappings: list[tuple[Path, Path]],
    apply: bool,
) -> list[str]:
    differences: list[str] = []
    for source_relative, destination_relative in mappings:
        source = inside(source_root, source_relative, "canonical source")
        reject_symlink_path(source_root, source_relative, "canonical source")
        if not source.is_file():
            raise ValueError(f"canonical file is missing: {source_relative.as_posix()}")
        destination = inside(mirror, destination_relative, "mirror destination")
        same = destination.is_file() and digest(source) == digest(destination)
        if same:
            continue
        differences.append(destination_relative.as_posix())
        if apply:
            atomic_copy(source, destination)
            print(f"UPDATED: {destination_relative.as_posix()}")
    if apply:
        atomic_json(mirror / STATE_NAME, expected_state(skill, mirror, mappings))
    return differences


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    mirror = args.mirror.expanduser().resolve()
    if not mirror.is_dir():
        raise ValueError("mirror repository directory does not exist")
    manifest_path = (args.manifest or mirror / MANIFEST_NAME).expanduser().resolve()
    try:
        manifest_path.relative_to(mirror)
    except ValueError as error:
        raise ValueError("mirror manifest must be inside the mirror repository") from error
    canonical, mappings = load_manifest(mirror, manifest_path)

    if args.verify_state:
        differences = verify_state(mirror, canonical["skill"], mappings)
        if differences:
            for path in differences:
                print(f"STATE-DRIFT: {path}", file=sys.stderr)
            return 1
        print("Mirror files match the recorded content state.")
        return 0

    if args.source is None:
        raise ValueError("--source is required with --check or --apply")
    source = args.source.expanduser().resolve()
    if not source.is_dir():
        raise ValueError("canonical skill directory does not exist")
    differences = synchronize(source, mirror, canonical["skill"], mappings, args.apply)
    if args.check and differences:
        for path in differences:
            print(f"SOURCE-DRIFT: {path}", file=sys.stderr)
        return 1
    if args.check:
        state_differences = verify_state(mirror, canonical["skill"], mappings)
        if state_differences:
            for path in state_differences:
                print(f"STATE-DRIFT: {path}", file=sys.stderr)
            return 1
        print("Mirror matches the canonical allowlist and recorded state.")
    elif not differences:
        print("Mirror already matches the canonical allowlist.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"Mirror synchronization failed: {error}", file=sys.stderr)
        raise SystemExit(2)

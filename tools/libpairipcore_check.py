#!/usr/bin/env python3
"""Read-only detector for libpairipcore.so in APK and split-APK archives."""
from __future__ import annotations

import argparse
import io
import sys
import zipfile
from pathlib import Path
from typing import Iterable

TARGET = "libpairipcore.so"
CONTAINERS = (".apk", ".apks", ".xapk", ".zip")


def find_library(data: bytes, label: str, depth: int = 0) -> Iterable[str]:
    """Yield archive paths containing an entry whose basename matches TARGET."""
    if depth > 6:
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive.namelist():
                if name.rsplit("/", 1)[-1].casefold() == TARGET:
                    yield f"{label}!/{name}"
                elif name.casefold().endswith(CONTAINERS):
                    try:
                        nested = archive.read(name)
                    except (KeyError, RuntimeError, OSError, zipfile.BadZipFile):
                        continue
                    yield from find_library(nested, f"{label}!/{name}", depth + 1)
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check APK/APKS/XAPK/ZIP files for libpairipcore.so (read-only)."
    )
    parser.add_argument("input", type=Path, help="APK, APKS, XAPK, or ZIP file")
    args = parser.parse_args()

    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 2

    try:
        data = args.input.read_bytes()
    except OSError as exc:
        print(f"Unable to read input: {exc}", file=sys.stderr)
        return 2

    matches = list(find_library(data, str(args.input)))
    if matches:
        print(f"FOUND {TARGET} ({len(matches)} entr{'y' if len(matches) == 1 else 'ies'}):")
        for match in matches:
            print(f"  {match}")
        print("This confirms the file is present; it does not prove the library is active at runtime.")
        return 0

    print(f"NOT FOUND: {TARGET} was not present in the scanned archive entries.")
    print("A negative result does not rule out runtime downloading or renamed/packed libraries.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Read-only DEX inspector for APK/DEX/ZIP files. Does not modify or patch inputs."""
from __future__ import annotations

import argparse
import io
import re
import struct
import sys
import zipfile
from pathlib import Path
from typing import BinaryIO, Iterable


def uleb128(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift > 35:
            break
    raise ValueError("invalid ULEB128")


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_cstring(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    # DEX uses modified UTF-8. Replacement decoding keeps inspection resilient.
    return data[offset:end].decode("utf-8", errors="replace")


def parse_dex(data: bytes) -> dict[str, list[str]]:
    if len(data) < 112 or not data.startswith(b"dex\n"):
        raise ValueError("not a valid DEX header")
    if u32(data, 32) > len(data):
        raise ValueError("DEX file_size exceeds input length")

    def section(size_off: int, data_off: int, width: int) -> list[int]:
        size, off = u32(data, size_off), u32(data, data_off)
        if size == 0:
            return []
        if off > len(data) or size > (len(data) - off) // width:
            raise ValueError("DEX section is outside file bounds")
        return [u32(data, off + i * width) for i in range(size)]

    string_offsets = section(56, 60, 4)
    strings: list[str] = []
    for off in string_offsets:
        if off >= len(data):
            strings.append("")
            continue
        _, start = uleb128(data, off)
        strings.append(read_cstring(data, start))

    type_count, type_off = u32(data, 64), u32(data, 68)
    if type_count and (type_off > len(data) or type_count > (len(data)-type_off)//4):
        raise ValueError("type_ids section is outside file bounds")
    types = [strings[u32(data, type_off + i * 4)] if u32(data, type_off + i*4) < len(strings) else ""
             for i in range(type_count)]

    fields: list[str] = []
    field_count, field_off = u32(data, 80), u32(data, 84)
    if field_count and (field_off > len(data) or field_count > (len(data)-field_off)//8):
        raise ValueError("field_ids section is outside file bounds")
    for i in range(field_count):
        off = field_off + i * 8
        cls_idx, type_idx, name_idx = u16(data, off), u16(data, off+2), u32(data, off+4)
        cls = types[cls_idx] if cls_idx < len(types) else "?"
        typ = types[type_idx] if type_idx < len(types) else "?"
        name = strings[name_idx] if name_idx < len(strings) else "?"
        fields.append(f"{cls}->{name}:{typ}")

    methods: list[str] = []
    method_count, method_off = u32(data, 88), u32(data, 92)
    if method_count and (method_off > len(data) or method_count > (len(data)-method_off)//8):
        raise ValueError("method_ids section is outside file bounds")
    for i in range(method_count):
        off = method_off + i * 8
        cls_idx, _proto_idx, name_idx = u16(data, off), u16(data, off+2), u32(data, off+4)
        cls = types[cls_idx] if cls_idx < len(types) else "?"
        name = strings[name_idx] if name_idx < len(strings) else "?"
        methods.append(f"{cls}->{name}")

    classes: list[str] = []
    class_count, class_off = u32(data, 96), u32(data, 100)
    if class_count and (class_off > len(data) or class_count > (len(data)-class_off)//32):
        raise ValueError("class_defs section is outside file bounds")
    for i in range(class_count):
        idx = u32(data, class_off + i * 32)
        classes.append(types[idx] if idx < len(types) else "?")

    return {"class": classes, "method": methods, "field": fields, "string": strings}


def iter_dex(source: bytes, label: str, depth: int = 0) -> Iterable[tuple[str, bytes]]:
    if source.startswith(b"dex\n"):
        yield label, source
        return
    if depth > 5:
        return
    try:
        with zipfile.ZipFile(io.BytesIO(source)) as archive:
            for name in archive.namelist():
                lower = name.lower()
                if lower.endswith(".dex"):
                    yield f"{label}!/{name}", archive.read(name)
                elif lower.endswith((".apk", ".apks", ".xapk", ".zip")):
                    yield from iter_dex(archive.read(name), f"{label}!/{name}", depth + 1)
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Search every DEX in an APK/DEX/ZIP (read-only).")
    parser.add_argument("input", type=Path, help="APK, DEX, APKS, XAPK, or ZIP file")
    parser.add_argument("-q", "--query", action="append", default=[],
                        help="case-insensitive literal search; may be repeated")
    parser.add_argument("--kind", choices=("all", "class", "method", "field", "string"), default="all",
                        help="which DEX index to search (default: all)")
    parser.add_argument("--limit", type=int, default=0, help="maximum matches; 0 means unlimited")
    args = parser.parse_args()
    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 2
    queries = [q.casefold() for q in args.query]
    total_dex = total_matches = 0
    try:
        raw = args.input.read_bytes()
        found = list(iter_dex(raw, str(args.input)))
        if not found:
            print("No DEX files found. Supported containers: APK, APKS, XAPK, ZIP, or raw DEX.")
            return 1
        for dex_label, dex_data in found:
            total_dex += 1
            try:
                indexes = parse_dex(dex_data)
            except (ValueError, struct.error) as exc:
                print(f"[WARN] {dex_label}: {exc}", file=sys.stderr)
                continue
            kinds = (args.kind,) if args.kind != "all" else ("class", "method", "field", "string")
            for kind in kinds:
                for item in indexes[kind]:
                    if queries and not any(q in item.casefold() for q in queries):
                        continue
                    print(f"{dex_label}\t{kind}\t{item}")
                    total_matches += 1
                    if args.limit and total_matches >= args.limit:
                        print(f"Scanned {total_dex}/{len(found)} DEX file(s); displayed {total_matches} match(es).")
                        return 0
        print(f"Scanned {total_dex} DEX file(s); displayed {total_matches} match(es).")
        return 0
    except OSError as exc:
        print(f"Unable to read input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Read-only inspector/comparator/status dashboard for libpairipcore.so."""
from __future__ import annotations

import argparse
import hashlib
import html
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TARGET = "libpairipcore.so"
CONTAINERS = (".apk", ".apks", ".xapk", ".zip")
PRINTABLE = re.compile(rb"[ -~]{4,}")
PAGE = r"""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Native Library Inspector</title>
<style>
:root{color-scheme:dark}body{font:16px system-ui;max-width:850px;margin:24px auto;padding:0 14px;background:#101318;color:#e8edf5}
h1{font-size:1.5rem}p{color:#b9c2d0}.card{background:#1b212b;border:1px solid #343d4b;border-radius:14px;padding:16px;margin:14px 0}
button{background:#b9f3d0;color:#12271c;border:0;border-radius:9px;padding:11px 14px;font-weight:700;margin:5px 5px 5px 0}
input{max-width:100%;margin:8px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#090b0f;padding:12px;border-radius:8px}
small{color:#9da8b7}
</style></head><body><h1>libpairipcore.so — Read-only tools</h1>
<p>Choose files from this device. The dashboard only reads uploaded files; it never modifies an APK or native library.</p>
<div class="card"><h2>1. Check APK / split bundle</h2><input id="apk" type="file" accept=".apk,.apks,.xapk,.zip"><br><button onclick="send('status','apk')">Check library status</button></div>
<div class="card"><h2>2. Inspect native library</h2><input id="one" type="file" accept=".so"><br><button onclick="send('inspect','one')">Inspect ELF / strings / symbols</button></div>
<div class="card"><h2>3. Compare two libraries</h2><input id="left" type="file" accept=".so"><br><input id="right" type="file" accept=".so"><br><button onclick="compare()">Compare libraries</button></div>
<div class="card"><h2>Results</h2><pre id="out">Select a file and choose an action.</pre><small>Exported symbols are shown only when the local environment provides readelf. Strings are printable ASCII sequences, not a complete disassembly.</small></div>
<script>
async function post(action,file){if(!file){out.textContent='Please select a file first.';return}out.textContent='Reading…';try{let r=await fetch('/api/'+action+'?name='+encodeURIComponent(file.name),{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:file});let j=await r.json();out.textContent=j.result||j.error||JSON.stringify(j,null,2)}catch(e){out.textContent='Request failed: '+e}}
function send(action,id){post(action,document.getElementById(id).files[0])}
async function compare(){let a=left.files[0],b=right.files[0];if(!a||!b){out.textContent='Choose both library files first.';return}out.textContent='Comparing…';try{let r=await fetch('/api/compare?left='+encodeURIComponent(a.name)+'&right='+encodeURIComponent(b.name),{method:'POST',headers:{'Content-Type':'application/octet-stream','X-Compare-Name':encodeURIComponent(b.name)},body:await pack(a,b)});let j=await r.json();out.textContent=j.result||j.error||JSON.stringify(j,null,2)}catch(e){out.textContent='Request failed: '+e}}
async function pack(a,b){let x=new Uint8Array(await a.arrayBuffer()),y=new Uint8Array(await b.arrayBuffer()),out=new Uint8Array(8+x.length+y.length);new DataView(out.buffer).setUint32(0,x.length);new DataView(out.buffer).setUint32(4,y.length);out.set(x,8);out.set(y,8+x.length);return out}
</script></body></html>"""


def elf_info(data: bytes, label: str) -> str:
    lines = [f"File: {label}", f"Size: {len(data)} bytes", f"SHA-256: {hashlib.sha256(data).hexdigest()}"]
    if len(data) < 16 or data[:4] != b"\x7fELF":
        lines.append("ELF: not an ELF binary (file may be packed or invalid).")
    else:
        cls = {1: "ELF32", 2: "ELF64"}.get(data[4], f"unknown class {data[4]}")
        endian = {1: "<", 2: ">"}.get(data[5])
        machine = "unknown"
        if endian and len(data) >= 20:
            m = struct.unpack(endian + "H", data[18:20])[0]
            machine = {3:"x86", 40:"ARM", 62:"x86-64", 183:"AArch64", 243:"RISC-V"}.get(m, f"machine {m}")
        lines.append(f"ELF format: {cls}; machine: {machine}; byte order: {'little-endian' if data[5] == 1 else 'big-endian' if data[5] == 2 else 'unknown'}")
    strings = []
    for match in PRINTABLE.finditer(data):
        s = match.group().decode("ascii", "replace")
        if s not in strings:
            strings.append(s)
        if len(strings) >= 80:
            break
    lines.append(f"Printable strings (up to 80): {len(strings)}")
    lines.extend("  " + s[:240] for s in strings)
    readelf = shutil.which("readelf")
    if readelf:
        try:
            proc = subprocess.run([readelf, "-Ws", "-D", "-"], input=data, capture_output=True, timeout=10)
            if proc.returncode == 0:
                symbols = [line.strip() for line in proc.stdout.decode("utf-8", "replace").splitlines()
                           if " GLOBAL " in line or " WEAK " in line]
                lines.append("Dynamic/global symbol rows:")
                lines.extend("  " + s for s in symbols[:100])
            else:
                lines.append("Symbol table: readelf could not parse this input.")
        except (OSError, subprocess.SubprocessError):
            lines.append("Symbol table: readelf failed.")
    else:
        lines.append("Exported symbols: not listed (install binutils/readelf to enable this section).")
    lines.append("Read-only inspection only; no patching or runtime state changes were performed.")
    return "\n".join(lines)


def archive_status(data: bytes, label: str, depth: int = 0) -> list[str]:
    found = []
    if depth > 6:
        return found
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                if name.rsplit("/", 1)[-1].casefold() == TARGET:
                    found.append(f"{label}!/{name}")
                elif name.casefold().endswith(CONTAINERS):
                    try:
                        found.extend(archive_status(z.read(name), f"{label}!/{name}", depth + 1))
                    except (KeyError, RuntimeError, OSError, zipfile.BadZipFile):
                        pass
    except (zipfile.BadZipFile, OSError, RuntimeError):
        pass
    return found


def status_result(data: bytes, label: str) -> str:
    matches = archive_status(data, label)
    if matches:
        return f"FOUND {TARGET} ({len(matches)} entr{'y' if len(matches) == 1 else 'ies'}):\n" + "\n".join("  " + x for x in matches) + "\nPresence does not prove the library is loaded or active."
    return f"NOT FOUND: {TARGET} was not found in scanned archive entries. This cannot rule out runtime downloads or renamed/packed libraries."


def inspect_path(path: Path) -> int:
    try:
        data = path.read_bytes()
    except OSError as e:
        print(f"Unable to read {path}: {e}", file=sys.stderr); return 2
    print(elf_info(data, str(path))); return 0


def compare_path(a: Path, b: Path) -> int:
    try:
        x, y = a.read_bytes(), b.read_bytes()
    except OSError as e:
        print(f"Unable to read comparison input: {e}", file=sys.stderr); return 2
    hx, hy = hashlib.sha256(x).hexdigest(), hashlib.sha256(y).hexdigest()
    print(f"A: {a}\n  size={len(x)} sha256={hx}\nB: {b}\n  size={len(y)} sha256={hy}")
    print("Result: IDENTICAL" if x == y else "Result: DIFFERENT")
    print("Comparison is read-only; neither file was changed.")
    if x[:4] == b"\x7fELF" and y[:4] == b"\x7fELF":
        print("A ELF summary: " + elf_info(x, str(a)).splitlines()[3])
        print("B ELF summary: " + elf_info(y, str(b)).splitlines()[3])
    return 0


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("HTTP:", fmt % args)

    def _json(self, payload, code=200):
        raw = json.dumps(payload).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_GET(self):
        if urlparse(self.path).path != "/":
            self._json({"error":"Not found"}, 404); return
        raw = PAGE.encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_POST(self):
        parsed = urlparse(self.path)
        n = int(self.headers.get("Content-Length", "0"))
        if n > 200 * 1024 * 1024:
            self._json({"error":"File too large (limit 200 MiB)."}, 413); return
        data = self.rfile.read(n)
        q = parse_qs(parsed.query)
        name = os.path.basename(q.get("name", ["upload"])[0])
        try:
            if parsed.path == "/api/inspect":
                result = elf_info(data, name)
            elif parsed.path == "/api/status":
                result = status_result(data, name)
            elif parsed.path == "/api/compare":
                if len(data) < 8:
                    raise ValueError("Comparison payload is incomplete.")
                size_a, size_b = struct.unpack(">II", data[:8])
                if 8 + size_a + size_b != len(data):
                    raise ValueError("Comparison payload lengths do not match.")
                a, b = data[8:8+size_a], data[8+size_a:]
                left = q.get("left", ["file A"])[0]; right = q.get("right", ["file B"])[0]
                result = (f"A: {left}\n  size={len(a)} sha256={hashlib.sha256(a).hexdigest()}\n"
                          f"B: {right}\n  size={len(b)} sha256={hashlib.sha256(b).hexdigest()}\n"
                          + ("Result: IDENTICAL" if a == b else "Result: DIFFERENT")
                          + "\nComparison is read-only; neither file was changed.")
            else:
                self._json({"error":"Unknown action"}, 404); return
            self._json({"result": result})
        except Exception as e:
            self._json({"error": str(e)}, 400)


def main() -> int:
    p = argparse.ArgumentParser(description="Read-only libpairipcore inspector, comparator, and APK status checker.")
    sub = p.add_subparsers(dest="command", required=True)
    i = sub.add_parser("inspect", help="Inspect ELF header, printable strings and available symbol table")
    i.add_argument("library", type=Path)
    c = sub.add_parser("compare", help="Compare two library files by bytes and SHA-256")
    c.add_argument("first", type=Path); c.add_argument("second", type=Path)
    s = sub.add_parser("status", help="Check APK/APKS/XAPK/ZIP for libpairipcore.so")
    s.add_argument("archive", type=Path)
    w = sub.add_parser("serve", help="Start Android-friendly local web dashboard")
    w.add_argument("--host", default="127.0.0.1"); w.add_argument("--port", type=int, default=8765)
    args = p.parse_args()
    if args.command == "inspect": return inspect_path(args.library)
    if args.command == "compare": return compare_path(args.first, args.second)
    if args.command == "status":
        try: data = args.archive.read_bytes()
        except OSError as e: print(f"Unable to read {args.archive}: {e}", file=sys.stderr); return 2
        print(status_result(data, str(args.archive))); return 0
    if args.command == "serve":
        server = ThreadingHTTPServer((args.host, args.port), Handler)
        print(f"Dashboard ready at http://{args.host}:{args.port}/ (Ctrl+C to stop)")
        try: server.serve_forever()
        except KeyboardInterrupt: pass
        finally: server.server_close()
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

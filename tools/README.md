# DEX Inspector (read-only)

This repository currently has no Android Gradle project at the `JaDX` branch root, so the DEX scanner is provided as a standalone Python utility. It inspects APK/DEX containers and does not patch or modify them.

## Requirements

- Python 3.10 or newer
- No third-party Python packages required

## Usage

Search every class, method, field, and DEX string in an APK:

```sh
python tools/dex_inspector.py app.apk
```

Search for a term across all indexed entries:

```sh
python tools/dex_inspector.py app.apk --query example --query com.example
```

Search only class names or strings:

```sh
python tools/dex_inspector.py app.apk --kind class --query MainActivity
python tools/dex_inspector.py app.apk --kind string --query endpoint
```

The scanner examines every `classes*.dex` entry it finds, including DEX files nested in APK/APKS/XAPK/ZIP containers. Output includes the container path, match type, and entry. Use only on files you are authorized to inspect.

## Checks

```sh
python -m py_compile tools/dex_inspector.py
python -m unittest discover -s tools/tests -v
```

GitHub Actions runs these checks on pushes and pull requests to `JaDX`.

## Limitations

This is a symbol/string index, not a full decompiler or Android APK builder. It does not recover method bodies or patch bytecode. Some unusual or malformed DEX files may be skipped with a warning.

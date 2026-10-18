# DEX Inspector and Native Library Check (read-only)

This repository currently has no Android Gradle project at the `JaDX` branch root, so these checks are standalone Python utilities. They inspect APK/archive contents and do not patch or modify inputs.

## Requirements

- Python 3.10 or newer
- No third-party Python packages required

## DEX search

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

The scanner examines every DEX entry it finds, including DEX files nested in APK/APKS/XAPK/ZIP containers. Output includes the container path, match type, and entry.

## Check for libpairipcore.so

Check an APK or split-APK bundle for an entry named `libpairipcore.so`:

```sh
python tools/libpairipcore_check.py app.apk
python tools/libpairipcore_check.py app.apks
```

The result lists matching archive paths, including ABI folders such as `lib/arm64-v8a/`. Exit code is 0 when found, 1 when not found, and 2 for input/read errors. A positive result confirms the file is packaged in the inspected archive; it does not prove it is loaded or active at runtime. A negative result cannot rule out libraries downloaded at runtime or libraries that have been renamed or packed.

Use only on files you are authorized to inspect.

## Checks

```sh
python -m py_compile tools/dex_inspector.py tools/libpairipcore_check.py
python -m unittest discover -s tools/tests -v
```

GitHub Actions runs the DEX inspector checks on pushes and pull requests to `JaDX`.

## Limitations

These are read-only inspection tools, not a full decompiler or Android APK builder. They do not recover all method bodies, disable native libraries, or patch bytecode. Some unusual or malformed DEX/archive files may be skipped with a warning.

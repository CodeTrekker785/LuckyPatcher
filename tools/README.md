# DEX Inspector and Native Library Check (read-only)

The `JaDX` branch currently uses standalone Python utilities; it does not contain an Android Gradle project to build into a native APK. The optional local web dashboard provides Android-friendly buttons in your browser.

## Requirements

- Python 3.10 or newer
- No third-party Python packages required for the standard checks
- Optional: `readelf` from binutils to show exported/global ELF symbols

## DEX search

Search every class, method, field, and DEX string in an APK:

```sh
python tools/dex_inspector.py app.apk
python tools/dex_inspector.py app.apk --query example --query com.example
python tools/dex_inspector.py app.apk --kind class --query MainActivity
python tools/dex_inspector.py app.apk --kind string --query endpoint
```

## Check for libpairipcore.so

```sh
python tools/libpairipcore_check.py app.apk
python tools/libpairipcore_check.py app.apks
```

The check lists matching archive paths, including ABI folders and nested split APKs. Presence does not prove runtime loading; absence cannot rule out runtime downloads or renamed/packed libraries.

## Native library modifier toolkit (read-only)

The modifier toolkit includes three functions: ELF/header and printable-string inspection, byte-for-byte comparison of two library files, and archive status checks. It never writes back to input files, changes loaded libraries, or patches application protections/license checks.

### Termux commands

```sh
python tools/libpairipcore_modifier.py inspect /path/to/libpairipcore.so
python tools/libpairipcore_modifier.py compare /path/to/old.so /path/to/new.so
python tools/libpairipcore_modifier.py status /path/to/app.apk
# Split bundles are supported too:
python tools/libpairipcore_modifier.py status /path/to/app.apks
```

Inspect prints SHA-256, size, ELF class/architecture when identifiable, and up to 80 distinct printable strings. If `readelf` is installed and can parse the file, it also attempts to show global/weak dynamic symbol rows. Stripped libraries may expose few or no symbols.

### Android-friendly browser dashboard

Run this in Termux:

```sh
python tools/libpairipcore_modifier.py serve
```

Then open `http://127.0.0.1:8765` in Chrome on the same phone. Use the buttons to check an APK/APKS/XAPK/ZIP, inspect a `.so`, or compare two `.so` files. The dashboard accepts files selected by you and processes them locally through the Termux server. Stop the server with Ctrl+C.

The dashboard listens on localhost by default. Do not bind it to a public interface; uploads are not authenticated.

## Tests

```sh
python -m py_compile tools/dex_inspector.py tools/libpairipcore_check.py tools/libpairipcore_modifier.py
python -m unittest discover -s tools/tests -v
```

GitHub Actions runs the Python compile checks and unit tests on pushes and pull requests to `JaDX`.

## Limitations

These are read-only inspection utilities, not a full decompiler, Android app builder, or runtime loader monitor. They do not enable/disable a native library or bypass third-party protections or license verification. Some malformed archives or ELF variants may not provide complete information.

## Native Android APK

A basic Android app is now included under `app/`. It has buttons to check APK/APKS/XAPK files for `libpairipcore.so`, inspect a selected native library's ELF header/strings/hash, and compare two library files.

The GitHub Actions workflow `.github/workflows/android-apk.yml` builds a debug APK on pushes to `JaDX` and on manual runs. Open the repository's **Actions → Android APK Build → latest successful run → Artifacts** to download `Native-Library-Inspector-debug-APK`. Version tags beginning with `v` also attach the APK to a GitHub Release.

This is a lightweight inspector APK, not the original LuckyPatcher app. It is not yet a signed production release; the debug APK is for testing. The app is read-only and does not disable third-party protections or license verification.

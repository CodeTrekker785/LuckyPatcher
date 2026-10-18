import io
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from libpairipcore_check import find_library


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buf.getvalue()


class LibraryCheckTests(unittest.TestCase):
    def test_finds_library_in_abi_directory(self):
        apk = make_zip({"lib/arm64-v8a/libpairipcore.so": b"fake-test-data"})
        matches = list(find_library(apk, "sample.apk"))
        self.assertEqual(len(matches), 1)
        self.assertIn("lib/arm64-v8a/libpairipcore.so", matches[0])

    def test_finds_library_inside_nested_apk(self):
        nested_apk = make_zip({"lib/armeabi-v7a/libpairipcore.so": b"fake-test-data"})
        bundle = make_zip({"splits/base.apk": nested_apk})
        matches = list(find_library(bundle, "sample.apks"))
        self.assertEqual(len(matches), 1)
        self.assertIn("splits/base.apk", matches[0])

    def test_missing_library_returns_no_matches(self):
        apk = make_zip({"lib/arm64-v8a/libother.so": b"fake-test-data"})
        self.assertEqual(list(find_library(apk, "sample.apk")), [])

    def test_invalid_archive_is_handled(self):
        self.assertEqual(list(find_library(b"not a zip", "broken.apk")), [])


if __name__ == "__main__":
    unittest.main()

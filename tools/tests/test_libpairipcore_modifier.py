import io
import unittest
import zipfile

from tools.libpairipcore_modifier import archive_status, elf_info, status_result


def archive(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return out.getvalue()


class ModifierToolTests(unittest.TestCase):
    def test_status_finds_native_library(self):
        data = archive({"lib/arm64-v8a/libpairipcore.so": b"\x7fELF"})
        self.assertIn("FOUND libpairipcore.so", status_result(data, "app.apk"))

    def test_status_finds_nested_split_apk(self):
        nested = archive({"lib/arm64-v8a/libpairipcore.so": b"binary"})
        data = archive({"splits/base.apk": nested})
        self.assertIn("splits/base.apk!/lib/arm64-v8a/libpairipcore.so",
                      status_result(data, "app.apks"))

    def test_status_missing_library(self):
        data = archive({"classes.dex": b"dex"})
        self.assertIn("NOT FOUND", status_result(data, "app.apk"))

    def test_invalid_archive_is_reported_as_not_found(self):
        self.assertIn("NOT FOUND", status_result(b"not a zip", "bad.apk"))

    def test_elf_inspection_reports_hash_and_architecture(self):
        data = bytearray(64)
        data[:4] = b"\x7fELF"
        data[4] = 2
        data[5] = 1
        data[18:20] = (183).to_bytes(2, "little")
        report = elf_info(bytes(data), "test.so")
        self.assertIn("SHA-256:", report)
        self.assertIn("AArch64", report)


if __name__ == "__main__":
    unittest.main()

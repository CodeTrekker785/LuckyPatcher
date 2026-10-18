import importlib.util
import struct
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "dex_inspector.py"
SPEC = importlib.util.spec_from_file_location("dex_inspector", MODULE_PATH)
dex_inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dex_inspector)


def empty_dex():
    data = bytearray(112)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<I", data, 32, 112)       # file_size
    struct.pack_into("<I", data, 36, 112)       # header_size
    struct.pack_into("<I", data, 40, 0x12345678)  # endian_tag
    return bytes(data)


class DexInspectorTests(unittest.TestCase):
    def test_uleb128_single_byte(self):
        self.assertEqual(dex_inspector.uleb128(b"\x7f", 0), (127, 1))

    def test_uleb128_multibyte(self):
        self.assertEqual(dex_inspector.uleb128(b"\xac\x02", 0), (300, 2))

    def test_parse_empty_valid_dex(self):
        self.assertEqual(
            dex_inspector.parse_dex(empty_dex()),
            {"class": [], "method": [], "field": [], "string": []},
        )

    def test_reject_non_dex_input(self):
        with self.assertRaises(ValueError):
            dex_inspector.parse_dex(b"not a dex")

    def test_reject_out_of_bounds_section(self):
        data = bytearray(empty_dex())
        struct.pack_into("<I", data, 56, 1)   # string_ids_size
        struct.pack_into("<I", data, 60, 110) # string_ids_off: impossible for one item
        with self.assertRaises(ValueError):
            dex_inspector.parse_dex(bytes(data))


if __name__ == "__main__":
    unittest.main()

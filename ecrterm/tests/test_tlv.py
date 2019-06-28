from unittest import TestCase, main

from ecrterm.packets.tlv import *


class TestTLV(TestCase):
    def test_simple(self):
        t = TLVItem.parse_all(b'\x01\x02\x03\x04')

        self.assertEqual(len(t), 1)
        self.assertFalse(t[0].constructed)
        self.assertEqual(t[0].tlv_class, TLVClass.UNIVERSAL)
        self.assertEqual(t[0].length, 2)
        self.assertEqual(t[0].value, b'\x03\x04')

        self.assertEqual(t[0].serialize(), bytearray.fromhex('01020304'))

    def test_container(self):
        c = TLVContainer.from_bytes(b'\x01\x02\x03\x04')

        self.assertEqual(c.x1, b'\x03\x04')

    def test_construction(self):
        t = TLVConstructedItem(tag=0x20, value=[
            TLVItem(tag=0x1e, value=b'012')
        ])

        self.assertEqual(t.x1e, b'012')

        self.assertEqual(t.serialize(), bytearray.fromhex('20051e03303132'))

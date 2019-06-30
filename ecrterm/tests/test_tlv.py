from unittest import TestCase, main

from ecrterm.packets.tlv import *


class TestTLV(TestCase):
    def test_simple(self):
        t = TLVItem.parse_all(b'\x01\x02\x03\x04')

        self.assertEqual(len(t), 1)
        self.assertFalse(t[0].constructed)
        self.assertEqual(TLVClass.UNIVERSAL, t[0].tlv_class)
        self.assertEqual(2, t[0].length)
        self.assertEqual(b'\x03\x04', t[0].value)

        self.assertEqual(bytearray.fromhex('01020304'), t[0].serialize())

    def test_container(self):
        c = TLVContainer.from_bytes(b'\x01\x02\x03\x04')

        self.assertEqual(c.x1, b'\x03\x04')

    def test_construction(self):
        t = TLVConstructedItem(tag=0x20, value=[
            TLVItem(tag=0x1e, value=b'012')
        ])

        self.assertEqual(t.x1e, b'012')

        self.assertEqual(t.serialize(), bytearray.fromhex('20051e03303132'))

    def test_container_easy_1(self):
        t1 = TLVContainer({'xde': b'012'})

        self.assertEqual(1, len(t1.value))
        self.assertEqual(b'012', t1.xde)

        t2 = TLVContainer({0xde: b'012'})

        self.assertEqual(1, len(t2.value))
        self.assertEqual(b'012', t2.xde)

    def test_container_easy_2(self):
        t1 = TLVContainer(xde=b'012')

        self.assertEqual(1, len(t1.value))
        self.assertEqual(b'012', t1.xde)

    def test_container_easy_3(self):
        t1 = TLVContainer(xfe={'xde': b'23'})

        self.assertIsInstance(t1.xfe, TLVConstructedItem)
        self.assertEqual(b'23', t1.xfe.xde)

    def test_container_easy_4(self):
        t1 = TLVContainer()
        t1.xfe.xde = b'34'

        self.assertIsInstance(t1.xfe, TLVConstructedItem)
        self.assertEqual(b'34', t1.xfe.xde)

    def test_container_implicit_creation(self):
        t1 = TLVContainer()

        self.assertIsInstance(t1.xfe, TLVItem)
        # An implicit item is created, but since we are not accessing its value, it is not fully realized
        self.assertEqual(b'\x00', t1.serialize())

        # But, when assigning to the item, it becomes concrete
        t1.xfe = []
        self.assertEqual(b'\x02\xfe\x00', t1.serialize())

        # This works deep down
        t2 = TLVContainer()

        self.assertIsNone(t2.xfe.xfe.xfe.xfe.xfe.xfe.de)
        self.assertIsInstance(t2.xfe.xfe.xfe.xfe.xfe.xfe, TLVItem)
        self.assertEqual(b'\x00', t2.serialize())

        t2.xfe.xfe.xfe.xfe.xfe.xfe.xde = b''
        self.assertEqual(b'\x0e\xfe\x0c\xfe\x0a\xfe\x08\xfe\x06\xfe\x04\xfe\x02\xde\x00', t2.serialize())

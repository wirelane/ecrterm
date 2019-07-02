from unittest import TestCase, main

from ecrterm.packets.tlv import *


class TestTLV(TestCase):
    def test_simple(self):
        t, r = TLVItem.parse(b'\x01\x02\x03\x04')

        self.assertEqual(b'', r)

        self.assertFalse(t.constructed_)
        self.assertEqual(TLVClass.UNIVERSAL, t.class_)
        self.assertEqual(b'\x03\x04', t.value_)

        self.assertEqual(bytearray.fromhex('01020304'), t.serialize())

    def test_container(self):
        c, r = TLVItem.parse(b'\x04\x01\x02\x03\x04', empty_tag=True)

        self.assertEqual(b'', r)
        self.assertEqual(b'\x03\x04', c.x1)

    def test_construction(self):
        t = TLVItem(tag_=0x20, value_=[
            TLVItem(tag_=0x1e, value_=b'012')
        ])

        self.assertEqual(t.x1e, b'012')

        self.assertEqual(t.serialize(), bytearray.fromhex('20051e03303132'))

    def test_container_easy_1(self):
        t1 = TLVItem({'xde': b'012'})

        self.assertEqual(1, len(t1.value_))
        self.assertEqual(b'012', t1.xde)

        t2 = TLVItem({0xde: b'012'})

        self.assertEqual(1, len(t2.value_))
        self.assertEqual(b'012', t2.xde)

    def test_container_easy_2(self):
        t1 = TLVItem(xde=b'012')

        self.assertEqual(1, len(t1.value_))
        self.assertEqual(b'012', t1.xde)

    def test_container_easy_3(self):
        t1 = TLVItem(xfe={'xde': b'23'})

        self.assertIsInstance(t1.xfe, TLVItem)
        self.assertEqual(b'23', t1.xfe.xde)

    def test_container_easy_4(self):
        t1 = TLVItem()
        t1.xfe.xde = b'34'

        self.assertIsInstance(t1.xfe, TLVItem)
        self.assertEqual(b'34', t1.xfe.xde)

    def test_container_implicit_creation(self):
        t1 = TLVItem()

        self.assertIsInstance(t1.xfe, TLVItem)
        # An implicit item is created, but since we are not accessing its value, it is not fully realized
        self.assertEqual(b'\x00', t1.serialize())

        # But, when assigning to the item, it becomes concrete
        t1.xfe = []
        self.assertEqual(b'\x02\xfe\x00', t1.serialize())

        # This works deep down
        t2 = TLVItem()

        self.assertIsNone(t2.xfe.xfe.xfe.xfe.xfe.xfe.xde)
        self.assertIsInstance(t2.xfe.xfe.xfe.xfe.xfe.xfe, TLVItem)
        self.assertEqual(b'\x00', t2.serialize())

        t2.xfe.xfe.xfe.xfe.xfe.xfe.xde = b''
        self.assertEqual(b'\x0e\xfe\x0c\xfe\x0a\xfe\x08\xfe\x06\xfe\x04\xfe\x02\xde\x00', t2.serialize())

    def test_null_coercion(self):
        a = TLVItem()
        b = TLVItem(a)

        self.assertIs(a, b)


from unittest import TestCase, main, expectedFailure

from ecrterm.packets.tlv import *


class TestTLV(TestCase):
    def test_simple(self):
        t, r = TLV.parse(b'\x01\x02\x03\x04')

        self.assertEqual(b'', r)

        self.assertFalse(t.constructed_)
        self.assertEqual(TLVClass.UNIVERSAL, t.class_)
        self.assertEqual(b'\x03\x04', t.value_)

        self.assertEqual(bytearray.fromhex('01020304'), t.serialize())

    def test_container(self):
        c, r = TLV.parse(b'\x04\x01\x02\x03\x04', empty_tag=True)

        self.assertEqual(b'', r)
        self.assertEqual(b'\x03\x04', c.x1)

    def test_construction(self):
        t = TLV(tag_=0x20, value_=[
            TLV(tag_=0x1e, value_=b'012')
        ])

        self.assertEqual(t.x1e, b'012')

        self.assertEqual(t.serialize(), bytearray.fromhex('20051e03303132'))

    def test_container_easy_1(self):
        t1 = TLV({'xde': b'012'})

        self.assertEqual(1, len(t1.value_))
        self.assertEqual(b'012', t1.xde)

        t2 = TLV({0xde: b'012'})

        self.assertEqual(1, len(t2.value_))
        self.assertEqual(b'012', t2.xde)

    def test_container_easy_2(self):
        t1 = TLV(xde=b'012')

        self.assertEqual(1, len(t1.value_))
        self.assertEqual(b'012', t1.xde)

    def test_container_easy_3(self):
        t1 = TLV(xfe={'xde': b'23'})

        self.assertIsInstance(t1.xfe, TLV)
        self.assertEqual(b'23', t1.xfe.xde)

    def test_container_easy_4(self):
        t1 = TLV()
        t1.xfe.xde = b'34'

        self.assertIsInstance(t1.xfe, TLV)
        self.assertEqual(b'34', t1.xfe.xde)

    def test_container_implicit_creation(self):
        t1 = TLV()

        self.assertIsInstance(t1.xfe, TLV)
        # An implicit item is created, but since we are not accessing its value, it is not fully realized
        self.assertEqual(b'\x00', t1.serialize())

        # But, when assigning to the item, it becomes concrete
        t1.xfe = []
        self.assertEqual(b'\x02\xfe\x00', t1.serialize())

        # This works deep down
        t2 = TLV()

        self.assertIsNone(t2.xfe.xfe.xfe.xfe.xfe.xfe.xde)
        self.assertIsInstance(t2.xfe.xfe.xfe.xfe.xfe.xfe, TLV)
        self.assertEqual(b'\x00', t2.serialize())

        t2.xfe.xfe.xfe.xfe.xfe.xfe.xde = b''
        self.assertEqual(b'\x0e\xfe\x0c\xfe\x0a\xfe\x08\xfe\x06\xfe\x04\xfe\x02\xde\x00', t2.serialize())

    def test_null_coercion(self):
        a = TLV()
        b = TLV(a)

        self.assertIs(a, b)


class TestTLVRepr(TestCase):
    def setUp(self) -> None:
        self.coll_1, dummy_ = TLV.parse(b'\x06\x01\x01\xaa\x02\x01\xbb', empty_tag=True)
        self.par_1, dummy_ = TLV.parse(b'\x20\x06\x21\x04\x03\x02\xab\xcd')

    def test_naked_repr(self):
        self.assertEqual('TLV(x1=b\'\\xaa\', x2=b\'\\xbb\')', repr(self.coll_1))

    def test_nested_repr(self):
        self.assertEqual('TLV(tag_=0x20, x21={\'x3\': b\'\\xab\\xcd\'})', repr(self.par_1))

from unittest import TestCase, main

from ecrterm.packets.fields import *
from ecrterm.packets.tlv import TLVContainer


class TestFields(TestCase):
    def test_intfield_be(self):
        ifield = IntField()

        self.assertEqual(ifield.from_bytes([3]), 3)
        self.assertEqual(ifield.from_bytes([1, 0]), 256)
        self.assertEqual(ifield.from_bytes([0, 1, 0]), 256)

        self.assertEqual(ifield.to_bytes(3, length=1), b'\x03')
        self.assertEqual(ifield.to_bytes(256, length=2), b'\x01\x00')
        self.assertEqual(ifield.to_bytes(256, length=3), b'\x00\x01\x00')

    def test_intfield_le(self):
        ifield = IntField()
        ifield.ENDIAN = Endianness.LITTLE_ENDIAN

        self.assertEqual(ifield.from_bytes([3]), 3)
        self.assertEqual(ifield.from_bytes([1, 0]), 1)
        self.assertEqual(ifield.from_bytes([0, 1, 0]), 256)

        self.assertEqual(ifield.to_bytes(3, length=1), b'\x03')
        self.assertEqual(ifield.to_bytes(256, length=2), b'\x00\x01')
        self.assertEqual(ifield.to_bytes(256, length=3), b'\x00\x01\x00')

    def test_bytefield(self):
        bfield = ByteField()

        self.assertEqual(bfield.from_bytes([0]), 0)
        self.assertEqual(bfield.from_bytes([1]), 1)

        self.assertEqual(bfield.to_bytes(0), b'\x00')
        self.assertEqual(bfield.to_bytes(1), b'\x01')

    def test_beintfield(self):
        ifield = BEIntField(length=4)

        self.assertEqual(ifield.from_bytes([0, 0, 0, 1]), 1)
        self.assertEqual(ifield.from_bytes([0, 0, 1, 0]), 256)

        self.assertEqual(ifield.to_bytes(256), b'\x00\x00\x01\x00')

    def test_bcdintfield(self):
        ifield = BCDIntField(length=3)

        self.assertEqual(ifield.from_bytes(b'\x00\x00\x03'), 3)

        self.assertEqual(ifield.to_bytes(23), b'\x00\x00\x23')
        self.assertEqual(ifield.to_bytes(10023), b'\x01\x00\x23')

    def test_stringfield(self):
        sfield = StringField()

        self.assertEqual(sfield.from_bytes([0x31, 0x32]), '12')

        self.assertEqual(sfield.to_bytes('12', length=2), b'12')

    def test_passwordfield(self):
        pfield = PasswordField()

        self.assertEqual(pfield.from_bytes([0x12, 0x22, 0x34]), '122234')

        self.assertEqual(pfield.to_bytes('234567'), b'\x23\x45\x67')

    def test_LVAR(self):
        lv = LVARField()

        self.assertEqual(lv.parse(b'\xF0'), (b'', b''))
        self.assertEqual(lv.parse(b'\xF1\x12\x34'), (b'\x12', b'\x34'))

        self.assertEqual(lv.serialize(b''), b'\xF0')
        self.assertEqual(lv.serialize(b'\x12\x34'), b'\xF2\x12\x34')

        lllv = LLLVARField()

        self.assertEqual(lllv.parse(b'\xF0\xF0\xF0'), (b'', b''))
        self.assertEqual(lllv.parse(b'\xF0\xF0\xF1\x12\x34'), (b'\x12', b'\x34'))

        self.assertEqual(lllv.serialize(b''), b'\xF0\xF0\xF0')
        self.assertEqual(lllv.serialize(b'\x12\x34'), b'\xF0\xF0\xF2\x12\x34')

        self.assertEqual(lllv.serialize(b'\xAA' * 11), b'\xF0\xF1\xF1' + (b'\xAA' * 11))

    def test_lllstringfield(self):
        ls = LLLStringField()

        self.assertEqual(ls.parse(b'\xF0\xF0\xF2abc'), ('ab', b'c'))

        self.assertEqual(ls.serialize('abc'), b'\xF0\xF0\xF3abc')

    def test_lllstring_regression(self):
        ls = LLLStringField()

        d = b'\xf0\xf7\xf3AS-TID = 13F00013\rAS-Proc-Code = 20 903 00\rCapt.-Ref.= 0000\rAID59: 809258'

        self.assertEqual(('AS-TID = 13F00013\rAS-Proc-Code = 20 903 00\rCapt.-Ref.= 0000\rAID59: 809258', b''), ls.parse(d))

    def test_bytesfield(self):
        bf = BytesField()

        d = b'\xff\x01\x02'

        self.assertEqual((d, b''), bf.parse(d))

        self.assertEqual(d, bf.serialize(d))

    def test_tlvfield(self):
        tf = TLVField()

        c, d = tf.parse(b'\x00')
        self.assertIsInstance(c, TLVContainer)
        self.assertEqual(d, b'')

        self.assertEqual(tf.serialize(TLVContainer(value=[])), b'\x00')

        # FIXME With more tags


if __name__ == '__main__':
    main()

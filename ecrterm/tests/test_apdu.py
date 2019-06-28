from ecrterm.packets.apdu import CommandAPDU
from ecrterm.packets.base_packets import LogOff, Initialisation, Registration
from unittest import TestCase, main


class TestAPDUParser(TestCase):

    def test_parse_simple(self):
        c = CommandAPDU.parse(bytearray.fromhex('060200'))
        self.assertIsInstance(c, LogOff)

    def test_parse_fixed(self):
        c = CommandAPDU.parse(bytearray.fromhex('069303999999'))
        self.assertEqual('999999', c.password)

    def test_parse_fixed_no_optional(self):
        c = CommandAPDU.parse(bytearray.fromhex('06000498765441'))
        self.assertEqual('987654', c.password, )
        self.assertEqual(0x41, c.config_byte)
        self.assertIsNone(c.cc)

    def test_parse_fixed_with_optional(self):
        c = CommandAPDU.parse(bytearray.fromhex('060006987654410978'))
        self.assertEqual(978, c.cc)

    def test_parse_cursed_completion(self):
        c1 = CommandAPDU.parse(bytearray.fromhex('060f07F0F0F3626c6100'))
        self.assertEqual(0x00, c1.terminal_status)
        self.assertEqual('bla', c1.sw_version)

        c2 = CommandAPDU.parse(bytearray.fromhex('060f07F0F0F3626c6106'))
        self.assertEqual(0x06, c2.terminal_status)
        self.assertIsNone(c2.tlv)

        c3 = CommandAPDU.parse(bytearray.fromhex('060f09F0F0F3626c61060600'))
        self.assertEqual(0x06, c3.terminal_status)
        self.assertIsNotNone(c3.tlv)

        c4 = CommandAPDU.parse(bytearray.fromhex('060f0106'))
        self.assertEqual(0x06, c4.terminal_status)
        self.assertIsNone(c4.sw_version)
        self.assertIsNone(c4.tlv)

        c5 = CommandAPDU.parse(bytearray.fromhex('060f03060600'))
        self.assertEqual(0x06, c5.terminal_status)
        self.assertIsNotNone(c5.tlv)


class TestAPDUSerializer(TestCase):

    def test_serialize_simple(self):
        c = LogOff()
        self.assertEqual(bytearray.fromhex('060200'), c.serialize())

    def test_serialize_fixed(self):
        c = Initialisation(password='999999')
        self.assertEqual(bytearray.fromhex('069303999999'), c.serialize())

    def test_serialize_fixed_no_optional(self):
        c = Registration('987654', config_byte=0x41)
        self.assertEqual(bytearray.fromhex('06000498765441'), c.serialize())


class TestAPDUBitmaps(TestCase):
    def test_simple_create_serialize(self):
        c = Registration('777777', 0xa0, cc='0978')
        c.service_byte = 0x0a

        self.assertEqual(bytearray.fromhex('060008777777a00978030a'), c.serialize())

    def test_parse_with_tlv(self):
        c = CommandAPDU.parse(bytearray.fromhex('06501712345606123f210c60065501aa0501bb1002abba110177'))

        self.assertEqual('123456', c.password)
        self.assertEqual(b'\x77', c.tlv.x11)
        self.assertEqual(b'\xaa', c.tlv.x3f21.x60.x55)
        self.assertEqual(b'\xbb', c.tlv.x3f21.x60.x5)
        self.assertEqual(b'\xab\xba', c.tlv.x3f21.x10)

    # FIXME Create empty TLV
    # FIXME Create TLV on access
    # FIXME TLV names


if __name__ == '__main__':
    main()

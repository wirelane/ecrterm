from ecrterm.packets.apdu import CommandAPDU, ParseError
from ecrterm.packets.fields import ByteField, BytesField, BCDIntField
from ecrterm.packets.base_packets import LogOff, Initialisation, Registration, DisplayText, PrintLine, Authorisation, \
    WriteFiles, OpenReservationsEnquiry
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

    def test_parse_error(self):
        self.assertRaises(ParseError, CommandAPDU.parse, bytearray.fromhex('06020322F0E0'))

    def test_parse_cursed_completion(self):
        c1 = CommandAPDU.parse(bytearray.fromhex('060f07F0F0F3626c6100'))
        self.assertEqual(0x00, c1.terminal_status)
        self.assertEqual('bla', c1.sw_version)

        c2 = CommandAPDU.parse(bytearray.fromhex('060f07F0F0F3626c6106'))
        self.assertEqual(0x06, c2.terminal_status)
        self.assertNotIn('tlv', c2.as_dict())

        c3 = CommandAPDU.parse(bytearray.fromhex('060f09F0F0F3626c61060600'))
        self.assertEqual(0x06, c3.terminal_status)
        self.assertIn('tlv', c3.as_dict())

        c4 = CommandAPDU.parse(bytearray.fromhex('060f0106'))
        self.assertEqual(0x06, c4.terminal_status)
        self.assertIsNone(c4.sw_version)
        self.assertNotIn('tlv', c4.as_dict())

        c5 = CommandAPDU.parse(bytearray.fromhex('060f03060600'))
        self.assertEqual(0x06, c5.terminal_status)
        self.assertIn('tlv', c5.as_dict())


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


class TestInvalidAPDUs(TestCase):
    def test_required_after_optional(self):
        def construct_class():
            class WrongPacket(CommandAPDU):
                foo = ByteField(required=False)
                bar = ByteField(required=True)

        self.assertRaises(TypeError, construct_class)

    def test_invalid_length(self):
        def construct_class():
            class WrongPacket(CommandAPDU):
                foo = BCDIntField()

        self.assertRaises(ValueError, construct_class)


class DummyPacket(CommandAPDU):
    CMD_CLASS = 0xff
    CMD_INSTR = 0xaa

    OVERRIDE_BITMAPS = {
        # Warning: This will consume the remainder of the packet. Do not use when more bitmaps are expected.
        0x06: (BytesField(), 'raw_tlv', 'Unparsed TLV'),
    }


class TestAPDUBitmaps(TestCase):
    def test_simple_create_serialize(self):
        c = Registration('777777', 0xa0, cc='0978')
        c.service_byte = 0x0a

        self.assertEqual(bytearray.fromhex('060008777777a00978030a'), c.serialize())

    def test_as_dict(self):
        c = Registration('777777', 0xa0)

        self.assertEqual({'password': '777777', 'config_byte': 0xa0}, c.as_dict())

    def test_nonexisting_attributes(self):
        c = Registration('123456')

        self.assertRaises(AttributeError, lambda: c.foobarbaz)
        self.assertIsNone(c.cc)

    def test_get(self):
        c = Registration('123456')

        self.assertEqual('123456', c.get('password'))
        self.assertEqual(None, c.get('password1', None))

    def test_del(self):
        c = Registration(service_byte=0x1)

        c.password = '123456'

        self.assertEqual('123456', c.password)
        self.assertIsNotNone(c.service_byte)

        del c.password
        del c.service_byte

        self.assertIsNone(c.password)
        self.assertIsNone(c.service_byte)

        c.password = '234567'

        self.assertEqual('234567', c.password)

    def test_unallowed_bitmaps(self):
        c = DisplayText()

        self.assertRaises(AttributeError, setattr, c, 'pump_nr', 1)

    def test_invalid_length(self):
        c = PrintLine(attribute=0x00, text='A' * 65536)

        self.assertRaises(ValueError, c.serialize)

    def test_parse_with_tlv(self):
        c = CommandAPDU.parse(bytearray.fromhex('06501712345606123f210c60065501aa0501bb1002abba110177'))

        self.assertEqual('123456', c.password)
        self.assertEqual(b'\x77', c.tlv.x11)
        self.assertEqual(b'\xaa', c.tlv.x3f21.x60.x55)
        self.assertEqual(b'\xbb', c.tlv.x3f21.x60.x5)
        self.assertEqual(b'\xab\xba', c.tlv.x3f21.x10)

    def test_create_tlv(self):
        c1 = Authorisation(tlv={0xf2: {0xc1: b'\x12\x23'}})

        self.assertEqual(bytearray.fromhex('0601080606f204c1021223'), c1.serialize())

        c2 = Authorisation()
        c2.tlv.xf2.xc1 = b'\x12\x23'
        self.assertEqual(bytearray.fromhex('0601080606f204c1021223'), c2.serialize())

    def test_create_open_reservations_enquiry_packet(self):
        packet = OpenReservationsEnquiry()

        self.assertEqual(bytearray.fromhex('06230387FFFF'), packet.serialize())

    def test_override_bitmaps(self):
        c = CommandAPDU.parse(bytearray.fromhex('ffaa040602ffaa'))

        self.assertIsInstance(c.raw_tlv, bytes)
        self.assertEqual(b'\x02\xff\xaa', c.raw_tlv)

    def test_write_file_apdu(self):
        c = WriteFiles(password='000000',
                       files={
                           32: bytes(str.encode('Test 123')),
                           33: bytes(str.encode('ä ö ü ß')),
                       })
        paket = c.serialize()
        self.assertEqual(bytearray.fromhex('08141d00000006182d0a1d01201f0004000000082d0a1d01211f00040000000b'), paket)

    # FIXME Test TLV names


if __name__ == '__main__':
    main()

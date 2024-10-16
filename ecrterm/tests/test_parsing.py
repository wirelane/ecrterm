"""
Incoming Packets should be always parsable.
this test tries to look at the parser in detail.
"""
from logging import info
from unittest import TestCase, main

from ecrterm.ecr import parse_represented_data
from ecrterm.packets.base_packets import Completion, Packet
from ecrterm.packets.fields import ParseError
from ecrterm.packets.types import CharacterSet
from ecrterm.packets.text_encoding import ZVT_7BIT_CHARACTER_SET
from ecrterm.packets.context import enter_context


class TestParsingMechanisms(TestCase):

    def test_version_completion(self):
        # following completion is sent by the PT with version on
        # statusenquiry:
        data_expected = '10 02 06 0F 0B F0 F0 F7 32 2E 31 34 2E 31 35 00 10 03 B1 11'
        # small test to test the completion with software version to be
        # recognized.
        rep = parse_represented_data(data_expected)
        self.assertEqual(rep.__class__, Completion)

    PACKET_LIST = [
        # 06 D1
        '06 D1 17 00 20 20 20 20 20 20 20 20 20 4B 61 73 73 65 6E '
        '73 63 68 6E 69 74 74',
        # 04 0F
        '04 0F 37 27 00 04 00 00 00 00 40 00 49 09 78 0C 09 38 48 '
        '0D 04 25 22 F1 F1 59 66 66 66 66 D2 00 21 22 01 00 17 00 01 87 '
        '01 75 0B 61 39 95 19 40 29 60 09 99 14 0E 05 12 8A 02',
        '06 00 63 00 00 00 FE 09 78 03 00 06 59 10 02 16 02 12 01 40 1A '
        '02 10 00 26 28 0A 02 04 0F 0A 02 06 0F 0A 02 06 1E 0A 02 04 FF '
        '0A 02 06 D8 0A 02 06 DB 0A 02 06 D9 0A 02 06 DA 0A 02 06 DD 0A '
        '02 06 D3 27 03 14 01 FF 28 10 15 02 44 45 15 02 45 4E 15 02 46 '
        '52 15 02 49 54 40 02 C0 00 1F 04 02 F1 00 1F 05 01 00',
        '06 0F 11 19 00 29 52 00 12 33 49 09 78 06 05 27 03 14 01 FF',
        '06 01 0E 02 01 04 00 00 00 00 10 00 19 44 49 09 78',
        '04 FF 1E 0A 01 06 1A 24 18 07 16 42 69 74 74 65 20 4B 61 72 74 '
        '65 20 65 69 6E 73 74 65 63 6B 65 6E',
        '040fa12700040000000000014909780c1223060d062922f0f8474843eeeeee77438700023b38383931353000000b000732196029420030'
        + '360e18018a0a8c038bf0f556495341002a3435353630303030303539392020203cf0f7f341532d544944203d2031334630303031330d'
        + '41532d50726f632d436f6465203d203230203930332030300d436170742e2d5265662e3d20303030300d41494435393a203830393235'
        + '38',
        '040FCE2700040000000010004909780C1230050D062922F0F8474843EEEEEE77438700023B38383931353000000B000733196029420030'
        + '360E18018A0A8C038BF0F556495341002A3435353630303030303539392020203CF0F7F341532D544944203D2031334630303031330D'
        + '41532D50726F632D436F6465203D203230203930332030300D436170742E2D5265662E3D20303030300D41494435393A203830393235'
        + '38062B4102000A4902000315024445600F4204564953414307A00000000310102F0C1F1001001F1101011F120102',
        '06d3ffe303068203df1f070102258203d70700072820202020202020202020202a2a204b756e64656e62656c6567202a2a202020202020'
        + '202020202020070007282020202020202020202020202042657a61686c756e6720564953412020202020202020202020202007000728'
        + '32392e30362e323031392020202020202020202020202020202020202020202031323a35343a343507285465726d696e616c2d49443a'
        + '20202020202020202020202020202020202020203432303033303336072854412d4e722e3a2020202020202020202020202020202020'
        + '20202020202020202020303030373431072842656c65672d4e722e3a2020202020202020202020202020202020202020202020202020'
        + '303030360728566f7267616e67732d4e722e3a202020202020202020202020202020202020202020202030303234072856552d4e756d'
        + '6d65723a20202020202020202020202020202020202034353536303030303035393907284170702d49443a2020202020202020202020'
        + '2020202020202020413030303030303030333130313007284b617274656e2d4e722e3a20202020202020202020202020787878787878'
        + '7878787878783737343307284b617274656e666f6c67652d4e722e3a2020202020202020202020202020202020202020202030300728'
        + '457266617373756e67736172743a202020202020202020202020202020204b6f6e74616b746c6f7307284175746f722d4e722e3a2020'
        + '2020202020202020202020202020202020202020202038383931353007284149442d506172616d657465723a20202020202020202020'
        + '20202020202031324142303330343035070007284265747261673a20202020202020202020202020202045555220302c303120202020'
        + '2020202020200700070007282020202020202020202020205a61686c756e67206572666f6c6774202020202020202020202020200700'
        + '07282020202020202d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d202020202020200728496e666f3a2020202020'
        + '202020202020202020202020202020202020202020202020202020202020072841532d544944203d2031334630303031332020202020'
        + '202020202020202020202020202020202020072841532d50726f632d436f6465203d2032302039303320303020202020202020202020'
        + '2020202020200728436170742e2d5265662e3d2030303030202020202020202020202020202020202020202020202020072841494435'
        + '393a2038303932353820202020202020202020202020202020202020202020202020202007282020202020202d2d2d2d2d2d2d2d2d2d'
        + '2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d202020202020200901ff',
    ]

    def test_parsing_two(self):
        """
        parse some packets
         - from the tutorial
         - from complicated scenarios
         - from failing parsings
        and tell me if they are understood:
        """
        for idx, packet in enumerate(self.PACKET_LIST):
            rep = parse_represented_data(packet)
            info(rep)
            if not isinstance(rep, Packet):
                raise AssertionError("Packet could not be parsed: #%s" % idx)

    def test_roundtrip(self):
        """
        parse packets, then serialize them again and check
        """
        for idx, packet in enumerate(self.PACKET_LIST):
            parsed = parse_represented_data(packet)
            serialized = parsed.serialize()
            self.assertEqual(str(parsed), str(parse_represented_data(serialized)),
                             "Parsed representation doesn't match serialized representation (case {})".format(idx))
            self.assertEqual(bytearray.fromhex(packet), serialized,
                             "Serialized {} message doesn't match original message (case {})".format(
                                 parsed.__class__.__name__,
                                 idx))

    def test_text_encoding_tlv(self):
        packet = '04ff140a010610240e070c5465737420842094208120e1'
        p = parse_represented_data(packet)

        self.assertEqual('Test ä ö ü ß', p.tlv.x24.x07)

    def test_text_encoding_default(self):
        packet = '06d10d005465737420842094208120e1'
        p = parse_represented_data(packet)

        self.assertEqual('Test ä ö ü ß', p.text)

    def test_text_encoding_utf8(self):
        packet = '06d121005465737420c3a420c3b620c3bc20c39f'

        with enter_context(character_set=CharacterSet.UTF8):
            p = parse_represented_data(packet)

        self.assertEqual('Test ä ö ü ß', p.text)

    def test_text_encoding_latin1(self):
        packet = '06d10d005465737420e420f620fc20df'

        with enter_context(character_set=CharacterSet.LATIN_1):
            p = parse_represented_data(packet)

        self.assertEqual('Test ä ö ü ß', p.text)

    def test_text_encoding_zvt_7bit(self):
        packet = '06d10d0054657374207b207c207d207e'

        with enter_context(character_set=ZVT_7BIT_CHARACTER_SET):
            p = parse_represented_data(packet)

        self.assertEqual('Test ä ö ü ß', p.text)

    def test_invalid_bitmap_parse_error_includes_full_hex_data(self):
        packet = """
            162820101000696451029148310400210345102914931040002314510291333104059481845102913231040021034510291161631040
            4158674510291173104018051084510291183104003574510291193104006216318557
        """

        with self.assertRaises(ParseError) as context:
            parse_represented_data(packet)

        self.assertTrue('Invalid bitmap 0x10 in data: 16282010100069645102914831040021034510291493104000231451029133310'
                        + '40594818451029132310400210345102911616310404158674510291173104018051084510291183104003574510'
                        + '291193104006216318557' in str(context.exception))


if __name__ == '__main__':
    main()

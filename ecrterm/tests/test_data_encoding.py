# -*- coding: utf-8 -*-

"""
Test for Data Encoding

All Packets tested here should be those which are SENT to the PT mainly.
you can see the incoming tests in parsing.

Lets test if packets are encoded right

Unter docs/examples finden sich dateien mit logs.
Diese Tests sehen nach ob unsere Klassen dieselben binären daten
erzeugen.
"""

from unittest import TestCase, main

from ecrterm.conv import toHexString
from ecrterm.packets.apdu import APDU
from ecrterm.packets.base_packets import (
    Authorisation, Diagnosis, DisplayText, Initialisation, PacketReceived,
    PacketReceivedError, PrintLine, Registration, ResetTerminal, StatusEnquiry, ReadCard)
from ecrterm.transmission.signals import ACK, NAK, DLE, ETX, STX
from ecrterm.transmission.transport_serial import SerialMessage


def list_of_bytes(apdu: APDU):
    data = apdu.serialize()
    message = SerialMessage(data)
    # Note: this is the encoding used for serial transport. @see SerialTransport.send_message()
    return toHexString(list(bytearray(bytes([DLE, STX]) + data.replace(bytes([DLE]), bytes([DLE, DLE]))
                                      + bytes([DLE, ETX, message.crc_l, message.crc_h]))))


class TestCaseDataEncoding(TestCase):
    maxDiff = None

    def setUp(self):
        pass

    def test_nakack(self):
        self.assertEqual(chr(NAK), chr(0x15))
        self.assertEqual(chr(ACK), chr(0x6))

    def test_Anmeldung(self):
        # Register Packet std.
        data_expected = '10 02 06 00 06 12 34 56 BA 09 78 10 03 24 C3'
        pk = Registration('123456', 0xBA, 978)
        self.assertEqual(data_expected, list_of_bytes(pk))

    def test_Initialisierung(self):
        # Initialization Std.
        data_expected = '10 02 06 93 03 12 34 56 10 03 CA A4'
        pk = Initialisation('123456')
        self.assertEqual(data_expected, list_of_bytes(pk))

    def test_Zahlung_eccash(self):
        # Authorisation
        data_expected = \
            '10 02 06 01 0A 04 00 00 00 01 10 10 00 49 09 78 10 03 F2 FF'
        pk = Authorisation(amount=11000,
                           currency_code=978)
        self.assertEqual(data_expected, list_of_bytes(pk))

    def test_packet_diagnosis(self):
        # Diagnosis
        data_expected = '10 02 06 70 00 10 03 D9 F9'
        pk = Diagnosis()
        self.assertEqual(data_expected, list_of_bytes(pk))

    def test_packet_printline(self):
        # Print Line Packet
        data_expected = \
            '10 02 06 D1 19 00 47 65 73 61 6D 74 20 20 20 20 20 20 30 20 20 ' \
            '20 20 20 20 20 30 2C 30 30 10 03 B5 AB'
        pk = PrintLine(
            text='Gesamt      0       0,00', attribute=0)
        self.assertEqual(data_expected, list_of_bytes(pk))

    def test_packet_received(self):
        data_expected = '10 02 80 00 00 10 03 F5 1F'
        pk = PacketReceived()
        self.assertEqual(data_expected, list_of_bytes(pk))

    def test_packet_received_error(self):
        data_expected = '10 02 84 9C 00 10 03 C3 41'
        pk = PacketReceivedError()
        pk.cmd_instr = 0x9c
        self.assertEqual(data_expected, list_of_bytes(pk))

    def test_packet_resetterminal(self):
        data_expected = '10 02 06 18 00 10 03 56 3A'
        pk = ResetTerminal()
        self.assertEqual(data_expected, list_of_bytes(pk))

    def test_packet_showtext(self):
        data_expected = \
            '10 02 06 E0 25 F1 F1 F6 46 41 48 52 45 52 4E 55 4D 4D 45 52 20 ' \
            '20 20 20 F2 F1 F5 45 49 4E 47 45 42 45 4E 20 55 4E 44 20 4F 4B ' \
            '10 03 DE CD'
        lines = ['FAHRERNUMMER    ', 'EINGEBEN UND OK']
        # FAHRERNUMMER:
        # F1 F1 F6 46 41 48 52 45 52 4E 55 4D 4D 45 52 20 20 20 20
        # EINGEBEN UND OK:
        # F2 F1 F5 45 49 4E 47 45 42 45 4E 20 55 4E 44 20 4F 4B
        pk = DisplayText(
            # display_duration=0,
            line1=lines[0],
            # beeps=5,
            line2=lines[1],
        )
        self.assertEqual(data_expected, list_of_bytes(pk))

    def test_packet_statusenquiry(self):
        data_expected = '10 02 05 01 03 12 34 56 10 03 E0 43'
        pk = StatusEnquiry('123456')
        self.assertEqual(data_expected, list_of_bytes(pk))


class TestReadCard(TestCase):
    def test_read_card_1(self):
        a = ReadCard(timeout=0x01, tlv={0x1F15: b'\xD0'})
        self.assertEqual(bytearray.fromhex('06c0070106041f1501d0'), a.serialize())


if __name__ == '__main__':
    main()

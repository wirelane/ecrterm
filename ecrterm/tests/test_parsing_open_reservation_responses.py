from unittest import TestCase, main

from ecrterm.ecr import parse_represented_data
from ecrterm.packets.base_packets import Abort


class TestParsingOpenReservationResponses(TestCase):

    def test_open_reservations_response_no_receipt_numbers(self):
        # receipt number FF FF means no open reservations
        packet = '06 1E 04 B8 87 FF FF'

        parsed = parse_represented_data(packet)
        self.assertIsInstance(parsed, Abort)
        self.assertEqual(parsed.get_receipt_numbers(), [])

    def test_open_reservations_response_receipt(self):
        packet = '06 1E 04 B8 87 01 23'

        parsed = parse_represented_data(packet)
        self.assertIsInstance(parsed, Abort)
        self.assertEqual(parsed.get_receipt_numbers(), ['0123'])

    def test_open_reservations_response_tlv(self):
        packet = '06 1E 0E B8 06 11 23 09 08 02 01 23 08 02 45 67'

        parsed = parse_represented_data(packet)
        self.assertIsInstance(parsed, Abort)
        receipt_numbers = parsed.get_receipt_numbers()

        self.assertEqual(['0123', '4567'], receipt_numbers)

    def test_open_reservations_response_receipt_and_tlv(self):
        packet = '06 1E 11 B8 87 01 23 06 11 23 09 08 02 45 67 08 02 78 90'

        parsed = parse_represented_data(packet)
        self.assertIsInstance(parsed, Abort)
        receipt_numbers = parsed.get_receipt_numbers()

        self.assertEqual(['0123', '4567', '7890'], receipt_numbers)


if __name__ == '__main__':
    main()

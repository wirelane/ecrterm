from unittest import TestCase, main

from ecrterm.ecr import parse_represented_data
from ecrterm.packets.base_packets import Abort


class TestParsingAbort(TestCase):

    def test_abort_by_external_command(self):
        packet = '061e2e6c062b1f1605ff000014411f1720416262727563682064757263682065787465726e6573204b6f6d6d616e646f21'
        parsed = parse_represented_data(packet)

        print(parsed)

        self.assertIsInstance(parsed, Abort)
        self.assertEqual(108, parsed.result_code)
        tlv = parsed.get('tlv')
        self.assertIsNotNone(tlv)
        extended_error_code = tlv.get_value('extended_error_code')
        self.assertEqual('ff00001441', extended_error_code)


if __name__ == '__main__':
    main()

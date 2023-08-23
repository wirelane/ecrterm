from unittest import TestCase, main

from ecrterm.common import TERMINAL_STATUS_CODES
from ecrterm.ecr import parse_represented_data
from ecrterm.packets.base_packets import Completion


class TestParsingCompletion(TestCase):

    def test_completion(self):
        packet = """
            060f89f0f4f04745522d4150502d76322e302e393b635230322e30312e30312d30302e30392d322d323b4343323600065b1f44045250
            0245e4431f400a6356454e4420626f782b1f41284745522d4150502d76322e302e393b635230322e30312e30312d30302e30392d322d
            323b434332361f420411e930ec1f430100340d1f0e04202306221f0f03085556
        """

        parsed = parse_represented_data(packet)
        self.assertIsInstance(parsed, Completion)
        self.assertEqual(parsed.get_serial_number(), '11e930ec')
        self.assertEqual(parsed.sw_version, 'GER-APP-v2.0.9;cR02.01.01-00.09-2-2;CC26')
        self.assertEqual(TERMINAL_STATUS_CODES.get(parsed.terminal_status), 'PT ready')


if __name__ == '__main__':
    main()

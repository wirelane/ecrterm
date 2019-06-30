from unittest import TestCase, main

from ecrterm.packets.types import *


class TestTypes(TestCase):
    def test_enum_repr(self):
        self.assertEqual('CurrencyCode.EUR', repr(CurrencyCode(978)))


if __name__ == '__main__':
    main()

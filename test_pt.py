#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Example script to demonstrate a payment process.
"""
from ecrterm.ecr import ECR
from ecrterm.packets.types import ConfigByte


def printer(lines_of_text):
    for line in lines_of_text:
        print(line)


if __name__ == '__main__':
    e = ECR(device='socket://192.168.1.163:20007', password='111111')
    # reenable logging:
    e.transport.slog = ecr_log
    print(e.detect_pt())
    if e.detect_pt():
        e.register(config_byte=ConfigByte.DEFAULT)

        e.wait_for_status()
        status = e.status()
        if status:
            print('Status code of PT is %s' % status)
            # laut doku sollte 0x9c bedeuten, ein tagesabschluss erfolgt
            # bis jetzt unklar ob er es von selbst ausführt.

            if status == 0x9c:
                print('End Of Day')
                e.end_of_day()
                # last_printout() would work too:
                printer(e.daylog)
            else:
                print('Unknown Status Code: %s' % status)
                # status == 0xDC for ReadCard (06 C0) -> Karte drin.
                # 0x9c karte draussen.

        if e.payment(amount_cent=1):
            printer(e.last_printout())
            e.wait_for_status()
            e.show_text(
                lines=['Auf Wiedersehen!', ' ', 'Zahlung erfolgt'], beeps=1)
        else:
            e.wait_for_status()
            e.show_text(
                lines=['Auf Wiedersehen!', ' ', 'Vorgang abgebrochen'],
                beeps=2)

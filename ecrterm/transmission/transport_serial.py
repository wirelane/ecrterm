"""
Serial Layer

The Serial Layer is a transport used for

@author g4b
"""

import serial
import logging
from functools import partial
from typing import Tuple
from ecrterm.common import Transport
from ecrterm.conv import toHexString
from ecrterm.crc import crc_xmodem16
from ecrterm.exceptions import (
    TransportLayerException, TransportTimeoutException)
from ecrterm.transmission.signals import (
    ACK, DLE, ETX, NAK, STX, TIMEOUT_T1, TIMEOUT_T2)
from time import time

SERIAL_DEBUG = False

logger = logging.getLogger('ecrterm.transport.serial')


class SerialMessage(object):
    """
    Converts a Packet into a serial message by serializing the packet
    and inserting it into the final Serial Packet
    CRC and double-DLEs included.
    """
    apdu: bytes = None

    def __init__(self, data=None):
        self.apdu = data

    def _get_crc(self):
        data = self.apdu + bytes([ETX])
        try:
            return crc_xmodem16(data)
        except Exception:
            print(self.apdu)
            raise

    def _get_crc_l(self):
        return self._get_crc() & 0x00FF

    def _get_crc_h(self):
        return (self._get_crc() & 0xFF00) >> 8
    crc_l = property(_get_crc_l)
    crc_h = property(_get_crc_h)

    def crc(self):
        return bytes([self.crc_l, self.crc_h])

    def __repr__(self):
        return 'SerialMessage (APDU: %s, CRC-L: %s CRC-H: %s)' % (
            toHexString(self.apdu),
            hex(self.crc_l),
            hex(self.crc_h))


class SerialTransport(Transport):
    SerialCls = serial.Serial
    insert_delays = True

    def __init__(self, device):
        self.device = device
        self.connection = None

    def connect(self, timeout=30):
        ser = self.SerialCls(
            port=self.device, baudrate=9600, parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_TWO, bytesize=serial.EIGHTBITS,
            timeout=timeout,  # set a timeout value, None for waiting forever
            xonxoff=0,  # disable software flow control
            rtscts=0,  # disable RTS/CTS flow control
        )
        if not ser.isOpen():
            ser.open()
        # 8< got that from somwhere, not sure what it does:
        ser.setRTS(1)
        ser.setDTR(1)
        ser.flushInput()
        ser.flushOutput()
        # >8
        if ser.isOpen():
            self.connection = ser
            return True
        return False

    def close(self):
        if self.connection:
            self.connection.close()

    def reset(self):
        if self.connection:
            self.connection.flushInput()
            self.connection.flushOutput()

    def write(self, data: bytes):
        if len(data) < 3:
            logger.debug('>> %s', data.hex())
        self.connection.write(data)

    def write_ack(self):
        # writes an ack.
        self.write(bytes([ACK]))

    def write_nak(self):
        self.write(bytes([NAK]))

    def read(self, timeout=TIMEOUT_T2) -> Tuple[bytes, bytes]:
        """Reads a message packet. any errors are raised directly."""
        # if in 5 seconds no message appears, we respond with a nak and
        # raise an error.
        self.connection.timeout = timeout

        header = self.connection.read(2)

        if len(header) < 2:
            raise TransportLayerException('Reading Header Timeout')
        if header != bytes([DLE, STX]):
            raise TransportLayerException('Header Error: %s' % header.hex())

        data = bytearray()

        crc = None

        # read until DLE, ETX is reached.
        dle = False

        # timeout to T1 after header.
        self.connection.timeout = TIMEOUT_T1

        while not crc:
            inb = self.connection.read(1)  # read a byte.
            if inb is None or len(inb) == 0:
                # timeout
                raise TransportLayerException('Timeout T1 reading stream.')
            b = inb[0]
            if b == ETX and dle:
                # dle was set, and this is ETX, so we are at the end.
                # we read the CRC now.
                crc = self.connection.read(2)
                if not crc or len(crc) < 2:
                    raise TransportLayerException('Timeout T1 reading CRC')
                # and break
                break
            elif b == DLE:
                if not dle:
                    # this is a dle
                    dle = True
                    continue
                else:
                    # this is the second dle. we take it.
                    dle = False
            elif dle:
                # dle was set, but we got no etx here.
                # this seems to be an error.
                raise TransportLayerException('DLE without sense detected.')
            # we add this byte to our apdu.
            data.append(b)
        logger.debug("<< %s", data.hex())
        return crc, data

    def read_message(self, timeout=TIMEOUT_T2) -> Tuple[bool, bytes]:
        try:
            crc, data = self.read(timeout)
            msg = SerialMessage(data)
        except Exception:
            # this is a NAK - re-raise for further investigation.
            self.write_nak()
            raise
        # test the CRC:
        if msg.crc() == crc:
            self.write_ack()
            return True, data
        else:
            # self.write_nak()
            return False, data

    def receive(self, timeout=TIMEOUT_T2, *args, **kwargs) -> Tuple[bool, bytes]:
        crc_ok = False
        data = None
        # receive a message up to three times.
        for i in range(3):
            crc_ok, data = self.read_message(timeout)
            if not crc_ok:
                logger.log(logging.WARNING if i <= 2 else logging.ERROR, 'CRC Checksum Error, retry %s' % i)
            else:
                break
        if not crc_ok:
            # Message Fail!?
            self.write_nak()
            return False, data
        # otherwise
        return True, data

    def send_message(self, data: bytes, tries=0, no_wait=False):
        """
        sends input with write
        returns output with read.
        if skip_read is True, it only returns true, you have to read
        yourself.
        """
        if data:
            message = SerialMessage(data)
            self.write(bytes([DLE, STX]) + data.replace(bytes([DLE]), bytes([DLE, DLE])) + bytes([DLE, ETX, message.crc_l, message.crc_h]))
            acknowledge = b''
            ts_start = time()
            while len(acknowledge) < 1:
                acknowledge = self.connection.read(1)
                # With ingenico devices, acknowledge is often empty.
                # Just retrying seems to help.
                if time() - ts_start > 1:
                    break
            logger.debug('<< %s', acknowledge.hex())
            # if nak, we retry, if ack, we read, if other, we raise.
            if acknowledge[0] == ACK:
                # everything alright.
                if no_wait:
                    return True
                return self.receive()
            elif acknowledge[0] == NAK:
                # not everything allright.
                # if tries < 3:
                #    return self.send_message(message, tries + 1, no_answer)
                # else:
                raise TransportLayerException('Could not send message')
            elif not len(acknowledge) < 1:
                raise TransportTimeoutException('No Answer, Possible Timeout')
            else:
                raise TransportLayerException(
                    'Unknown Acknowledgment Byte %s' % acknowledge.hex())

    def send(self, data: bytes, tries=0, no_wait=False):
        """Automatically converts an apdu into a message."""
        return self.send_message(data, tries, no_wait)


# self test
if __name__ == '__main__':
    c = SerialTransport('/dev/ttyUSB0')
    from ecrterm.packets.base_packets import Registration
    if c.connect():
        print('connected to usb0')
    else:
        exit()
    # register
    answer = c.send_serial(Registration())
    print(answer)

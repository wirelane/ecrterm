from binascii import hexlify
from socket import SHUT_RDWR, create_connection
from socket import timeout as exc_timeout
from struct import unpack
from typing import Tuple

from ecrterm.common import Transport, noop
from ecrterm.conv import bs2hl
from ecrterm.packets.apdu import APDUPacket
from ecrterm.transmission.signals import TIMEOUT_T2


def hexformat(data: bytes) -> str:
    """Return a prettified binary data."""
    hexlified = str(hexlify(data), 'ascii')
    splitted = ':'.join(
        hexlified[i:i + 2] for i in range(0, len(hexlified), 2))
    return repr(bytes(data)) + ' -> ' + splitted


class SocketTransport(Transport):
    """Transport for TCP/IP."""
    insert_delays = False
    slog = noop

    def __init__(self, uri: str, debug: bool=False):
        """Setup the IP and Port."""
        prefix, ip, port = uri.split(':')
        self.port = int(port)
        self.ip = ip[2:]  # Trim '//' from the beginning
        self._debug = debug

    def connect(self, timeout: int=30) -> bool:
        """
        Connect to the TCP socket. Return `True` on successful
        connection, `False` on an unsuccessful one.
        """
        try:
            self.sock = create_connection(
                address=(self.ip, self.port), timeout=timeout)
            return True
        except (ConnectionError, exc_timeout) as exc:
            return False

    def send(self, apdu, tries: int=0, no_wait: bool=False):
        """Send data."""
        to_send = bytes(apdu.to_list())
        self.slog(data=bs2hl(binstring=to_send), incoming=False)
        total_sent = 0
        msglen = len(to_send)
        while total_sent < msglen:
            sent = self.sock.send(to_send[total_sent:])
            if self._debug:
                print('sent', sent, 'bytes of', hexformat(
                    data=to_send[total_sent:]))
            if sent == 0:
                raise RuntimeError('Socket connection broken.')
            total_sent += sent
        if no_wait:
            return True
        return self.receive()

    def _receive_bytes(self, length: int) -> bytes:
        """Receive and return a fixed amount of bytes."""
        recv_bytes = 0
        result = b''
        if self._debug:
            print('waiting for', length, 'bytes')
        while recv_bytes < length:
            chunk = self.sock.recv(length - recv_bytes)
            if self._debug:
                print('received', len(chunk), 'bytes:', hexformat(data=chunk))
            if chunk == b'':
                raise RuntimeError('Socket connection broken.')
            result += chunk
            recv_bytes += len(chunk)
        return result

    def _receive_length(self) -> Tuple[bytes, int]:
        """
        Receive the 4 bytes on the socket which indicates the message
        length, and return the packed and the `int` converted length.
        """
        data = self._receive_bytes(length=3)
        length = data[2]
        if length != 0xff:
            return data, length
        # Need to get 2 more bytes
        length = self._receive_bytes(length=2)
        data += length
        return data, unpack('<H', length)[0]

    def _receive(self, timeout=TIMEOUT_T2) -> bytes:
        """
        Receive the response from the terminal and return is as `bytes`.
        """
        self.sock.settimeout(timeout)
        data, length = self._receive_length()
        if not length:  # Length is 0
            return data
        new_data = self._receive_bytes(length=length)
        return data + new_data

    def receive(
            self, timeout=None, *args, **kwargs) -> Tuple[bool, APDUPacket]:
        """
        Receive data, return success status and ADPUPacket instance.
        """
        data = self._receive()
        self.slog(data=bs2hl(binstring=data), incoming=True)
        return True, APDUPacket.parse(blob=data)

    def close(self):
        """Shutdown and close the connection."""
        self.sock.shutdown(SHUT_RDWR)
        self.sock.close()

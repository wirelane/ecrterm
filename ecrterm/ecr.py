"""
Maybe create a small console program which allows us to:
- send packets directly
- receive them directly
- see the binary data of the packet
- see the representation of the packet
- ability for incoming and outgoing
"""
import logging
import string
from time import sleep

from ecrterm.common import TERMINAL_STATUS_CODES
from ecrterm.conv import toBytes
from ecrterm.exceptions import (
    TransportConnectionFailed, TransportLayerException)
from ecrterm.packets.base_packets import (
    Authorisation, CloseCardSession, Completion, DisplayText, EndOfDay, Initialisation, Packet,
    PrintLine, ReadCard, Registration, ReservationBookTotal, ReservationPartialReversal,
    ReservationRequest, ResetTerminal, SetTerminalID, StatusEnquiry, StatusInformation, WriteFiles,
    OpenReservationsEnquiry)
from ecrterm.packets.types import (ConfigByte, CurrencyCode)
from ecrterm.transmission._transmission import Transmission
from ecrterm.transmission.signals import ACK, DLE, ETX, NAK, STX, TRANSMIT_OK
from ecrterm.transmission.transport_serial import SerialTransport
from ecrterm.transmission.transport_socket import SocketTransport
from ecrterm.utils import detect_pt_serial, is_stringlike

logger = logging.getLogger('ecrterm.ecr')


def dismantle_serial_packet(data):
    apdu = []
    crc = None
    i = 2
    header = data[:i]
    # header = bs2hl(header)
    # test if there was a transmission:
    if header == []:
        raise TransportLayerException('No Header')
    # test our header to be valid
    if header != [DLE, STX]:
        raise TransportLayerException('Header Error: %s' % header)
    # read until DLE, ETX is reached.
    dle = False
    while not crc and i < len(data):
        b = data[i]  # read a byte.
        if b == ETX and dle:
            # dle was set, and this is ETX, so we are at the end.
            # we read the CRC now.
            crc = [data[i + 1], data[i + 2]]
            # and break
            continue
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
            raise Exception('DLE without sense detected.')
        # we add this byte to our apdu.
        apdu += [b]
        i += 1
    return crc, apdu


def parse_represented_data(data):
    # represented data
    if is_stringlike(data):
        # we assume a bytelist like 10 02 03....
        data = toBytes(data)
    # first of all, serial data starts with 10 02, so everything
    # starting with 10 will be assumed as "serial packet" and first "demantled"
    if data[0] == DLE:
        try:
            crc, data = dismantle_serial_packet(data)
        except TransportLayerException:
            pass
    elif data[0] == ACK:
        if len(data) == 1:
            return 'ACK'
    elif data[0] == NAK:
        if len(data) == 1:
            return 'NAK'
    # then we create the packet and return that.
    p = Packet.parse(data)
    return p


class ECR(object):
    transmitter = None
    transport = None
    version = None
    terminal_id = None
    MAX_TEXT_LINES = 4
    _state_registered = None
    _state_connected = None
    _status = None

    def __init__(self, device='/dev/ttyUSB0', password='123456'):
        """
        Initializes an ECR object and connects to the serial device
        given. Fails if Serial Device is not found.

        You can access the Device on low level as the `transport`.
        You can access the Protocol Handler on low level as
        `transmission`.

        Pass `socket://` prefixed IP address and port for TCP/IP
        transport: `socket://192.168.1.163:20007`
        """
        if device.startswith('/') or device.startswith('COM'):
            self.transport = SerialTransport(device)
        elif device.startswith('socket://'):
            self.transport = SocketTransport(uri=device)

        self.daylog = []
        self.daylog_template = ''
        self.history = []
        self.terminal_id = None
        # we save some states here.
        self._state_registered = False
        self._state_connected = False
        self.password = password

        if self.transport.connect():
            self.transmitter = Transmission(self.transport)
            self._state_connected = True
        else:
            raise TransportConnectionFailed('ECR could not connect.')

    def __get_last(self):
        if self.transmitter is not None:
            return self.transmitter.last

    # !: Last is a short access for transmitter.last if possible.
    last = property(__get_last)

    def register(self, config_byte, **kwargs):
        """
        registers this ECR at the PT, locking menus
        for real world conditions.
        """
        kwargs = dict(kwargs)
        if self.password:
            kwargs['password'] = self.password
        if config_byte is not None:
            kwargs['config_byte'] = config_byte

        ret = self.transmit(Registration(**kwargs))

        if ret == TRANSMIT_OK:
            # get the terminal-id if its there.
            for inc, packet in self.transmitter.last_history:
                if inc and isinstance(packet, Completion):
                    self.terminal_id = packet.as_dict().get('tid', '00' * 4)
            # remember this.
            self._state_registered = True
        return ret

    def register_unlocked(self):
        """
        registers to the PT, not locking the master menu on it.
        do not use in production environment.
        """
        return self.register(password=self.password,
                             config_byte=ConfigByte.DEFAULT & ~ConfigByte.ECR_CONTROLS_ADMIN)

    def _end_of_day_info_packet(self, history=None):
        """
        Search for an end of day packet status information in the last
        packets, can also search in any history list.
        """
        # helper function to scan for end of day information via packets.
        status_info = None
        plist = history or self.transmitter.last_history
        for inc, packet in plist:
            if inc:  # incoming
                if isinstance(packet, StatusInformation):
                    status_info = packet
        if status_info:
            eod_info = status_info.get_end_of_day_information()
            # we add terminal id to it.
            eod_info['terminal-id'] = self.terminal_id
            return eod_info

    def end_of_day(self, listener=None):
        """
        - sends an end of day packet.
        - saves the log in `daylog`

        @returns: 0 if there were no protocol errors.
        """
        # old_histoire = self.transmitter.history
        # self.transmitter.history = []
        # we send the packet
        packet = EndOfDay(self.password)
        if listener:
            packet.register_response_listener(listener)
        result = self.transmit(packet=packet)
        # now save the log
        self.daylog = self.last_printout()

        if not self.daylog:
            # there seems to be no printout. we search in statusinformation.
            eod_info = self._end_of_day_info_packet()
            try:
                self.daylog = (self.daylog_template % eod_info).split('\n')
            except Exception:
                logger.exception("Error in daylog template")
        return result

    def last_printout(self):
        """
        returns all printlines from the last history.
        @todo: TextBlock support - if some printer decides to do it that
        way.
        """
        printout = []
        for entry in self.transmitter.last_history:
            inc, packet = entry
            if inc and isinstance(packet, PrintLine):
                printout += [packet.fixed_values['text']]
        return printout

    def payment(self, amount_cent=50, listener=None):
        """
        executes a payment in amount of cents.
        @returns: True, if payment went through, or False if it was
        canceled.
        throws exceptions.
        """
        packet = Authorisation(
            amount=amount_cent,  # in cents.
            currency_code=CurrencyCode.EUR,  # euro, only one that works, can be skipped.
            tlv=[],
        )
        if listener:
            packet.register_response_listener(listener)
        code = self.transmit(packet=packet)

        if code == 0:
            # now check if the packet actually got what it wanted.
            if self.transmitter.last.completion:
                if isinstance(self.transmitter.last.completion, Completion):
                    return True
            else:
                return False
        else:
            # @todo: remove this.
            logger.error("transmit error?")
        return False

    def restart(self):
        """Restarts/resets the PT."""
        self._state_registered = False
        return self.transmit(ResetTerminal())

    def reset(self):
        """
        - resets transport: @see ecrterm.transmission.Transport.reset()
        - restarts pt: @see self.restart()
        """
        self.transport.reset()
        if self.transport.insert_delays:
            sleep(1)
        ret = self.restart()
        if self.transport.insert_delays:
            sleep(1)
        return ret

    def show_text(self, lines=None, duration=5, beeps=0):
        """
        displays a text on the PT screen for duration of seconds.

        @param lines: a list of strings.
        @param duration: 0 for forever.
        @param beeps: make some noise.

        @note: any error due to wrong strings given are not checked.
        """
        lines = lines or ['Hello world!', ]
        kw = {'display_duration': duration}
        if beeps:
            kw['beeps'] = int(beeps)
        i = 1
        for line in lines[:self.MAX_TEXT_LINES]:
            kw['line%s' % i] = line
            i += 1
        return self.transmit(DisplayText(**kw))

    def status(self):
        """
        executes a status enquiry. also sets self.version if not set.
        success:
        returns 0 if successful, and status is unchanged.
        returns an int status code if status has changed.
        errors:
        returns None if no status was transmitted.
        returns False on transmit errors.

        to check for the status code:
            common.TERMINAL_STATUS_CODES.get( status, 'Unknown' )
        """
        errors = self.transmit(StatusEnquiry(self.password))
        if not errors:
            if isinstance(self.last.completion, Completion):
                # try to get version
                if not self.version:
                    self.version = self.last.completion.get('sw_version', None)

                self._status = self.last.completion.terminal_status
                return self.last.completion.status_byte
            # no completion means some error.
        return False

    def transmit(self, packet):
        """
        transmits a packet, therefore introducing the protocol cascade.
        rewrite this function if you want packets be routed anywhere
        since the whole ECR Object uses this function to transmit.

        use `last` property to access last packet transmitted.
        """
        if self.transport.insert_delays:
            # we actually make a small sleep, allowing better flow.
            sleep(0.2)
        transmission = self.transmitter.transmit(packet)
        return transmission

    def request_reservation(self, amount_cent=50, timeout=10, tlv=[], listener=None):
        """
        executes a reservation request in amount of cents.
        @returns: True, if reservation went through, or False if it was canceled.
        throws exceptions.
        """
        packet = ReservationRequest(
            amount=amount_cent,  # in cents.
            currency_code=CurrencyCode.EUR,  # euro, only one that works, can be skipped.
            timeout=timeout,
            tlv=tlv,
        )

        return self._send_packet(packet, listener)

    def reverse_reservation(self, receipt_no, amount_cent=50, tlv=[], listener=None):
        """
        executes a reservation reversal for receipt with unused amount in cents.
        @returns: True, if reversal went through, or False if it was canceled.
        throws exceptions.
        """
        packet = ReservationPartialReversal(
            receipt=receipt_no,
            amount=amount_cent,
            currency_code=CurrencyCode.EUR,
            tlv=tlv,
        )

        return self._send_packet(packet, listener)

    def get_open_reservations(self, listener=None):
        """
        Fetches the receipt-number of the first pre-authorisation not yet reversed by a partial-reversal / book total.
        Note: The receipt-number is returned in an Abort package (06 1E).
        If no open reservation exist in the PT, ‘FFFF’ is returned as receipt-number.

        Instead of a single receipt-number the PT can also transmit a receipt-number list as a TLV-container.
        However, for this the ECR must have sent a BMP 06 in the triggering command or in the registration.

        @returns: True on success, False on failure
        """
        packet = OpenReservationsEnquiry()

        return self._send_packet(packet, listener)

    def book_reservation(self, receipt_no, amount_cent=50, tlv=[], listener=None):
        """
        executes a reservation booking for receipt with used amount in cents.
        @returns: True, if booking went through, or False if it was canceled.
        throws exceptions.
        """
        packet = ReservationBookTotal(
            receipt=receipt_no,
            amount=amount_cent,
            currency_code=CurrencyCode.EUR,
            tlv=tlv,
        )

        return self._send_packet(packet, listener)

    def set_terminal_id(self, terminal_id=None, listener=None):
        """
        Set the terminal id for the PT, needs an initialize afterwards.
        @returns: True, if configuration went through, or False if it was invalid.
        throws exceptions.
        """
        packet = SetTerminalID(
            password=self.password,
            tid=terminal_id,
        )

        return self._send_packet(packet, listener)

    def initialize(self, listener=None):
        """
        Initialize the PT, needed after configuration change.
        @returns: True, if initialize went through, or False if it was invalid.
        throws exceptions.
        """
        packet = Initialisation(
            password=self.password
        )

        return self._send_packet(packet, listener)

    def _send_packet(self, packet, listener=None):
        """
        Generic method to send packets and check for completion status.
        @returns: True, if packet went through, or False if it failed.
        throws exceptions.
        """
        if listener:
            packet.register_response_listener(listener)
        code = self.transmit(packet=packet)

        if code == 0:
            # now check if the packet actually got what it wanted.
            if self.transmitter.last.completion:
                if isinstance(self.transmitter.last.completion, Completion):
                    return True
            else:
                return False
        else:
            # @todo: remove this.
            logger.error("transmit error?")
        return False

    # dev functions.
    #########################################################################

    def wait_for_status(self):
        """
        waits until self.status() returns 0 (or False/None)
        polls the PT in 2 second intervals.
        this function prints out the status string.
        use it as code example.
        """
        status = self.status()
        while status:
            print(TERMINAL_STATUS_CODES.get(status, 'Unknown Status'))
            if self.transport.insert_delays:
                sleep(2)
            status = self.status()

    def listen(self, timeout=15):
        """Dev function to simply listen."""
        ok, message = None, None
        while True:
            try:
                ok, message = self.transport.receive(timeout)
                if ok and message:
                    return message
            except:
                logger.exception()
                continue
            print('-mark-')

    def write_files(self, password, files):
        return self.transmit(WriteFiles(password=password, files=files))

    def detect_pt(self):
        # note: this only executes utils.detect_pt with the local ecrterm.
        if type(self.transport) is SerialTransport:
            return detect_pt_serial(timeout=2, silent=False, ecr=self)
        return True

    def parse_str(self, s):
        return parse_represented_data(s)

    def read_card(self, timeout=1, read_card_args={}):
        args = dict(read_card_args)
        args.setdefault('timeout', timeout)
        return self.transmit(ReadCard(**args))

    def close_card(self):
        return self.transmit(CloseCardSession())

    def get_human_readable_status(self) -> string:
        return TERMINAL_STATUS_CODES.get(self._status, 'Unknown Status')


if __name__ == '__main__':
    logging.basicConfig(level=9, filename='./terminallog.txt', filemode='aw')
    logging.info('-MARK-')
    e = ECR()
    # e.end_of_day()
    e.show_text(['Hello world!', 'Testing', 'myself.'], 5, 0)
    print('preparing for payment.')
    print(e.payment(50))

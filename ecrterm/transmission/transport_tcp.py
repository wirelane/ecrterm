from socket import create_connection

from ecrterm.common import Transport


class TcpTransport(Transport):
    """Transport for TCP/IP."""
    is_tcp = True

    def __init__(self, uri: str):
        """Setup the IP and Port."""
        prefix, ip, port = uri.split(':')
        self.port = int(port)
        self.ip = ip[2:]

    def connect(self, timeout: int=30):
        """Connect to the TCP socket."""
        self.sock = create_connection(
            address=(self.ip, self.port), timeout=timeout)

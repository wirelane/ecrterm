from unittest import TestCase

from unittest_data_provider import data_provider

from ecrterm.transmission.transport_socket import SocketTransport


class TestSocketTransport(TestCase):
    uris = lambda: (
        ('socket://hostname:123', 'hostname', 123),
        ('socket://192.168.123.12:456', '192.168.123.12', 456),
        ('socket://2001:0db8:85a3:0000:0000:8a2e:0370:7334:789', '2001:0db8:85a3:0000:0000:8a2e:0370:7334', 789),
    )

    @data_provider(uris)
    def test_uri_parsing(self, uri, ip, socket):
        socket_transport = SocketTransport(uri=uri)
        self.assertEqual(ip, socket_transport.ip)
        self.assertEqual(socket, socket_transport.port)

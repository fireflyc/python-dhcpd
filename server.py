# encoding=utf8
__author__ = 'fireflyc'

import socket
import select
import logging

import packet


LOGGER = logging.getLogger(__name__)


class DHCPServer:
    def __init__(self, listen_address="0.0.0.0", listen_port=67, timeout=60):
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.select_timeout = timeout
        self.socket_list = []
        self._bind(listen_address, listen_port)

    def _bind(self, listen_address, listen_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # udp
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # broadcast
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.listen_address, self.listen_port))
        self.socket_list.append(sock)

    def start(self):
        while True:
            r, w, e = select.select(self.socket_list, [], [], self.select_timeout)
            for sock in r:
                data, address = sock.recvfrom(packet.DHCPFormatSize)
                self.handle(sock, address, data)

    def handle(self, sock, address, data):
        request_packet = packet.DHCPacket(data)
        if request_packet.is_discover_packet():
            self.on_discover_packet(sock, address, packet)
        elif request_packet.is_request_packet():
            self.on_request_packet(sock, address, packet)
        elif request_packet.is_decline_packet():
            self.on_decline_packet(sock, address, packet)
        elif request_packet.is_release_packet():
            self.on_release_packet(sock, address, packet)
        else:
            self.on_unknow_packet(sock, address, packet)

    def on_discover_packet(self, sock, address, packet):
        sock.sendto(packet.build_offer())

    def on_request_packet(self, sock, address, packet):
        sock.sendto(packet.build_ack())

    def on_unknow_packet(self, sock, address, packet):
        pass

    def on_decline_packet(self, sock, address, packet):
        pass

    def on_release_packet(self, sock, address, packet):
        pass
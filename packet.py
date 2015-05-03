# encoding=utf8

__author__ = 'fireflyc'

import logging
import struct
import copy
import socket

import util


LOGGER = logging.getLogger(__name__)
DHCPFormat = "!4bIHH4s4s4s4s16s64s128s4s"  # dbcp标准数据包最后一个options对于服务器来说只有一个字节52
DHCPFormatSize = struct.calcsize(DHCPFormat)
(OP, HTYPE, HLEN, HOPS, XID, SECS, FLAGS, CIADDR, YIADDR, SIADDR, GIADDR, CHADDR, SNAME, FILE, VEND) = range(15)

REQUEST = 1
REPLY = 2

DHCP_OPTIONS = {0: 'Byte padding',
                1: 'Subnet mask',
                2: 'Time offset',
                3: 'Routers',
                4: 'Time servers',
                5: 'Name servers',
                6: 'Domain name servers',
                7: 'Log servers',
                8: 'Cookie servers',
                9: 'Line printer servers',
                10: 'Impress servers',
                11: 'Resource location servers',
                12: 'Host Name',  # + PXE extensions
                13: 'Boot file size',
                14: 'Dump file',
                15: 'Domain name',
                16: 'Swap server',
                17: 'Root path',
                18: 'Extensions path',
                # --- IP layer / host ---
                19: 'IP forwarding',
                20: 'Source routing',
                21: 'Policy filter',
                22: 'Maximum datagram reassembly size',
                23: 'Default IP TTL',
                24: 'Path MTU aging timeout',
                25: 'Path MTU plateau table',
                # --- IP Layer / interface ---
                26: 'Interface MTU',
                27: 'All subnets local',
                28: 'Broadcast address',
                29: 'Perform mask discovery',
                30: 'Mask supplier',
                31: 'Perform router discovery',
                32: 'Router solicitation address',
                33: 'Static route',
                # --- Link layer ---
                34: 'Trailer encapsulation',
                35: 'ARP cache timeout',
                36: 'Ethernet encaspulation',
                # --- TCP ---
                37: 'TCP default TTL',
                38: 'TCP keepalive interval',
                39: 'TCP keepalive garbage',
                # --- Application & Services ---
                40: 'Network Information Service domain',
                41: 'Network Information servers',
                42: 'Network Time Protocol servers',
                43: 'Vendor specific',
                44: 'NetBIOS over TCP/IP name server',
                45: 'NetBIOS over TCP/IP datagram server',
                46: 'NetBIOS over TCP/IP node type',
                47: 'NetBIOS over TCP/IP scope',
                48: 'X Window system font server',
                49: 'X Window system display manager',
                50: 'Requested IP address',
                51: 'IP address lease time',
                52: 'Option overload',
                53: 'DHCP message',
                54: 'Server ID',
                55: 'Param request list',
                56: 'Error message',
                57: 'Message length',
                58: 'Renewal time',
                59: 'Rebinding time',
                60: 'Class ID',
                61: 'GUID',
                64: 'Network Information Service+ domain',
                65: 'Network Information Service+ servers',
                66: 'TFTP server name',
                67: 'Bootfile name',
                68: 'Mobile IP home agent',
                69: 'Simple Mail Transport Protocol servers',
                70: 'Post Office Protocol servers',
                71: 'Network News Transport Protocol servers',
                72: 'World Wide Web servers',
                73: 'Finger servers',
                74: 'Internet Relay Chat server',
                93: 'System architecture',
                94: 'Network type',
                97: 'UUID',
                255: 'End of DHCP options'}

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8
DHCP_RENEWING = 100

OPTIONS_IP_MASK = 1  # Subnet Mask
OPTIONS_IP_GATEWAY = 3  # Router
OPTIONS_IP_DNS = 6  # DNS Server
OPTIONS_IP_LEASE_TIME = 51
OPTIONS_MESSAGE_TYPE = 53
OPTIONS_SERVER = 54
OPTIONS_END = 255


class DHCPacket:
    def __init__(self, data):
        self.data = data
        self.buf = None

        self.message_type = None
        self.mac_address = None
        self.mac_address_str = None

        self.parse()

    def parse(self):
        if len(self.data) < DHCPFormatSize:
            LOGGER.error("Cannot be a DHCP or BOOTP request - too small!")
        tail = self.data[DHCPFormatSize:]
        self.buf = list(struct.unpack(DHCPFormat, self.data[:DHCPFormatSize]))
        if self.buf[OP] != REQUEST:
            LOGGER.warn("Not a request")
            return
        options = self.parse_options(tail)
        if options is None:
            LOGGER.warn("Error in option parsing, ignore request")
            return
        try:
            self.message_type = ord(options[OPTIONS_MESSAGE_TYPE][0])
        except KeyError:
            self.message_type = None

        self.mac_address = self.buf[CHADDR][:6]
        self.mac_address_str = '-'.join(['%02X' % ord(x) for x in self.mac_address])

    def parse_options(self, tail):
        dhcp_tags = {}
        while tail:
            tag = ord(tail[0])
            # padding
            if tag == 0:
                continue
            if tag == 0xff:
                return dhcp_tags
            length = ord(tail[1])
            (value,) = struct.unpack('!%ss' % length, tail[2:2 + length])
            tail = tail[2 + length:]
            try:
                option = DHCP_OPTIONS[tag]
                LOGGER.debug(" option %d: '%s', size:%d %s" % \
                             (tag, option, length, util.hexline(value)))
            except KeyError:
                LOGGER.error("unknown option %d, size:%d %s:", tag, length, util.hexline(value))
                return None
            dhcp_tags[tag] = value

    def build_offer(self, ip_address, mask, gateway, dns):
        offer_packet = copy.copy(self.buf)
        offer_packet[OP] = REPLY
        offer_packet[YIADDR] = socket.inet_aton(ip_address)
        offer_packet[SECS] = 0
        offer_packet[FLAGS] = 0
        pkt = struct.pack(DHCPFormat, *offer_packet)
        pkt += struct.pack('!BBB', OPTIONS_MESSAGE_TYPE, 1, DHCP_OFFER)
        pkt += struct.pack('!BB4s', OPTIONS_IP_MASK, 4, mask)
        pkt += struct.pack('!BB4s', OPTIONS_IP_GATEWAY, 4, gateway)
        pkt += struct.pack('!BB4s', OPTIONS_IP_DNS, 4, dns)
        pkt += struct.pack('!BBI', OPTIONS_IP_LEASE_TIME, 4, 24 * 3600)  # 1 days
        pkt += struct.pack('!BB', OPTIONS_END, 0)
        return pkt

    def build_ack(self, ip_address, mask, gateway, dns):
        ack_packet = copy.copy(self.buf)
        ack_packet[OP] = REPLY
        ack_packet[YIADDR] = socket.inet_aton(ip_address)
        ack_packet[SECS] = 0
        ack_packet[FLAGS] = 0
        pkt = struct.pack(DHCPFormat, *ack_packet)
        pkt += struct.pack('!BBB', OPTIONS_MESSAGE_TYPE, 1, DHCP_ACK)
        pkt += struct.pack('!BB4s', OPTIONS_IP_MASK, 4, mask)
        pkt += struct.pack('!BB4s', OPTIONS_IP_GATEWAY, 4, gateway)
        pkt += struct.pack('!BB4s', OPTIONS_IP_DNS, 4, dns)
        pkt += struct.pack('!BBI', OPTIONS_IP_LEASE_TIME, 4, 24 * 3600)  # 1 days
        pkt += struct.pack('!BB', OPTIONS_END, 0)
        return pkt

    def is_discover_packet(self):
        return self.message_type == DHCP_DISCOVER

    def is_request_packet(self):
        return self.message_type == DHCP_REQUEST

    def is_decline_packet(self):
        return self.message_type == DHCP_DECLINE

    def is_release_packet(self):
        return self.message_type == DHCP_RELEASE

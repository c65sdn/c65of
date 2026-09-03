"""ARP (RFC 826) header."""

# Copyright (C) 2026 The c65sdn Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from c65of.lib.type_desc import IPv4Addr, MacAddr
from c65of.packet import ether_types as ether
from c65of.packet import ethernet
from c65of.packet.packet_base import PacketBase

ARP_HW_TYPE_ETHERNET = 1

# arp operation codes
ARP_REQUEST = 1
ARP_REPLY = 2
ARP_REV_REQUEST = 3
ARP_REV_REPLY = 4


class arp(PacketBase):  # pylint: disable=invalid-name
    """ARP header. Hardware and protocol addresses are held as text.

    ``hwtype``/``proto`` name the address families, ``hlen``/``plen`` their
    byte lengths, ``opcode`` the operation. The sender and target addresses
    follow as ``src_mac``/``src_ip`` and ``dst_mac``/``dst_ip``.
    """

    _FMT = "HHBBH6s4s6s4s"
    _FIELDS = "hwtype proto hlen plen opcode src_mac src_ip dst_mac dst_ip"
    _CODERS = {
        "src_mac": MacAddr,
        "src_ip": IPv4Addr,
        "dst_mac": MacAddr,
        "dst_ip": IPv4Addr,
    }
    _DEFAULTS = {
        "hwtype": ARP_HW_TYPE_ETHERNET,
        "proto": ether.ETH_TYPE_IP,
        "hlen": 6,
        "plen": 4,
        "opcode": ARP_REQUEST,
        "src_mac": "ff:ff:ff:ff:ff:ff",
        "src_ip": "0.0.0.0",
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "dst_ip": "0.0.0.0",
    }
    _TYPE = {"ascii": ("src_mac", "src_ip", "dst_mac", "dst_ip")}
    _MIN_LEN = 28


def arp_ip(opcode, src_mac, src_ip, dst_mac, dst_ip):
    """IPv4 ARP over ethernet: :class:`arp` with the address families filled in."""
    return arp(
        ARP_HW_TYPE_ETHERNET,
        ether.ETH_TYPE_IP,
        6,
        4,
        opcode,
        src_mac,
        src_ip,
        dst_mac,
        dst_ip,
    )


ethernet.ethernet.register_packet_type(arp, ether.ETH_TYPE_ARP)

"""Checksums shared by the IP protocol headers."""

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

import struct

from c65of.lib import addrconv

_IPV4_PSEUDO_HEADER_PACK_STR = "!4s4sxBH"
_IPV6_PSEUDO_HEADER_PACK_STR = "!16s16sI3xB"
_MODX = 4102


def carry_around_add(a, b):
    """Ones-complement addition of two 16 bit values."""
    total = a + b
    return (total & 0xFFFF) + (total >> 16)


def checksum(data):
    """Internet checksum (RFC 1071) over ``data``."""
    data = bytes(data)
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack_from("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return ~total & 0xFFFF


def checksum_ip(ipvx, length, payload):
    """Checksum over the IPv4/IPv6 pseudo header of ``ipvx`` plus ``payload``.

    ``length`` is the upper layer packet length. See RFC 793 3.1 and RFC 2460 8.1.
    """
    if ipvx.version == 4:
        header = struct.pack(
            _IPV4_PSEUDO_HEADER_PACK_STR,
            addrconv.ipv4.text_to_bin(ipvx.src),
            addrconv.ipv4.text_to_bin(ipvx.dst),
            ipvx.proto,
            length,
        )
    elif ipvx.version == 6:
        header = struct.pack(
            _IPV6_PSEUDO_HEADER_PACK_STR,
            addrconv.ipv6.text_to_bin(ipvx.src),
            addrconv.ipv6.text_to_bin(ipvx.dst),
            length,
            ipvx.nxt,
        )
    else:
        raise ValueError("Unknown IP version %d" % ipvx.version)
    return checksum(header + payload)


def fletcher_checksum(data, offset):
    """Fletcher checksum (RFC 1008), written into ``data`` at ``offset``."""
    c0 = c1 = 0
    pos = 0
    length = len(data)
    data = bytearray(data)
    data[offset : offset + 2] = [0] * 2
    while pos < length:
        tlen = min(length - pos, _MODX)
        for octet in data[pos : pos + tlen]:
            c0 += octet
            c1 += c0
        c0 %= 255
        c1 %= 255
        pos += tlen
    x = ((length - offset - 1) * c0 - c1) % 255
    if x <= 0:
        x += 255
    y = 510 - c0 - x
    if y > 255:
        y -= 255
    data[offset] = x
    data[offset + 1] = y
    return (x << 8) | (y & 0xFF)

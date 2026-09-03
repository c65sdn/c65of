"""MAC and IP text/binary conversion, on the stdlib.

``text_to_bin`` accepts a plain address, or (for IP) ``addr/mask`` in either
prefix-length or dotted-mask form, in which case it returns a
``(addr, netmask)`` pair of packed values -- the shape OXM masked matches
expect.
"""

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

import ipaddress
import socket


class _IPConverter:
    """Packed/text conversion for one IP version."""

    __slots__ = ("family", "size", "_net", "_addr")

    def __init__(self, version):
        self.family = socket.AF_INET if version == 4 else socket.AF_INET6
        self.size = 4 if version == 4 else 16
        self._net = ipaddress.IPv4Network if version == 4 else ipaddress.IPv6Network
        self._addr = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address

    def text_to_bin(self, text):
        """Packed address, or ``(addr, netmask)`` for a ``addr/mask`` text."""
        try:
            return socket.inet_pton(self.family, text)
        except OSError:
            net = self._net(text, strict=False)
            return net.network_address.packed, net.netmask.packed

    def bin_to_text(self, packed):
        """Canonical text for a packed address."""
        return socket.inet_ntop(self.family, bytes(packed))

    def text_to_int(self, text):
        """Integer value of an address."""
        return int(self._addr(text))


class _MacConverter:
    """Packed/text conversion for 48 bit MAC addresses."""

    size = 6

    @staticmethod
    def text_to_bin(text):
        """Packed form of a ``xx:xx:xx:xx:xx:xx`` address."""
        octets = text.split(":")
        if len(octets) != 6:
            raise ValueError("not a MAC address: %r" % (text,))
        return bytes(int(octet, 16) for octet in octets)

    @staticmethod
    def bin_to_text(packed):
        """Lower case colon separated text for a packed address."""
        if len(packed) != 6:
            raise ValueError("not a packed MAC address: %r" % (packed,))
        return bytes(packed).hex(":")


ipv4 = _IPConverter(4)
ipv6 = _IPConverter(6)
mac = _MacConverter()

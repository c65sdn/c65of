"""Ethernet II header."""

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

from c65of.lib.type_desc import MacAddr
from c65of.packet import ether_types as ether
from c65of.packet.packet_base import ETHERTYPES, PacketBase


class ethernet(PacketBase):  # pylint: disable=invalid-name
    """Ethernet II header. Addresses are held as text."""

    _FMT = "6s6sH"
    _FIELDS = "dst src ethertype"
    _CODERS = {"dst": MacAddr, "src": MacAddr}
    _DEFAULTS = {
        "dst": "ff:ff:ff:ff:ff:ff",
        "src": "00:00:00:00:00:00",
        "ethertype": ether.ETH_TYPE_IP,
    }
    _TYPE = {"ascii": ("dst", "src")}
    _NEXT_FIELD = "ethertype"
    _TYPES = ETHERTYPES
    _MIN_LEN = 14
    _MIN_PAYLOAD_LEN = 46

    @classmethod
    def get_packet_type(cls, type_):
        """Class for an ethertype.

        A Length/Type value of 1500 or less is an 802.3 length, and what
        follows is LLC rather than a typed protocol.
        """
        return cls._TYPES.get(max(type_, ether.ETH_TYPE_IEEE802_3))

    def serialize(self, payload, prev):
        """Pack the header, padding a short payload to the 46 byte minimum."""
        pad_len = self._MIN_PAYLOAD_LEN - len(payload)
        if pad_len > 0:
            payload.extend(b"\x00" * pad_len)
        return self.pack_fixed()

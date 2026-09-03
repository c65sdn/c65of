"""IEEE 802.1Q and 802.1ad VLAN tags."""

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

from c65of.packet import ether_types as ether
from c65of.packet.packet_base import ETHERTYPES, PacketBase

VLAN_PCP_SHIFT = 13
VLAN_CFI_SHIFT = 12
VLAN_VID_MASK = (1 << 12) - 1


class _vlan(PacketBase):  # pylint: disable=invalid-name
    """A VLAN tag: priority, drop-eligible bit and VLAN id in one 16 bit TCI."""

    _FMT = "HH"
    _FIELDS = "tci ethertype"
    _EXTRA = "pcp cfi vid"
    _DEFAULTS = {"ethertype": ether.ETH_TYPE_IP}
    _TYPES = ETHERTYPES
    _MIN_LEN = 4

    def __init__(self, pcp=0, cfi=0, vid=0, ethertype=ether.ETH_TYPE_IP):
        self.pcp = pcp
        self.cfi = cfi
        self.vid = vid
        self.ethertype = ethertype

    def iter_attrs(self):
        yield "pcp", self.pcp
        yield "cfi", self.cfi
        yield "vid", self.vid
        yield "ethertype", self.ethertype

    @classmethod
    def parser(cls, buf):
        tci, ethertype = cls._STRUCT.unpack_from(buf)
        header = cls(
            tci >> VLAN_PCP_SHIFT,
            (tci >> VLAN_CFI_SHIFT) & 1,
            tci & VLAN_VID_MASK,
            ethertype,
        )
        return header, cls.get_packet_type(ethertype), buf[cls._MIN_LEN :]

    def serialize(self, payload, prev):
        tci = self.pcp << VLAN_PCP_SHIFT | self.cfi << VLAN_CFI_SHIFT | self.vid
        return self._STRUCT.pack(tci, self.ethertype)


class vlan(_vlan):  # pylint: disable=invalid-name
    """802.1Q customer VLAN tag."""


class svlan(_vlan):  # pylint: disable=invalid-name
    """802.1ad service VLAN tag."""

"""IPv4 (RFC 791) header."""

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

from c65of.lib.type_desc import IPv4Addr
from c65of.packet import ether_types as ether
from c65of.packet import ethernet
from c65of.packet.packet_base import IP_PROTOS, PacketBase
from c65of.packet.packet_utils import checksum

IPV4_ADDRESS_PACK_STR = "!I"
IPV4_ADDRESS_LEN = struct.calcsize(IPV4_ADDRESS_PACK_STR)
IPV4_PSEUDO_HEADER_PACK_STR = "!4s4s2xHH"

_OFFSET_MASK = (1 << 13) - 1
_FLAGS_SHIFT = 13
_CSUM_OFFSET = 10


class ipv4(PacketBase):  # pylint: disable=invalid-name
    """IPv4 header. Addresses are held as text, options as raw bytes.

    ``version`` and ``header_length`` share the first octet, ``flags`` and
    ``offset`` the fragment field. A ``total_length`` of 0 and ``csum`` are
    computed when encoding. ``option`` is the whole options area, or None.

    Decoding walks into the upper layer protocol even for a fragment.
    """

    _FMT = "BBHHHBBH4s4s"
    _FIELDS = "version tos total_length identification flags ttl proto csum src dst"
    _EXTRA = "header_length offset option"
    _CODERS = {"src": IPv4Addr, "dst": IPv4Addr}
    _TYPE = {"ascii": ("src", "dst")}
    _TYPES = IP_PROTOS
    _MIN_LEN = 20

    def __init__(
        self,
        version=4,
        header_length=5,
        tos=0,
        total_length=0,
        identification=0,
        flags=0,
        offset=0,
        ttl=255,
        proto=0,
        csum=0,
        src="10.0.0.1",
        dst="10.0.0.2",
        option=None,
    ):
        self.version = version
        self.header_length = header_length
        self.tos = tos
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.offset = offset
        self.ttl = ttl
        self.proto = proto
        self.csum = csum
        self.src = src
        self.dst = dst
        self.option = option

    def __len__(self):
        return self.header_length * 4

    @classmethod
    def parser(cls, buf):
        fields = cls.unpack_fixed(buf)
        version = fields["version"]
        fields["version"] = version >> 4
        header_length = fields["header_length"] = version & 0xF
        flags = fields["flags"]
        fields["flags"] = flags >> _FLAGS_SHIFT
        fields["offset"] = flags & _OFFSET_MASK
        length = header_length * 4
        fields["option"] = buf[cls._MIN_LEN : length] if length > cls._MIN_LEN else None
        msg = cls.from_fields(fields)
        rest = buf[length : fields["total_length"]]
        return msg, cls.get_packet_type(msg.proto), rest

    def serialize(self, payload, prev):
        length = len(self)
        hdr = bytearray(length)
        if self.total_length == 0:
            self.total_length = self.header_length * 4 + len(payload)
        self._STRUCT.pack_into(
            hdr,
            0,
            self.version << 4 | self.header_length,
            self.tos,
            self.total_length,
            self.identification,
            self.flags << _FLAGS_SHIFT | self.offset,
            self.ttl,
            self.proto,
            0,
            IPv4Addr.from_user(self.src),
            IPv4Addr.from_user(self.dst),
        )
        if self.option:
            assert (length - self._MIN_LEN) >= len(self.option)
            hdr[self._MIN_LEN : self._MIN_LEN + len(self.option)] = self.option
        self.csum = checksum(hdr)
        struct.pack_into("!H", hdr, _CSUM_OFFSET, self.csum)
        return hdr


ethernet.ethernet.register_packet_type(ipv4, ether.ETH_TYPE_IP)

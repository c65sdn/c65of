"""ICMP (RFC 792) header and its message bodies."""

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

# The codec compiles __init__ from the declarations below, so pylint sees no
# assignment for the attributes those constructors and the parsers set.
# pylint: disable=no-member,attribute-defined-outside-init
# pylint: disable=access-member-before-definition

import struct

from c65of.codec import Codec
from c65of.packet import in_proto as inet
from c65of.packet import ipv4
from c65of.packet.packet_base import PacketBase
from c65of.packet.packet_utils import checksum

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_SRC_QUENCH = 4
ICMP_REDIRECT = 5
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

ICMP_ECHO_REPLY_CODE = 0
ICMP_HOST_UNREACH_CODE = 1
ICMP_PORT_UNREACH_CODE = 3
ICMP_TTL_EXPIRED_CODE = 0


class icmp(PacketBase):  # pylint: disable=invalid-name
    """ICMP header.

    ``data`` is the message body: raw bytes, or the :class:`echo`,
    :class:`dest_unreach` or :class:`TimeExceeded` object registered for
    ``type``. A ``csum`` of 0 is computed when encoding.
    """

    _FMT = "BBH"
    _FIELDS = "type code csum"
    _EXTRA = "data"
    _DEFAULTS = {"type": ICMP_ECHO_REQUEST, "data": b""}
    _MIN_LEN = 4
    _ICMP_TYPES = {}

    @staticmethod
    def register_icmp_type(*args):
        """Class decorator recording a body class under each ICMP type."""

        def _register_icmp_type(cls):
            for type_ in args:
                icmp._ICMP_TYPES[type_] = cls
            return cls

        return _register_icmp_type

    def __len__(self):
        return self._MIN_LEN + len(self.data)

    @classmethod
    def parser(cls, buf):
        msg = cls.from_fields(cls.unpack_fixed(buf))
        offset = cls._MIN_LEN
        if len(buf) > offset:
            cls_ = cls._ICMP_TYPES.get(msg.type)
            msg.data = cls_.parser(buf, offset) if cls_ else buf[offset:]
        return msg, None, None

    def serialize(self, payload, prev):
        hdr = bytearray(self.pack_fixed())
        if self.data:
            if self.type in icmp._ICMP_TYPES:
                assert isinstance(self.data, _ICMPv4Payload)
                hdr += self.data.serialize()
            else:
                hdr += self.data
        else:
            self.data = echo()
            hdr += self.data.serialize()
        if self.csum == 0:
            self.csum = checksum(hdr)
            struct.pack_into("!H", hdr, 2, self.csum)
        return hdr


class _ICMPv4Payload(Codec):
    """Base for an ICMPv4 message body."""

    _ABSTRACT = True

    def __len__(self):
        return self._SIZE + (0 if self.data is None else len(self.data))

    @classmethod
    def parser(cls, buf, offset):
        """Decode a body at ``offset``, taking the remaining bytes as data."""
        msg = cls.from_fields(cls.unpack_fixed(buf, offset))
        offset += cls._SIZE
        if len(buf) > offset:
            msg.data = buf[offset:]
        return msg

    def serialize(self):
        """Encode this body, appending ``data`` when set."""
        hdr = bytearray(self.pack_fixed())
        if self.data is not None:
            hdr += self.data
        return hdr


@icmp.register_icmp_type(ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST)
class echo(_ICMPv4Payload):  # pylint: disable=invalid-name
    """Echo and Echo Reply body: identifier, sequence number and data."""

    _FMT = "HH"
    _FIELDS = "id seq"
    _EXTRA = "data"


@icmp.register_icmp_type(ICMP_DEST_UNREACH)
class dest_unreach(_ICMPv4Payload):  # pylint: disable=invalid-name
    """Destination Unreachable body.

    ``data_len`` is the RFC 4884 data length; ``mtu`` the RFC 1191 next hop
    MTU, required when the ICMP code is 4.
    """

    _FMT = "xBH"
    _FIELDS = "data_len mtu"
    _EXTRA = "data"

    def _init_hook(self):
        if not 0 <= self.data_len <= 255:
            raise ValueError("Specified data length (%d) is invalid." % self.data_len)


@icmp.register_icmp_type(ICMP_TIME_EXCEEDED)
class TimeExceeded(_ICMPv4Payload):
    """Time Exceeded body: the RFC 4884 data length and the original datagram."""

    _FMT = "xBxx"
    _FIELDS = "data_len"
    _EXTRA = "data"

    def _init_hook(self):
        if not 0 <= self.data_len <= 255:
            raise ValueError("Specified data length (%d) is invalid." % self.data_len)


ipv4.ipv4.register_packet_type(icmp, inet.IPPROTO_ICMP)

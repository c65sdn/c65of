"""ICMPv6 (RFC 2463) header and its message bodies."""

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

# Class and attribute names are the wire names os-ken exposes.
# pylint: disable=invalid-name

import struct

from c65of.codec import Codec
from c65of.lib import addrconv
from c65of.lib.type_desc import IPv6Addr, MacAddr
from c65of.packet import in_proto as inet
from c65of.packet import packet_utils
from c65of.packet.ipv6 import ipv6
from c65of.packet.packet_base import PacketBase

ICMPV6_DST_UNREACH = 1
ICMPV6_PACKET_TOO_BIG = 2
ICMPV6_TIME_EXCEEDED = 3
ICMPV6_PARAM_PROB = 4

ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129
MLD_LISTENER_QUERY = 130
MLD_LISTENER_REPOR = 131
MLD_LISTENER_DONE = 132
MLDV2_LISTENER_REPORT = 143

# RFC 2292 names for the MLD types above.
ICMPV6_MEMBERSHIP_QUERY = 130
ICMPV6_MEMBERSHIP_REPORT = 131
ICMPV6_MEMBERSHIP_REDUCTION = 132

ND_ROUTER_SOLICIT = 133
ND_ROUTER_ADVERT = 134
ND_NEIGHBOR_SOLICIT = 135
ND_NEIGHBOR_ADVERT = 136
ND_REDIREC = 137

ICMPV6_ROUTER_RENUMBERING = 138

ICMPV6_WRUREQUEST = 139
ICMPV6_WRUREPLY = 140
ICMPV6_FQDN_QUERY = 139
ICMPV6_FQDN_REPLY = 140
ICMPV6_NI_QUERY = 139
ICMPV6_NI_REPLY = 140

ICMPV6_MAXTYPE = 201

# Neighbour discovery options, RFC 4861.
ND_OPTION_SLA = 1
ND_OPTION_TLA = 2
ND_OPTION_PI = 3
ND_OPTION_RH = 4
ND_OPTION_MTU = 5

MODE_IS_INCLUDE = 1
MODE_IS_EXCLUDE = 2
CHANGE_TO_INCLUDE_MODE = 3
CHANGE_TO_EXCLUDE_MODE = 4
ALLOW_NEW_SOURCES = 5
BLOCK_OLD_SOURCES = 6

_ND_OPTION_LA_STRUCT = struct.Struct("!BB6s")
_ND_OPTION_PI_STRUCT = struct.Struct("!BBBBIII16s")
_ADDRESS_STRUCT = struct.Struct("!16s")


class icmpv6(PacketBase):
    """ICMPv6 header.

    ``data`` is the message body: a :class:`_ICMPv6Payload` when the type has
    a registered class, otherwise raw bytes. A ``csum`` of 0 is computed over
    the IPv6 pseudo header of ``prev`` at serialize time.
    """

    _FMT = "BBH"
    _FIELDS = "type code csum"
    _EXTRA = "data"
    _DEFAULTS = {"data": b""}
    _MIN_LEN = 4
    _ICMPV6_TYPES = {}

    @staticmethod
    def register_icmpv6_type(*args):
        """Class decorator registering a message body for each of ``args``."""

        def _register_icmpv6_type(cls):
            for type_ in args:
                icmpv6._ICMPV6_TYPES[type_] = cls
            return cls

        return _register_icmpv6_type

    @classmethod
    def parser(cls, buf):
        fields = cls.unpack_fixed(buf)
        msg = cls.from_fields(fields)
        offset = cls._MIN_LEN
        if len(buf) > offset:
            cls_ = cls._ICMPV6_TYPES.get(fields["type"])
            msg.data = cls_.parser(buf, offset) if cls_ else buf[offset:]
        return msg, None, None

    def serialize(self, payload, prev):
        hdr = bytearray(self.pack_fixed())
        if self.data:
            if self.type in self._ICMPV6_TYPES:
                hdr += self.data.serialize()
            else:
                hdr += self.data
        if self.csum == 0:
            self.csum = packet_utils.checksum_ip(prev, len(hdr), hdr + payload)
            struct.pack_into("!H", hdr, 2, self.csum)
        return hdr

    def __len__(self):
        return self._MIN_LEN + len(self.data)


class _ICMPv6Payload(Codec):
    """Base for an ICMPv6 message body."""


class _nd_message(_ICMPv6Payload):
    """Base for the neighbour discovery messages, which carry ND options."""

    _ND_OPTION_TYPES = {}

    @classmethod
    def register_nd_option_type(cls, option_cls):
        """Class decorator registering an ND option this message accepts."""
        cls._ND_OPTION_TYPES[option_cls.option_type()] = option_cls
        return option_cls

    @classmethod
    def _parse_option(cls, buf, offset, bounded=False):
        """Decode the ND option at ``offset``, as raw bytes if unregistered."""
        type_, length = struct.unpack_from("!BB", buf, offset)
        if length == 0:
            raise struct.error("Invalid length: %d" % length)
        cls_ = cls._ND_OPTION_TYPES.get(type_)
        if cls_ is not None:
            return cls_.parser(buf, offset)
        return buf[offset : offset + length * 8] if bounded else buf[offset:]


def _option_bytes(option):
    """Wire form of an ND option, which may already be raw bytes."""
    return option.serialize() if isinstance(option, nd_option) else option


@icmpv6.register_icmpv6_type(ND_NEIGHBOR_SOLICIT, ND_NEIGHBOR_ADVERT)
class nd_neighbor(_nd_message):
    """Neighbor Solicitation and Neighbor Advertisement body (RFC 4861).

    ``res`` holds the R,S,O flags of an advertisement, or the 3 most
    significant bits of the reserved field of a solicitation.
    """

    _FMT = "I16s"
    _FIELDS = "res dst"
    _EXTRA = "option"
    _DEFAULTS = {"dst": "::", "option": None}
    _TYPE = {"ascii": ("dst",)}
    _ND_OPTION_TYPES = {}

    @classmethod
    def parser(cls, buf, offset):
        """Decode the body at ``offset`` of ``buf``."""
        res, dst = cls._STRUCT.unpack_from(buf, offset)
        offset += cls._SIZE
        option = cls._parse_option(buf, offset) if len(buf) > offset else None
        return cls(res >> 29, addrconv.ipv6.bin_to_text(dst), option)

    def serialize(self):
        """Encode the body and its option."""
        hdr = bytearray(
            self._STRUCT.pack(self.res << 29, addrconv.ipv6.text_to_bin(self.dst))
        )
        if self.option is not None:
            hdr.extend(_option_bytes(self.option))
        return bytes(hdr)

    def __len__(self):
        return self._SIZE + (0 if self.option is None else len(self.option))


@icmpv6.register_icmpv6_type(ND_ROUTER_SOLICIT)
class nd_router_solicit(_nd_message):
    """Router Solicitation body (RFC 4861). ``res`` must be zero."""

    _FMT = "I"
    _FIELDS = "res"
    _EXTRA = "option"
    _DEFAULTS = {"option": None}
    _ND_OPTION_TYPES = {}

    @classmethod
    def parser(cls, buf, offset):
        """Decode the body at ``offset`` of ``buf``."""
        (res,) = cls._STRUCT.unpack_from(buf, offset)
        offset += cls._SIZE
        option = cls._parse_option(buf, offset) if len(buf) > offset else None
        return cls(res, option)

    def serialize(self):
        """Encode the body and its option."""
        hdr = bytearray(self.pack_fixed())
        if self.option is not None:
            hdr.extend(_option_bytes(self.option))
        return bytes(hdr)

    def __len__(self):
        return self._SIZE + (0 if self.option is None else len(self.option))


@icmpv6.register_icmpv6_type(ND_ROUTER_ADVERT)
class nd_router_advert(_nd_message):
    """Router Advertisement body (RFC 4861). ``res`` holds the M,O flags."""

    _FMT = "BBHII"
    _FIELDS = "ch_l res rou_l rea_t ret_t"
    _EXTRA = "options"
    _ND_OPTION_TYPES = {}

    def _init_hook(self):
        self.options = self.options or []

    @classmethod
    def parser(cls, buf, offset):
        """Decode the body and every option that follows it."""
        ch_l, res, rou_l, rea_t, ret_t = cls._STRUCT.unpack_from(buf, offset)
        offset += cls._SIZE
        options = []
        while len(buf) > offset:
            option = cls._parse_option(buf, offset, bounded=True)
            options.append(option)
            offset += len(option)
        return cls(ch_l, res >> 6, rou_l, rea_t, ret_t, options)

    def serialize(self):
        """Encode the body and its options."""
        hdr = bytearray(
            self._STRUCT.pack(
                self.ch_l, self.res << 6, self.rou_l, self.rea_t, self.ret_t
            )
        )
        for option in self.options:
            hdr.extend(_option_bytes(option))
        return bytes(hdr)

    def __len__(self):
        return self._SIZE + sum(len(option) for option in self.options)


class nd_option(Codec):
    """Base for a neighbour discovery option."""

    _MIN_LEN = 0

    @classmethod
    def option_type(cls):
        """The option type code."""
        raise NotImplementedError

    def __len__(self):
        return self._MIN_LEN


class nd_option_la(nd_option):
    """Base for the link-layer address options.

    ``hw_src`` holds the first 6 octets of the address and ``data`` the rest
    plus any padding the caller must supply for 8 octet alignment.
    """

    _FMT = "xB6s"
    _FIELDS = "length hw_src"
    _EXTRA = "data"
    _CODERS = {"hw_src": MacAddr}
    _DEFAULTS = {"hw_src": "00:00:00:00:00:00", "data": None}
    _TYPE = {"ascii": ("hw_src",)}
    _MIN_LEN = 8

    @classmethod
    def parser(cls, buf, offset):
        """Decode the option at ``offset`` of ``buf``."""
        msg = cls.from_fields(cls.unpack_fixed(buf, offset))
        offset += cls._SIZE
        if len(buf) > offset:
            msg.data = buf[offset:]
        return msg

    def serialize(self):
        """Encode the option, padding and sizing it when length is 0."""
        buf = bytearray(
            _ND_OPTION_LA_STRUCT.pack(
                self.option_type(), self.length, addrconv.mac.text_to_bin(self.hw_src)
            )
        )
        if self.data is not None:
            buf.extend(self.data)
        mod = len(buf) % 8
        if mod:
            buf.extend(bytearray(8 - mod))
        if self.length == 0:
            self.length = len(buf) // 8
            struct.pack_into("!B", buf, 1, self.length)
        return bytes(buf)

    def __len__(self):
        return self._MIN_LEN + (0 if self.data is None else len(self.data))


@nd_neighbor.register_nd_option_type
@nd_router_solicit.register_nd_option_type
@nd_router_advert.register_nd_option_type
class nd_option_sla(nd_option_la):
    """Source Link-Layer Address option (RFC 4861)."""

    @classmethod
    def option_type(cls):
        """The option type code."""
        return ND_OPTION_SLA


@nd_neighbor.register_nd_option_type
class nd_option_tla(nd_option_la):
    """Target Link-Layer Address option (RFC 4861)."""

    @classmethod
    def option_type(cls):
        """The option type code."""
        return ND_OPTION_TLA


@nd_router_advert.register_nd_option_type
class nd_option_pi(nd_option):
    """Prefix Information option (RFC 4861). ``res1`` holds the L,A,R flags."""

    _FMT = "xBBBIII16s"
    _FIELDS = "length pl res1 val_l pre_l res2 prefix"
    _CODERS = {"prefix": IPv6Addr}
    _DEFAULTS = {"prefix": "::"}
    _TYPE = {"ascii": ("prefix",)}
    _MIN_LEN = 32

    @classmethod
    def option_type(cls):
        """The option type code."""
        return ND_OPTION_PI

    @classmethod
    def parser(cls, buf, offset):
        """Decode the option at ``offset`` of ``buf``."""
        fields = cls.unpack_fixed(buf, offset)
        fields["res1"] >>= 5
        return cls.from_fields(fields)

    def serialize(self):
        """Encode the option, sizing it when length is 0."""
        hdr = bytearray(
            _ND_OPTION_PI_STRUCT.pack(
                self.option_type(),
                self.length,
                self.pl,
                self.res1 << 5,
                self.val_l,
                self.pre_l,
                self.res2,
                addrconv.ipv6.text_to_bin(self.prefix),
            )
        )
        if self.length == 0:
            self.length = len(hdr) // 8
            struct.pack_into("!B", hdr, 1, self.length)
        return bytes(hdr)


@nd_router_advert.register_nd_option_type
class nd_option_mtu(nd_option):
    """MTU option (RFC 4861)."""

    _EXTRA = "mtu"
    _DEFAULTS = {"mtu": 1500}
    _MIN_LEN = 8
    _LEN = 8
    _OPTION_LEN = 1

    def _init_hook(self):
        self.length = 0

    @classmethod
    def option_type(cls):
        """The option type code."""
        return ND_OPTION_MTU

    def iter_attrs(self):
        yield "length", self.length
        yield "mtu", self.mtu

    @classmethod
    def parser(cls, buf, offset):
        """Decode the option at ``offset`` of ``buf``."""
        (mtu,) = struct.unpack_from("!4xI", buf, offset)
        return cls(mtu)

    def serialize(self):
        """Encode the option."""
        return struct.pack("!BBHI", self.option_type(), self._OPTION_LEN, 0, self.mtu)


@icmpv6.register_icmpv6_type(ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST)
class echo(_ICMPv6Payload):
    """Echo Request and Echo Reply body."""

    _FMT = "HH"
    _FIELDS = "id seq"
    _EXTRA = "data"
    _DEFAULTS = {"data": None}

    @classmethod
    def parser(cls, buf, offset):
        """Decode the body at ``offset`` of ``buf``."""
        msg = cls.from_fields(cls.unpack_fixed(buf, offset))
        offset += cls._SIZE
        if len(buf) > offset:
            msg.data = buf[offset:]
        return msg

    def serialize(self):
        """Encode the body and its data."""
        hdr = bytearray(self.pack_fixed())
        if self.data is not None:
            hdr += bytearray(self.data)
        return hdr

    def __len__(self):
        return self._SIZE + (0 if self.data is None else len(self.data))


@icmpv6.register_icmpv6_type(MLD_LISTENER_QUERY, MLD_LISTENER_REPOR, MLD_LISTENER_DONE)
class mld(_ICMPv6Payload):
    """MLD Listener Query, Report and Done body (RFC 2710).

    ``maxresp`` is the maximum response delay in milliseconds and is
    meaningful only in a query.
    """

    _FMT = "H2x16s"
    _FIELDS = "maxresp address"
    _CODERS = {"address": IPv6Addr}
    _DEFAULTS = {"address": "::"}
    _TYPE = {"ascii": ("address",)}

    @classmethod
    def parser(cls, buf, offset):
        """Decode the body, dispatching a longer one to MLDv2."""
        if cls._SIZE < len(buf[offset:]):
            return mldv2_query.parser(buf[offset:])
        return cls.from_fields(cls.unpack_fixed(buf, offset))

    def serialize(self):
        """Encode the body."""
        return self.pack_fixed()

    def __len__(self):
        return self._SIZE


class mldv2_query(mld):
    """MLDv2 Listener Query body (RFC 3810)."""

    _FMT = "H2x16sBBH"
    _FIELDS = "maxresp address s_qrv qqic num"
    _EXTRA = "s_flg qrv srcs"
    _HIDDEN = "s_qrv"
    _CODERS = {"address": IPv6Addr}
    _TYPE = {"ascii": ("address",), "asciilist": ("srcs",)}

    def __init__(
        self, maxresp=0, address="::", s_flg=0, qrv=2, qqic=0, num=0, srcs=None
    ):
        self.maxresp = maxresp
        self.address = address
        self.s_flg = s_flg
        self.qrv = qrv
        self.qqic = qqic
        self.num = num
        self.srcs = srcs or []

    @classmethod
    def parser(cls, buf, offset=0):
        """Decode the body at offset 0 of ``buf``."""
        maxresp, address, s_qrv, qqic, num = cls._STRUCT.unpack_from(buf, offset)
        offset += cls._SIZE
        srcs = []
        while len(buf) > offset and num > len(srcs):
            (src,) = _ADDRESS_STRUCT.unpack_from(buf, offset)
            srcs.append(addrconv.ipv6.bin_to_text(src))
            offset += 16
        return cls(
            maxresp,
            addrconv.ipv6.bin_to_text(address),
            (s_qrv >> 3) & 0b1,
            s_qrv & 0b111,
            qqic,
            num,
            srcs,
        )

    def serialize(self):
        """Encode the body, counting the sources when num is 0."""
        buf = bytearray(
            self._STRUCT.pack(
                self.maxresp,
                addrconv.ipv6.text_to_bin(self.address),
                self.s_flg << 3 | self.qrv,
                self.qqic,
                self.num,
            )
        )
        for src in self.srcs:
            buf.extend(_ADDRESS_STRUCT.pack(addrconv.ipv6.text_to_bin(src)))
        if self.num == 0:
            self.num = len(self.srcs)
            struct.pack_into("!H", buf, 22, self.num)
        return bytes(buf)

    def __len__(self):
        return self._SIZE + len(self.srcs) * 16


@icmpv6.register_icmpv6_type(MLDV2_LISTENER_REPORT)
class mldv2_report(mld):
    """MLDv2 Listener Report body (RFC 3810)."""

    _FMT = "2xH"
    _FIELDS = "record_num"
    _EXTRA = "records"
    _CODERS = {}
    _TYPE = {}

    def _init_hook(self):
        self.records = self.records or []

    @classmethod
    def parser(cls, buf, offset):
        """Decode the body and its group records."""
        (record_num,) = cls._STRUCT.unpack_from(buf, offset)
        offset += cls._SIZE
        records = []
        while len(buf) > offset and record_num > len(records):
            record = mldv2_report_group.parser(buf[offset:])
            records.append(record)
            offset += len(record)
        return cls(record_num, records)

    def serialize(self):
        """Encode the body, counting the records when record_num is 0."""
        buf = bytearray(self.pack_fixed())
        for record in self.records:
            buf.extend(record.serialize())
        if self.record_num == 0:
            self.record_num = len(self.records)
            struct.pack_into("!H", buf, 2, self.record_num)
        return bytes(buf)

    def __len__(self):
        return self._SIZE + sum(len(record) for record in self.records)


class mldv2_report_group(Codec):
    """One MLDv2 group record (RFC 3810). ``aux_len`` is in 32 bit words."""

    _FMT = "BBH16s"
    _FIELDS = "type aux_len num address"
    _EXTRA = "srcs aux"
    _CODERS = {"address": IPv6Addr}
    _DEFAULTS = {"address": "::"}
    _TYPE = {"ascii": ("address",), "asciilist": ("srcs",)}

    def _init_hook(self):
        self.srcs = self.srcs or []

    @classmethod
    def parser(cls, buf):
        """Decode one group record at offset 0 of ``buf``."""
        fields = cls.unpack_fixed(buf)
        offset = cls._SIZE
        srcs = []
        while len(buf) > offset and fields["num"] > len(srcs):
            (src,) = _ADDRESS_STRUCT.unpack_from(buf, offset)
            srcs.append(addrconv.ipv6.bin_to_text(src))
            offset += 16
        aux = None
        if fields["aux_len"]:
            (aux,) = struct.unpack_from("%ds" % (fields["aux_len"] * 4), buf, offset)
        return cls.from_fields(fields, srcs=srcs, aux=aux)

    def serialize(self):
        """Encode the record, sizing the source list and auxiliary data."""
        buf = bytearray(self.pack_fixed())
        for src in self.srcs:
            buf.extend(_ADDRESS_STRUCT.pack(addrconv.ipv6.text_to_bin(src)))
        if self.num == 0:
            self.num = len(self.srcs)
            struct.pack_into("!H", buf, 2, self.num)
        if self.aux is not None:
            mod = len(self.aux) % 4
            if mod:
                self.aux = bytes(self.aux) + bytes(4 - mod)
            buf.extend(self.aux)
            if self.aux_len == 0:
                self.aux_len = len(self.aux) // 4
                struct.pack_into("!B", buf, 1, self.aux_len)
        return bytes(buf)

    def __len__(self):
        return self._SIZE + len(self.srcs) * 16 + self.aux_len * 4


ipv6.register_packet_type(icmpv6, inet.IPPROTO_ICMPV6)

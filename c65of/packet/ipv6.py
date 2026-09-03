"""IPv6 (RFC 2460) header and its extension headers."""

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
from c65of.packet import ether_types as ether
from c65of.packet import in_proto as inet
from c65of.packet.ethernet import ethernet
from c65of.packet.packet_base import IP_PROTOS, PacketBase

IPV6_ADDRESS_PACK_STR = "!16s"
IPV6_ADDRESS_LEN = struct.calcsize(IPV6_ADDRESS_PACK_STR)
IPV6_PSEUDO_HEADER_PACK_STR = "!16s16s3xB"


class ipv6(PacketBase):
    """IPv6 header. Addresses are held as text, ``ext_hdrs`` as a list."""

    _FMT = "IHBB16s16s"
    _FIELDS = "v_tc_flow payload_length nxt hop_limit src dst"
    _MIN_LEN = 40
    _TYPES = IP_PROTOS
    _IPV6_EXT_HEADER_TYPE = {}
    _TYPE = {"ascii": ("src", "dst")}

    @staticmethod
    def register_header_type(type_):
        """Class decorator registering an extension header for ``type_``."""

        def _register_header_type(cls):
            ipv6._IPV6_EXT_HEADER_TYPE[type_] = cls
            return cls

        return _register_header_type

    def __init__(
        self,
        version=6,
        traffic_class=0,
        flow_label=0,
        payload_length=0,
        nxt=inet.IPPROTO_TCP,
        hop_limit=255,
        src="10::10",
        dst="20::20",
        ext_hdrs=None,
    ):
        self.version = version
        self.traffic_class = traffic_class
        self.flow_label = flow_label
        self.payload_length = payload_length
        self.nxt = nxt
        self.hop_limit = hop_limit
        self.src = src
        self.dst = dst
        self.ext_hdrs = ext_hdrs or []

    def iter_attrs(self):
        yield "version", self.version
        yield "traffic_class", self.traffic_class
        yield "flow_label", self.flow_label
        yield "payload_length", self.payload_length
        yield "nxt", self.nxt
        yield "hop_limit", self.hop_limit
        yield "src", self.src
        yield "dst", self.dst
        yield "ext_hdrs", self.ext_hdrs

    @classmethod
    def parser(cls, buf):
        v_tc_flow, payload_length, nxt, hop_limit, src, dst = cls._STRUCT.unpack_from(
            buf
        )
        offset = cls._MIN_LEN
        last = nxt
        ext_hdrs = []
        while True:
            cls_ = cls._IPV6_EXT_HEADER_TYPE.get(last)
            if not cls_:
                break
            hdr = cls_.parser(buf[offset:])
            ext_hdrs.append(hdr)
            offset += len(hdr)
            last = hdr.nxt
        msg = cls(
            v_tc_flow >> 28,
            (v_tc_flow >> 20) & 0xFF,
            v_tc_flow & 0xFFFFF,
            payload_length,
            nxt,
            hop_limit,
            addrconv.ipv6.bin_to_text(src),
            addrconv.ipv6.bin_to_text(dst),
            ext_hdrs,
        )
        return msg, cls.get_packet_type(last), buf[offset : offset + payload_length]

    def serialize(self, payload, prev):
        hdr = bytearray(self._MIN_LEN)
        v_tc_flow = self.version << 28 | self.traffic_class << 20 | self.flow_label
        self._STRUCT.pack_into(
            hdr,
            0,
            v_tc_flow,
            self.payload_length,
            self.nxt,
            self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst),
        )
        for ext_hdr in self.ext_hdrs:
            hdr.extend(ext_hdr.serialize())
        if self.payload_length == 0:
            self.payload_length = len(payload) + sum(
                len(ext_hdr) for ext_hdr in self.ext_hdrs
            )
            struct.pack_into("!H", hdr, 4, self.payload_length)
        return hdr

    def __len__(self):
        return self._MIN_LEN + sum(len(ext_hdr) for ext_hdr in self.ext_hdrs)


class header(Codec):
    """Base for the IPv6 extension headers.

    These never end the header chain, so ``parser`` returns just the header
    and ``serialize`` takes no payload.
    """

    _MIN_LEN = 0

    def __len__(self):
        return self._MIN_LEN


class option(Codec):
    """A TLV option of a hop-by-hop or destination options header.

    Type 0 is the one octet Pad1 option, which has neither a length nor a
    value; ``len`` records that as -1.
    """

    _FMT = "BB"
    _FIELDS = "type len"
    _EXTRA = "data"
    _DEFAULTS = {"len": -1, "data": None}

    @classmethod
    def parser(cls, buf):
        """Decode one option at offset 0 of ``buf``."""
        (type_,) = struct.unpack_from("!B", buf)
        if not type_:
            return cls(type_, -1, None)
        data = None
        type_, len_ = cls._STRUCT.unpack_from(buf)
        if len_:
            (data,) = struct.unpack_from("%ds" % len_, buf, cls._SIZE)
        return cls(type_, len_, data)

    def serialize(self):
        """Encode this option."""
        if not self.type:
            return struct.pack("!B", self.type)
        if not self.len:
            return self._STRUCT.pack(self.type, self.len)
        return struct.pack("!BB%ds" % self.len, self.type, self.len, self.data)

    def __len__(self):
        return self._SIZE + self.len


class opt_header(header):
    """Base for the hop-by-hop and destination options headers."""

    _FMT = "BB"
    _FIELDS = "nxt size"
    _EXTRA = "data"
    _DEFAULTS = {"nxt": inet.IPPROTO_TCP, "data": None}
    _FIX_SIZE = 8

    @classmethod
    def parser(cls, buf):
        """Decode the header and its options at offset 0 of ``buf``."""
        nxt, len_ = cls._STRUCT.unpack_from(buf)
        data_len = cls._FIX_SIZE + int(len_)
        data = []
        size = cls._SIZE
        while size < data_len:
            (type_,) = struct.unpack_from("!B", buf, size)
            if type_ == 0:
                opt = option(type_, -1, None)
                size += 1
            else:
                opt = option.parser(buf[size:])
                size += len(opt)
            data.append(opt)
        return cls(nxt, len_, data)

    def serialize(self):
        """Encode the header and its options, defaulting to one PadN option."""
        buf = bytearray(self.pack_fixed())
        if self.data is None:
            self.data = [option(type_=1, len_=4, data=b"\x00\x00\x00\x00")]
        for opt in self.data:
            buf.extend(opt.serialize())
        return buf

    def __len__(self):
        return self._FIX_SIZE + self.size


@ipv6.register_header_type(inet.IPPROTO_HOPOPTS)
class hop_opts(opt_header):
    """Hop-by-Hop Options header. ``size`` excludes the first 8 octets."""

    TYPE = inet.IPPROTO_HOPOPTS


@ipv6.register_header_type(inet.IPPROTO_DSTOPTS)
class dst_opts(opt_header):
    """Destination Options header. ``size`` excludes the first 8 octets."""

    TYPE = inet.IPPROTO_DSTOPTS


@ipv6.register_header_type(inet.IPPROTO_ROUTING)
class routing(header):
    """Routing header dispatcher.

    Only the RPL Source Route Header (type 3, RFC 6554) has a parser; any
    other routing type decodes as None.
    """

    TYPE = inet.IPPROTO_ROUTING

    _OFFSET_LEN = struct.calcsize("!2B")

    ROUTING_TYPE_2 = 0x02
    ROUTING_TYPE_3 = 0x03

    @classmethod
    def parser(cls, buf):
        """Decode a routing header by its routing type."""
        (type_,) = struct.unpack_from("!B", buf, cls._OFFSET_LEN)
        cls_ = {
            cls.ROUTING_TYPE_2: None,
            cls.ROUTING_TYPE_3: routing_type3,
        }.get(type_)
        if cls_:
            return cls_.parser(buf)
        return None


class routing_type3(header):
    """RPL Source Route Header (RFC 6554).

    Addresses 1..n-1 carry only their trailing ``16 - cmpi`` octets and
    address n only its trailing ``16 - cmpe`` octets.
    """

    _FMT = "BBBBBB2x"
    _FIELDS = "nxt size type seg cmp pad"
    _TYPE = {"asciilist": ("adrs",)}

    def __init__(
        self, nxt=inet.IPPROTO_TCP, size=0, type_=3, seg=0, cmpi=0, cmpe=0, adrs=None
    ):
        self.nxt = nxt
        self.size = size
        self.type = type_
        self.seg = seg
        self.cmpi = cmpi
        self.cmpe = cmpe
        self.adrs = adrs or []
        self._pad = (
            8 - ((len(self.adrs) - 1) * (16 - self.cmpi) + (16 - self.cmpe) % 8)
        ) % 8

    def iter_attrs(self):
        yield "nxt", self.nxt
        yield "size", self.size
        yield "type", self.type
        yield "seg", self.seg
        yield "cmpi", self.cmpi
        yield "cmpe", self.cmpe
        yield "adrs", self.adrs

    @classmethod
    def _get_size(cls, size):
        return (int(size) + 1) * 8

    @classmethod
    def parser(cls, buf):
        """Decode a type 3 routing header at offset 0 of ``buf``."""
        nxt, size, type_, seg, cmp_, pad = cls._STRUCT.unpack_from(buf)
        data = cls._SIZE
        header_len = cls._get_size(size)
        cmpi = int(cmp_ >> 4)
        cmpe = int(cmp_ & 0xF)
        pad = int(pad >> 4)
        adrs = []
        if size:
            adrs_len_i = 16 - cmpi
            adrs_len_e = 16 - cmpe
            form_i = "%ds" % adrs_len_i
            form_e = "%ds" % adrs_len_e
            while data < (header_len - (adrs_len_e + pad)):
                (adr,) = struct.unpack_from(form_i, buf[data:])
                adrs.append(addrconv.ipv6.bin_to_text((b"\x00" * cmpi) + adr))
                data += adrs_len_i
            (adr,) = struct.unpack_from(form_e, buf[data:])
            adrs.append(addrconv.ipv6.bin_to_text((b"\x00" * cmpe) + adr))
        return cls(nxt, size, type_, seg, cmpi, cmpe, adrs)

    def serialize(self):
        """Encode the header, sizing it from the address list when size is 0."""
        if self.size == 0:
            self.size = (
                (len(self.adrs) - 1) * (16 - self.cmpi) + (16 - self.cmpe) + self._pad
            ) // 8
        buf = bytearray(
            self._STRUCT.pack(
                self.nxt,
                self.size,
                self.type,
                self.seg,
                (self.cmpi << 4) | self.cmpe,
                self._pad << 4,
            )
        )
        if self.size:
            form_i = "%ds" % (16 - self.cmpi)
            form_e = "%ds" % (16 - self.cmpe)
            for adr in self.adrs[:-1]:
                buf.extend(
                    struct.pack(form_i, addrconv.ipv6.text_to_bin(adr)[self.cmpi :])
                )
            buf.extend(
                struct.pack(
                    form_e, addrconv.ipv6.text_to_bin(self.adrs[-1])[self.cmpe :]
                )
            )
        return buf

    def __len__(self):
        return self._get_size(self.size)


@ipv6.register_header_type(inet.IPPROTO_FRAGMENT)
class fragment(header):
    """Fragment header. ``offset`` is in 8 octet units."""

    TYPE = inet.IPPROTO_FRAGMENT

    _FMT = "BxHI"
    _FIELDS = "nxt off_m id"
    _MIN_LEN = 8

    def __init__(self, nxt=inet.IPPROTO_TCP, offset=0, more=0, id_=0):
        self.nxt = nxt
        self.offset = offset
        self.more = more
        self.id = id_

    def iter_attrs(self):
        yield "nxt", self.nxt
        yield "offset", self.offset
        yield "more", self.more
        yield "id", self.id

    @classmethod
    def parser(cls, buf):
        """Decode a fragment header at offset 0 of ``buf``."""
        nxt, off_m, id_ = cls._STRUCT.unpack_from(buf)
        return cls(nxt, off_m >> 3, off_m & 0x1, id_)

    def serialize(self):
        """Encode the fragment header."""
        return self._STRUCT.pack(self.nxt, self.offset << 3 | self.more, self.id)


@ipv6.register_header_type(inet.IPPROTO_AH)
class auth(header):
    """IP Authentication header (RFC 2402).

    ``size`` is the header length in 32 bit words less two.
    """

    TYPE = inet.IPPROTO_AH

    _FMT = "BB2xII"
    _FIELDS = "nxt size spi seq"
    _EXTRA = "data"
    _DEFAULTS = {"nxt": inet.IPPROTO_TCP, "size": 2, "data": b"\x00\x00\x00\x00"}

    @classmethod
    def _get_size(cls, size):
        return (int(size) + 2) * 4

    @classmethod
    def parser(cls, buf):
        """Decode an authentication header at offset 0 of ``buf``."""
        fields = cls.unpack_fixed(buf)
        form = "%ds" % (cls._get_size(fields["size"]) - cls._SIZE)
        (data,) = struct.unpack_from(form, buf, cls._SIZE)
        return cls.from_fields(fields, data=data)

    def serialize(self):
        """Encode the authentication header and its data."""
        buf = bytearray(self.pack_fixed())
        form = "%ds" % (self._get_size(self.size) - self._SIZE)
        buf.extend(struct.pack(form, self.data))
        return buf

    def __len__(self):
        return self._get_size(self.size)


ethernet.register_packet_type(ipv6, ether.ETH_TYPE_IPV6)

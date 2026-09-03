"""Nicira extensions: the experimenter actions and the NXM match fields.

A Nicira action is an ``OFPAT_EXPERIMENTER`` action whose body opens with the
Nicira experimenter id and a 16 bit subtype. :class:`NXAction` owns that
framing and dispatches on the subtype, so a concrete action declares only the
layout that follows it.
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

# Structures read the layout configuration of sibling classes.
# pylint: disable=protected-access

import struct

from c65of.codec import REQUIRED, msg_pack_into
from c65of.lib.type_desc import (
    Int1,
    Int2,
    Int4,
    Int8,
    Int16,
    IPv4Addr,
    IPv6Addr,
    MacAddr,
)
from c65of.ofproto import base
from c65of.ofproto import consts as ofproto
from c65of.ofproto import oxm

# Action subtypes.
NXAST_CT = 35
NXAST_NAT = 36
NXAST_CT_CLEAR = 43

# NXActionNAT range_present bits, in the order the ranges are packed.
NX_NAT_RANGE_IPV4_MIN = 1 << 0
NX_NAT_RANGE_IPV4_MAX = 1 << 1
NX_NAT_RANGE_IPV6_MIN = 1 << 2
NX_NAT_RANGE_IPV6_MAX = 1 << 3
NX_NAT_RANGE_PROTO_MIN = 1 << 4
NX_NAT_RANGE_PROTO_MAX = 1 << 5

_EXPERIMENTER = struct.Struct("!I")
_SUBTYPE = struct.Struct("!H")

#: type, len, experimenter, subtype.
NX_ACTION_HEADER_SIZE = ofproto.OFP_ACTION_EXPERIMENTER_HEADER_SIZE + _SUBTYPE.size


class NXAction(base.OFPActionExperimenter):
    """Base for Nicira experimenter actions.

    Registered as the parser for ``OFPAT_EXPERIMENTER``: it reads the
    experimenter id, hands a foreign one back to the plain experimenter action
    and dispatches a Nicira one on its subtype.
    """

    _ABSTRACT = True
    _FMT = ""
    _FIELDS = ""
    _EXTRA = "type len experimenter subtype"
    _DEFAULTS = {}
    #: subtype -> class.
    _SUBTYPES = {}
    #: The subtype of a concrete action; None on the base and the catch-all.
    _SUBTYPE = None

    def _init_hook(self):
        self.type = ofproto.OFPAT_EXPERIMENTER
        # The length is whatever serialization works out, so a value passed in
        # is not believed, as in os-ken.
        self.len = None
        self.experimenter = ofproto.NX_EXPERIMENTER_ID
        if self._SUBTYPE is not None:
            self.subtype = self._SUBTYPE

    @classmethod
    def parse_body(cls, buf, offset, type_, len_):
        (experimenter,) = _EXPERIMENTER.unpack_from(buf, offset + 4)
        if experimenter != ofproto.NX_EXPERIMENTER_ID:
            action = base.OFPActionExperimenter(experimenter)
            action.type = type_
            action.len = len_
            return action
        header = ofproto.OFP_ACTION_EXPERIMENTER_HEADER_SIZE
        action = cls.parse(bytes(buf[offset + header : offset + len_]))
        action.len = len_
        return action

    @classmethod
    def parser(cls, buf):  # pylint: disable=arguments-differ
        """Build one action from its body. An override point."""
        return cls.from_fields(cls.unpack_fixed(buf, 0))

    @classmethod
    def parse(cls, buf):
        """Build one Nicira action from its subtype and body."""
        (subtype,) = _SUBTYPE.unpack_from(buf, 0)
        subcls = cls._SUBTYPES.get(subtype)
        body = buf[_SUBTYPE.size :]
        if subcls is None:
            return NXActionUnknown(subtype, body)
        return subcls.parser(body)

    def serialize(self, buf, offset):
        """Write this action into ``buf``, returning its padded length."""
        data = self.serialize_body()
        self.len = base.round_up(NX_ACTION_HEADER_SIZE + len(data), 8)
        pad_len = self.len - NX_ACTION_HEADER_SIZE - len(data)
        msg_pack_into(
            "!HHIH%ds%dx" % (len(data), pad_len),
            buf,
            offset,
            self.type,
            self.len,
            self.experimenter,
            self.subtype,
            bytes(data),
        )
        return self.len

    def serialize_body(self):
        """The action body following the subtype. An override point."""
        return self.pack_fixed() + self.pack_tail()


def _nx_action(cls):
    """Register a Nicira action class under its subtype."""
    if cls._SUBTYPE in NXAction._SUBTYPES:
        raise TypeError("NX action subtype %d already registered" % cls._SUBTYPE)
    NXAction._SUBTYPES[cls._SUBTYPE] = cls
    return cls


class NXActionUnknown(NXAction):
    """A Nicira action whose subtype this library does not recognise."""

    _LEAD = "subtype"
    _EXTRA = "data type len experimenter"

    def serialize_body(self):
        return b"" if self.data is None else self.data


class _ZoneSrc:
    """The CT zone source: an OXM/NXM field name, or ``""`` for an immediate."""

    @staticmethod
    def to_user(value):
        """Field name for four bytes of OXM header, or ``""`` if all zero."""
        if value == b"\x00\x00\x00\x00":
            return ""
        num, _ = oxm.oxm_parse_header(value, 0)
        return oxm.oxm_to_user_header(num)

    @staticmethod
    def from_user(value):
        """Four bytes: an OXM header, a raw int, or zeros for an immediate."""
        if not value:
            return b"\x00\x00\x00\x00"
        if isinstance(value, int):
            return _EXPERIMENTER.pack(value)
        buf = bytearray()
        oxm.oxm_serialize_header(oxm.oxm_from_user_header(value), buf, 0)
        return bytes(buf)


@_nx_action
class NXActionCT(NXAction):
    """Send the packet through the connection tracker.

    ``zone_ofs_nbits`` is the immediate zone when ``zone_src`` is empty and the
    bit range within ``zone_src`` otherwise. Zero or more actions run in the
    connection tracking context.
    """

    _SUBTYPE = NXAST_CT
    _FMT = "H4sHB3xH"
    _FIELDS = "flags zone_src zone_ofs_nbits recirc_table alg"
    _EXTRA = "actions type len experimenter subtype"
    _DEFAULTS = {
        "flags": REQUIRED,
        "zone_src": REQUIRED,
        "zone_ofs_nbits": REQUIRED,
        "recirc_table": REQUIRED,
        "alg": REQUIRED,
        "actions": REQUIRED,
    }
    _CODERS = {"zone_src": _ZoneSrc}
    _TYPE = {"ascii": ("zone_src",)}

    @classmethod
    def parser(cls, buf):
        """Build the action from its body, nested actions included."""
        fields = cls.unpack_fixed(buf, 0)
        rest = buf[cls._SIZE :]
        actions = []
        while rest:
            action = base.OFPAction.parser(rest, 0)
            actions.append(action)
            rest = rest[action.len :]
        return cls.from_fields(fields, actions=actions)

    def pack_tail(self):
        data = bytearray()
        for action in self.actions:
            action.serialize(data, len(data))
        return bytes(data)


@_nx_action
class NXActionCTClear(NXAction):
    """Clear the connection tracking state of the packet."""

    _SUBTYPE = NXAST_CT_CLEAR
    _FMT = "6x"
    _FIELDS = ""


# (attribute, range_present bit, type descriptor, the value meaning absent).
_NAT_RANGES = (
    ("range_ipv4_min", NX_NAT_RANGE_IPV4_MIN, IPv4Addr, ""),
    ("range_ipv4_max", NX_NAT_RANGE_IPV4_MAX, IPv4Addr, ""),
    ("range_ipv6_min", NX_NAT_RANGE_IPV6_MIN, IPv6Addr, ""),
    ("range_ipv6_max", NX_NAT_RANGE_IPV6_MAX, IPv6Addr, ""),
    ("range_proto_min", NX_NAT_RANGE_PROTO_MIN, Int2, None),
    ("range_proto_max", NX_NAT_RANGE_PROTO_MAX, Int2, None),
)

_NAT_HEADER = struct.Struct("!2xHH")


@_nx_action
class NXActionNAT(NXAction):
    """Network address translation, valid only inside :class:`NXActionCT`.

    Each range is optional; the ones supplied are flagged in a bitmap and
    packed in a fixed order after the flags.
    """

    _SUBTYPE = NXAST_NAT
    _LEAD = "flags"
    _EXTRA = (
        "range_ipv4_min range_ipv4_max range_ipv6_min range_ipv6_max "
        "range_proto_min range_proto_max type len experimenter subtype"
    )
    _DEFAULTS = {
        "range_ipv4_min": "",
        "range_ipv4_max": "",
        "range_ipv6_min": "",
        "range_ipv6_max": "",
    }
    _TYPE = {
        "ascii": (
            "range_ipv4_max",
            "range_ipv4_min",
            "range_ipv6_max",
            "range_ipv6_min",
        )
    }

    @classmethod
    def parser(cls, buf):
        """Build the action from its flags and the ranges its bitmap flags."""
        flags, range_present = _NAT_HEADER.unpack_from(buf, 0)
        rest = buf[_NAT_HEADER.size :]
        kwargs = {}
        for name, bit, desc, _ in _NAT_RANGES:
            if range_present & bit:
                kwargs[name] = desc.to_user(rest[: desc.size])
                rest = rest[desc.size :]
        return cls(flags, **kwargs)

    def serialize_body(self):
        optional = b""
        range_present = 0
        for name, bit, desc, absent in _NAT_RANGES:
            value = getattr(self, name)
            if value != absent:
                range_present |= bit
                optional += desc.from_user(value)
        return _NAT_HEADER.pack(self.flags, range_present) + optional


# An OFPAT_EXPERIMENTER action is parsed here from now on, so that a Nicira one
# becomes its subtype class rather than a bare OFPActionExperimenter.
base.ACTIONS.classes[ofproto.OFPAT_EXPERIMENTER] = NXAction


class NiciraNshExperimenter(oxm.NiciraExperimenter):
    """Nicira Network Service Header experimenter field."""

    experimenter_id = ofproto.NX_NSH_EXPERIMENTER_ID


#: The NXM/NXOXM match fields, in os-ken's registration order. A leading
#: underscore marks a name OVS reserves for internal use.
oxm_types = (
    [
        oxm.NiciraExtended0("in_port_nxm", 0, Int2),
        oxm.NiciraExtended0("eth_dst_nxm", 1, MacAddr),
        oxm.NiciraExtended0("eth_src_nxm", 2, MacAddr),
        oxm.NiciraExtended0("eth_type_nxm", 3, Int2),
        oxm.NiciraExtended0("vlan_tci", 4, Int2),
        oxm.NiciraExtended0("nw_tos", 5, Int1),
        oxm.NiciraExtended0("ip_proto_nxm", 6, Int1),
        oxm.NiciraExtended0("ipv4_src_nxm", 7, IPv4Addr),
        oxm.NiciraExtended0("ipv4_dst_nxm", 8, IPv4Addr),
        oxm.NiciraExtended0("tcp_src_nxm", 9, Int2),
        oxm.NiciraExtended0("tcp_dst_nxm", 10, Int2),
        oxm.NiciraExtended0("udp_src_nxm", 11, Int2),
        oxm.NiciraExtended0("udp_dst_nxm", 12, Int2),
        oxm.NiciraExtended0("icmpv4_type_nxm", 13, Int1),
        oxm.NiciraExtended0("icmpv4_code_nxm", 14, Int1),
        oxm.NiciraExtended0("arp_op_nxm", 15, Int2),
        oxm.NiciraExtended0("arp_spa_nxm", 16, IPv4Addr),
        oxm.NiciraExtended0("arp_tpa_nxm", 17, IPv4Addr),
        oxm.NiciraExtended1("tunnel_id_nxm", 16, Int8),
        oxm.NiciraExtended1("arp_sha_nxm", 17, MacAddr),
        oxm.NiciraExtended1("arp_tha_nxm", 18, MacAddr),
        oxm.NiciraExtended1("ipv6_src_nxm", 19, IPv6Addr),
        oxm.NiciraExtended1("ipv6_dst_nxm", 20, IPv6Addr),
        oxm.NiciraExtended1("icmpv6_type_nxm", 21, Int1),
        oxm.NiciraExtended1("icmpv6_code_nxm", 22, Int1),
        oxm.NiciraExtended1("nd_target", 23, IPv6Addr),
        oxm.NiciraExtended1("nd_sll", 24, MacAddr),
        oxm.NiciraExtended1("nd_tll", 25, MacAddr),
        oxm.NiciraExtended1("ip_frag", 26, Int1),
        oxm.NiciraExtended1("ipv6_label", 27, Int4),
        oxm.NiciraExtended1("ip_ecn_nxm", 28, Int1),
        oxm.NiciraExtended1("nw_ttl", 29, Int1),
        oxm.NiciraExtended1("mpls_ttl", 30, Int1),
        oxm.NiciraExtended1("tun_ipv4_src", 31, IPv4Addr),
        oxm.NiciraExtended1("tun_ipv4_dst", 32, IPv4Addr),
        oxm.NiciraExtended1("pkt_mark", 33, Int4),
        oxm.NiciraExtended1("tcp_flags_nxm", 34, Int2),
        oxm.NiciraExtended1("conj_id", 37, Int4),
        oxm.NiciraExtended1("tun_gbp_id", 38, Int2),
        oxm.NiciraExtended1("tun_gbp_flags", 39, Int1),
        oxm.NiciraExtended1("tun_flags", 104, Int2),
        oxm.NiciraExtended1("ct_state", 105, Int4),
        oxm.NiciraExtended1("ct_zone", 106, Int2),
        oxm.NiciraExtended1("ct_mark", 107, Int4),
        oxm.NiciraExtended1("ct_label", 108, Int16),
        oxm.NiciraExtended1("tun_ipv6_src", 109, IPv6Addr),
        oxm.NiciraExtended1("tun_ipv6_dst", 110, IPv6Addr),
        oxm.NiciraExtended1("_recirc_id", 36, Int4),
        oxm.NiciraExperimenter("_dp_hash", 0, Int4),
        NiciraNshExperimenter("nsh_flags", 1, Int1),
        NiciraNshExperimenter("nsh_mdtype", 2, Int1),
        NiciraNshExperimenter("nsh_np", 3, Int1),
        NiciraNshExperimenter("nsh_spi", 4, Int4),
        NiciraNshExperimenter("nsh_si", 5, Int1),
        NiciraNshExperimenter("nsh_c1", 6, Int4),
        NiciraNshExperimenter("nsh_c2", 7, Int4),
        NiciraNshExperimenter("nsh_c3", 8, Int4),
        NiciraNshExperimenter("nsh_c4", 9, Int4),
        NiciraNshExperimenter("nsh_ttl", 10, Int1),
    ]
    + [oxm.NiciraExtended1("reg%d" % i, i, Int4) for i in range(16)]
    + [oxm.NiciraExtended1("xxreg%d" % i, 111 + i, Int16) for i in range(4)]
)

oxm.add_fields(oxm_types)

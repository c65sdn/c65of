"""OXM match fields: the wire encoding and the user value mapping.

An OXM TLV is a 32 bit header -- 16 bit class, 7 bit field, mask flag, 8 bit
payload length -- followed by a value and, when the mask flag is set, a mask.
Experimenter classes carry a further 32 bit experimenter id.

Two representations of a field value are in play. The *user* form is what
callers pass and receive: a text address, an int, or a ``(value, mask)`` pair.
The *internal* form is on-wire bytes, with a mask of None when unmasked.
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

import struct
import sys

from c65of.codec import msg_pack_into
from c65of.lib import type_desc
from c65of.lib.type_desc import (
    Int1,
    Int2,
    Int3,
    Int4,
    Int8,
    IPv4Addr,
    IPv6Addr,
    MacAddr,
)
from c65of.ofproto import consts

OFPXMC_NXM_0 = 0
OFPXMC_NXM_1 = 1
OFPXMC_OPENFLOW_BASIC = 0x8000
OFPXMC_PACKET_REGS = 0x8001
OFPXMC_EXPERIMENTER = 0xFFFF


class _OxmClass:
    """One match field: its name, wire numbering and value type."""

    __slots__ = ("name", "oxm_field", "oxm_type", "num", "type", "exp_type")

    oxm_class = None
    experimenter_id = None

    def __init__(self, name, num, type_):
        self.name = name
        self.oxm_field = num
        self.oxm_type = num | (self.oxm_class << 7)
        self.num = self.oxm_type
        self.type = type_
        self.exp_type = None


class OpenFlowBasic(_OxmClass):
    """OFPXMC_OPENFLOW_BASIC field."""

    oxm_class = OFPXMC_OPENFLOW_BASIC


class PacketRegs(_OxmClass):
    """OFPXMC_PACKET_REGS field."""

    oxm_class = OFPXMC_PACKET_REGS


class NiciraExtended0(_OxmClass):
    """NXM_OF_ field. Same 32 bit header shape as a basic field."""

    oxm_class = OFPXMC_NXM_0


class NiciraExtended1(_OxmClass):
    """NXM_NX_ field. Same 32 bit header shape as a basic field."""

    oxm_class = OFPXMC_NXM_1


class _Experimenter(_OxmClass):
    """Field in the experimenter class, numbered by ``(exp_id, oxm_type)``."""

    oxm_class = OFPXMC_EXPERIMENTER

    def __init__(self, name, num, type_):
        super().__init__(name, num, type_)
        self.num = (self.experimenter_id, self.oxm_type)
        self.exp_type = self.oxm_field


class ONFExperimenter(_Experimenter):
    """ONF experimenter field."""

    experimenter_id = consts.ONF_EXPERIMENTER_ID


class OldONFExperimenter(_Experimenter):
    """ONF experimenter field in the superseded EXT-256 encoding."""

    experimenter_id = consts.ONF_EXPERIMENTER_ID

    def __init__(self, name, num, type_):
        super().__init__(name, 0, type_)
        self.num = (self.experimenter_id, num)
        self.exp_type = 2560


class NiciraExperimenter(_Experimenter):
    """Nicira experimenter field."""

    experimenter_id = consts.NX_EXPERIMENTER_ID


# OFPXMT_OFB_* field numbers are the position in this table.
_BASIC = (
    ("in_port", Int4),
    ("in_phy_port", Int4),
    ("metadata", Int8),
    ("eth_dst", MacAddr),
    ("eth_src", MacAddr),
    ("eth_type", Int2),
    ("vlan_vid", Int2),
    ("vlan_pcp", Int1),
    ("ip_dscp", Int1),
    ("ip_ecn", Int1),
    ("ip_proto", Int1),
    ("ipv4_src", IPv4Addr),
    ("ipv4_dst", IPv4Addr),
    ("tcp_src", Int2),
    ("tcp_dst", Int2),
    ("udp_src", Int2),
    ("udp_dst", Int2),
    ("sctp_src", Int2),
    ("sctp_dst", Int2),
    ("icmpv4_type", Int1),
    ("icmpv4_code", Int1),
    ("arp_op", Int2),
    ("arp_spa", IPv4Addr),
    ("arp_tpa", IPv4Addr),
    ("arp_sha", MacAddr),
    ("arp_tha", MacAddr),
    ("ipv6_src", IPv6Addr),
    ("ipv6_dst", IPv6Addr),
    ("ipv6_flabel", Int4),
    ("icmpv6_type", Int1),
    ("icmpv6_code", Int1),
    ("ipv6_nd_target", IPv6Addr),
    ("ipv6_nd_sll", MacAddr),
    ("ipv6_nd_tll", MacAddr),
    ("mpls_label", Int4),
    ("mpls_tc", Int1),
    ("mpls_bos", Int1),
    ("pbb_isid", Int3),
    ("tunnel_id", Int8),
    ("ipv6_exthdr", Int2),
)

oxm_types = [OpenFlowBasic(name, num, desc) for num, (name, desc) in enumerate(_BASIC)]
oxm_types += [PacketRegs("xreg%d" % i, i, Int8) for i in range(8)]
oxm_types += [
    OldONFExperimenter("pbb_uca", 2560, Int1),  # EXT-256
    ONFExperimenter("tcp_flags", 42, Int2),  # EXT-109
    ONFExperimenter("actset_output", 43, Int4),  # EXT-233
]


def add_fields(fields):
    """Extend the field table, refresh the lookups and the generated names."""
    oxm_types.extend(fields)
    _index()


_name_to_field = {}
_num_to_field = {}


def _index():
    _name_to_field.clear()
    _num_to_field.clear()
    module = sys.modules[__name__]
    for field in oxm_types:
        _name_to_field[field.name] = field
        _num_to_field[field.num] = field
        if isinstance(field.num, tuple) or field.oxm_class != OFPXMC_OPENFLOW_BASIC:
            continue
        upper = field.name.upper()
        size = field.type.size
        setattr(module, "OFPXMT_OFB_" + upper, field.oxm_field)
        setattr(module, "OXM_OF_" + upper, oxm_tlv_header(field.oxm_field, size))
        setattr(
            module, "OXM_OF_" + upper + "_W", oxm_tlv_header_w(field.oxm_field, size)
        )


oxm_tlv_header = consts.oxm_tlv_header
oxm_tlv_header_w = consts.oxm_tlv_header_w
oxm_tlv_header_extract_hasmask = consts.oxm_tlv_header_extract_hasmask
oxm_tlv_header_extract_length = consts.oxm_tlv_header_extract_length


def oxm_get_field_info_by_name(name):
    """Return ``(num, type_desc)`` for a field name."""
    field = _name_to_field.get(name)
    if field is not None:
        return field.num, field.type
    if name.startswith("field_"):
        return int(name.split("_")[1]), type_desc.UnknownType
    raise KeyError("unknown OXM field: %s" % name)


def _field_info_by_number(num):
    field = _num_to_field.get(num)
    if field is not None:
        return field.name, field.type
    if isinstance(num, int):
        return "field_%d" % num, type_desc.UnknownType
    raise KeyError("unknown OXM field number: %s" % (num,))


def oxm_from_user_header(name):
    """Field number for a field name."""
    return oxm_get_field_info_by_name(name)[0]


def oxm_to_user_header(num):
    """Field name for a field number."""
    return _field_info_by_number(num)[0]


def oxm_from_user(name, user_value):
    """Convert a user value to ``(num, value, mask)`` on-wire bytes."""
    num, desc = oxm_get_field_info_by_name(name)
    # json.dumps turns a tuple into a list, so accept both.
    if isinstance(user_value, (tuple, list)):
        value, mask = user_value if user_value else (None, None)
    else:
        value, mask = user_value, None
    if value is not None:
        value = desc.from_user(value)
    if mask is not None:
        mask = desc.from_user(mask)
    elif isinstance(value, tuple):
        # An address in CIDR notation converts to a (value, netmask) pair.
        value, mask = value
    return num, value, mask


def oxm_to_user(num, value, mask):
    """Convert on-wire bytes to ``(name, user_value)``."""
    name, desc = _field_info_by_number(num)
    if value is None:
        return name, None
    size = getattr(desc, "size", None)
    if size is not None:
        length = (
            len(value) * len(value[0])
            if isinstance(value, (tuple, list))
            else len(value)
        )
        if size != length:
            raise ValueError(
                "unexpected OXM payload length %d for %s (expected %d)"
                % (length, name, size)
            )
    user_value = desc.to_user(value)
    return name, (user_value if mask is None else (user_value, desc.to_user(mask)))


def oxm_field_desc(num):
    """The field descriptor for a field number."""
    return _num_to_field[num]


def oxm_normalize_user(name, user_value):
    """Return the user value a round trip through the wire form would give."""
    try:
        num, value, mask = oxm_from_user(name, user_value)
    except (KeyError, ValueError, TypeError):
        return name, user_value
    if mask is not None:
        value = bytes(v & m for v, m in zip(value, mask))
    try:
        return oxm_to_user(num, value, mask)
    except (KeyError, ValueError, TypeError):
        return name, user_value


def _parse_header_impl(buf, offset):
    (header,) = struct.unpack_from("!I", buf, offset)
    hdr_len = 4
    oxm_type = header >> 9
    hasmask = (header >> 8) & 1
    oxm_class = oxm_type >> 7
    oxm_length = header & 0xFF
    if oxm_class == OFPXMC_EXPERIMENTER:
        (exp_id,) = struct.unpack_from("!I", buf, offset + hdr_len)
        exp_hdr_len = 4
        oxm_field = oxm_type & 0x7F
        if exp_id == consts.ONF_EXPERIMENTER_ID and oxm_field == 0:
            # EXT-256 style: the experimenter id is followed by an exp_type.
            (exp_type,) = struct.unpack_from("!H", buf, offset + hdr_len + exp_hdr_len)
            exp_hdr_len += 2
            num = (exp_id, exp_type)
        else:
            num = (exp_id, oxm_type)
    else:
        num = oxm_type
        exp_hdr_len = 0
    value_len = oxm_length - exp_hdr_len
    if hasmask:
        value_len //= 2
    if value_len <= 0:
        raise ValueError("OXM field %s has no payload" % (num,))
    return num, hdr_len + exp_hdr_len, hasmask, value_len, hdr_len + oxm_length


def oxm_parse_header(buf, offset):
    """Return ``(num, header_len)`` for the OXM header at ``offset``."""
    num, _, _, value_len, field_len = _parse_header_impl(buf, offset)
    return num, field_len - value_len


def oxm_parse(buf, offset):
    """Return ``(num, value, mask, field_len)`` for the OXM TLV at ``offset``."""
    num, total_hdr_len, hasmask, value_len, field_len = _parse_header_impl(buf, offset)
    value_offset = offset + total_hdr_len
    value = bytes(buf[value_offset : value_offset + value_len])
    mask = None
    if hasmask:
        mask_offset = value_offset + value_len
        mask = bytes(buf[mask_offset : mask_offset + value_len])
    return num, value, mask, field_len


def _exp_header(num):
    """Return ``(oxm_type, experimenter_header_bytes)`` for a field number."""
    try:
        desc = _num_to_field[num]
    except KeyError:
        return num, b""
    if desc.oxm_class != OFPXMC_EXPERIMENTER:
        return num, b""
    exp_id, _ = num
    if desc.exp_type == 2560:
        return desc.oxm_type, struct.pack("!IH", exp_id, desc.exp_type)
    return desc.oxm_type, struct.pack("!I", exp_id)


def oxm_serialize(num, value, mask, buf, offset):
    """Write an OXM TLV into ``buf`` at ``offset``, returning its length."""
    num, exp_hdr = _exp_header(num)
    exp_hdr_len = len(exp_hdr)
    value_len = len(value)
    if mask:
        if value_len != len(mask):
            raise ValueError("OXM value and mask differ in length")
        pack_str = "!I%ds%ds%ds" % (exp_hdr_len, value_len, value_len)
        header = (num << 9) | (1 << 8) | (exp_hdr_len + value_len * 2)
        msg_pack_into(pack_str, buf, offset, header, exp_hdr, value, mask)
    else:
        pack_str = "!I%ds%ds" % (exp_hdr_len, value_len)
        header = (num << 9) | (exp_hdr_len + value_len)
        msg_pack_into(pack_str, buf, offset, header, exp_hdr, value)
    return struct.calcsize(pack_str)


def oxm_serialize_header(num, buf, offset):
    """Write a bare OXM header (no payload) into ``buf`` at ``offset``."""
    try:
        value_len = _num_to_field[num].type.size
    except KeyError:
        value_len = 0
    num, exp_hdr = _exp_header(num)
    exp_hdr_len = len(exp_hdr)
    pack_str = "!I%ds" % exp_hdr_len
    msg_pack_into(
        pack_str, buf, offset, (num << 9) | (exp_hdr_len + value_len), exp_hdr
    )
    return struct.calcsize(pack_str)


def oxm_to_jsondict(name, user_value):
    """JSON dict form of one match field."""
    value, mask = user_value if isinstance(user_value, tuple) else (user_value, None)
    return {"OXMTlv": {"field": name, "value": value, "mask": mask}}


def oxm_from_jsondict(jsondict):
    """Return ``(name, user_value)`` from the JSON dict form of a match field."""
    tlv = jsondict["OXMTlv"]
    mask = tlv.get("mask")
    value = tlv["value"]
    return tlv["field"], value if mask is None else (value, mask)


_index()

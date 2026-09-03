"""Differential tests: OXM encoding must be byte identical to os-ken's."""

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

# os-ken attaches its oxm_* helpers with setattr, so pylint cannot see them.
# pylint: disable=no-member

import os_ken.ofproto.ofproto_v1_3 as reference
import pytest

from c65of.ofproto import oxm

# One representative value per OF1.3 basic field, plus the experimenter and
# packet register classes.
PLAIN = {
    "in_port": 4294967293,
    "in_phy_port": 2,
    "metadata": 0x1234567890ABCDEF,
    "eth_dst": "0e:00:00:00:00:01",
    "eth_src": "ff:ff:ff:ff:ff:ff",
    "eth_type": 0x800,
    "vlan_vid": 0x1064,
    "vlan_pcp": 3,
    "ip_dscp": 46,
    "ip_ecn": 1,
    "ip_proto": 6,
    "ipv4_src": "10.0.0.1",
    "ipv4_dst": "192.168.1.254",
    "tcp_src": 80,
    "tcp_dst": 443,
    "udp_src": 53,
    "udp_dst": 67,
    "sctp_src": 1,
    "sctp_dst": 2,
    "icmpv4_type": 8,
    "icmpv4_code": 0,
    "arp_op": 1,
    "arp_spa": "10.0.0.1",
    "arp_tpa": "10.0.0.2",
    "arp_sha": "0e:00:00:00:00:01",
    "arp_tha": "00:00:00:00:00:00",
    "ipv6_src": "fe80::1",
    "ipv6_dst": "2001:db8::ff",
    "ipv6_flabel": 0x12345,
    "icmpv6_type": 135,
    "icmpv6_code": 0,
    "ipv6_nd_target": "fe80::2",
    "ipv6_nd_sll": "0e:00:00:00:00:03",
    "ipv6_nd_tll": "0e:00:00:00:00:04",
    "mpls_label": 100,
    "mpls_tc": 2,
    "mpls_bos": 1,
    "pbb_isid": 0xABCDEF,
    "tunnel_id": 0xDEADBEEF,
    "ipv6_exthdr": 0x40,
    "tcp_flags": 0x12,
    "actset_output": 7,
    "pbb_uca": 1,
    "xreg0": 1,
    "xreg7": 255,
}

MASKED = {
    "eth_dst": ("0e:00:00:00:00:00", "ff:ff:ff:00:00:00"),
    "ipv4_src": ("10.0.0.0", "255.0.0.0"),
    "ipv6_src": ("2001:db8::", "ffff:ffff::"),
    "vlan_vid": (0x1000, 0x1000),
    "metadata": (0xFF, 0xFF),
}

# An address in CIDR or dotted-mask notation becomes a masked match.
CIDR = {
    "ipv4_src": "10.0.0.0/8",
    "ipv6_dst": "2001:db8::/32",
    "ipv4_dst": "192.168.0.0/255.255.0.0",
}

CASES = list(PLAIN.items()) + list(MASKED.items()) + list(CIDR.items())
CASE_IDS = [
    "%s-%s" % (name, kind)
    for kind, group in (("plain", PLAIN), ("masked", MASKED), ("cidr", CIDR))
    for name in group
]


@pytest.mark.parametrize("name, value", CASES, ids=CASE_IDS)
def test_field_round_trip_matches_reference(name, value):
    """Every stage of the OXM pipeline agrees with os-ken, byte for byte."""
    ours = oxm.oxm_from_user(name, value)
    assert ours == reference.oxm_from_user(name, value)
    num, packed, mask = ours

    our_buf, ref_buf = bytearray(), bytearray()
    our_len = oxm.oxm_serialize(num, packed, mask, our_buf, 0)
    ref_len = reference.oxm_serialize(num, packed, mask, ref_buf, 0)
    assert (bytes(our_buf), our_len) == (bytes(ref_buf), ref_len)

    assert oxm.oxm_parse(bytes(our_buf), 0) == reference.oxm_parse(bytes(ref_buf), 0)
    parsed_num, parsed_value, parsed_mask, _ = oxm.oxm_parse(bytes(our_buf), 0)
    assert oxm.oxm_to_user(
        parsed_num, parsed_value, parsed_mask
    ) == reference.oxm_to_user(parsed_num, parsed_value, parsed_mask)
    assert oxm.oxm_normalize_user(name, value) == reference.oxm_normalize_user(
        name, value
    )

    our_hdr, ref_hdr = bytearray(), bytearray()
    assert oxm.oxm_serialize_header(num, our_hdr, 0) == reference.oxm_serialize_header(
        num, ref_hdr, 0
    )
    assert bytes(our_hdr) == bytes(ref_hdr)
    assert oxm.oxm_parse_header(bytes(our_hdr), 0) == reference.oxm_parse_header(
        bytes(ref_hdr), 0
    )
    assert oxm.oxm_to_jsondict(name, value) == reference.oxm_to_jsondict(name, value)


def test_generated_names_match_reference():
    """OXM_OF_* and OFPXMT_OFB_* are generated with the reference values."""
    missing = []
    for field in reference.oxm_types:
        if (
            isinstance(field.num, tuple)
            or field.oxm_type >> 7 != oxm.OFPXMC_OPENFLOW_BASIC
        ):
            continue
        upper = field.name.upper()
        for name in (
            "OFPXMT_OFB_" + upper,
            "OXM_OF_" + upper,
            "OXM_OF_" + upper + "_W",
        ):
            if getattr(oxm, name, None) != getattr(reference, name):
                missing.append(name)
    assert not missing, "differing: %s" % missing


def test_jsondict_round_trip():
    """A field survives the JSON dict form used by the REST and test paths."""
    for name, value in PLAIN.items():
        jsondict = oxm.oxm_to_jsondict(name, value)
        assert oxm.oxm_from_jsondict(jsondict) == (name, value)


def test_unknown_field_by_number():
    """An unrecognised field number round trips as field_N opaque bytes."""
    name = oxm.oxm_to_user_header(0x7000)
    assert name == "field_28672"
    assert oxm.oxm_from_user_header(name) == 0x7000


def test_unknown_field_name_rejected():
    """A name that is neither known nor field_N is an error."""
    with pytest.raises(KeyError):
        oxm.oxm_from_user_header("no_such_field")

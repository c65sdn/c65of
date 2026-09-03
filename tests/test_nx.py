"""Differential tests: the Nicira actions and NXM fields against os-ken."""

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

import inspect

import os_ken.ofproto.ofproto_v1_3 as ref_ofp
import os_ken.ofproto.ofproto_v1_3_parser as ref
import pytest

from c65of.lib.type_desc import IntDescr, IPv4Addr, IPv6Addr, MacAddr
from c65of.ofproto import base, nx, oxm, parser

# (id, builder taking the parser module under test).
ACTIONS = [
    ("ct-bare", lambda m: m.NXActionCT(0, "", 0, 0, 0, [])),
    ("ct-immediate-zone", lambda m: m.NXActionCT(1, "", 5, 255, 0, [])),
    ("ct-zone-src", lambda m: m.NXActionCT(1, "reg0", 283, 4, 0, [])),
    ("ct-alg", lambda m: m.NXActionCT(3, "ct_zone", 64, 10, 21, [])),
    (
        "ct-one-action",
        lambda m: m.NXActionCT(1, "reg0", 283, 4, 0, [m.OFPActionOutput(1)]),
    ),
    (
        "ct-many-actions",
        lambda m: m.NXActionCT(
            3,
            "",
            9,
            10,
            80,
            [
                m.OFPActionSetField(ct_mark=7),
                m.OFPActionSetField(ct_label=1 << 100),
                m.NXActionNAT(
                    1, range_ipv4_min="10.1.12.0", range_ipv4_max="10.1.13.255"
                ),
                m.OFPActionOutput(4294967293),
            ],
        ),
    ),
    ("ct-clear", lambda m: m.NXActionCTClear()),
    ("nat-bare", lambda m: m.NXActionNAT(0)),
    ("nat-flags", lambda m: m.NXActionNAT(0x37)),
    ("nat-ipv4-min", lambda m: m.NXActionNAT(1, range_ipv4_min="10.1.12.0")),
    ("nat-ipv4-max", lambda m: m.NXActionNAT(1, range_ipv4_max="10.1.13.255")),
    ("nat-ipv4-range", lambda m: m.NXActionNAT(1, "10.1.12.0", "10.1.13.255")),
    ("nat-ipv6-min", lambda m: m.NXActionNAT(2, range_ipv6_min="2001:db8::1")),
    ("nat-ipv6-max", lambda m: m.NXActionNAT(2, range_ipv6_max="2001:db8::ff")),
    ("nat-proto-min", lambda m: m.NXActionNAT(4, range_proto_min=0)),
    ("nat-proto-max", lambda m: m.NXActionNAT(4, range_proto_max=1023)),
    (
        "nat-everything",
        lambda m: m.NXActionNAT(
            0x21,
            "10.1.12.0",
            "10.1.13.255",
            "2001:db8::1",
            "2001:db8::ff",
            1,
            1023,
        ),
    ),
]
ACTION_IDS = [name for name, _ in ACTIONS]


def _serialized(obj):
    buf = bytearray()
    obj.serialize(buf, 0)
    return bytes(buf)


def _reference_bytes(action):
    """os-ken's bytes, zero filled to the length it declares.

    os-ken sets ``len`` to the padded length but never writes the padding, so
    a lone ``NXActionNAT`` whose optional ranges do not land on an eight byte
    boundary comes back short of its own ``len``. Serializing it inside an
    instruction hides that, as the next action is written at ``len``.
    """
    return _serialized(action).ljust(action.len, b"\x00")


@pytest.mark.parametrize("build", [b for _, b in ACTIONS], ids=ACTION_IDS)
def test_action_matches_reference(build):
    """An action serializes, parses and stringifies exactly as os-ken's does."""
    ours, theirs = build(parser), build(ref)
    assert str(ours) == str(theirs)
    assert ours.to_jsondict() == theirs.to_jsondict()
    assert _serialized(ours) == _reference_bytes(theirs)
    assert ours.len == theirs.len
    assert str(ours) == str(theirs)
    assert ours.to_jsondict() == theirs.to_jsondict()

    wire = _reference_bytes(theirs)
    assert (
        base.OFPAction.parser(wire, 0).to_jsondict()
        == ref.OFPAction.parser(wire, 0).to_jsondict()
    )


@pytest.mark.parametrize("build", [b for _, b in ACTIONS], ids=ACTION_IDS)
def test_action_jsondict_round_trip(build):
    """An action survives the JSON dict form, as os-ken's does."""
    ours, theirs = build(parser), build(ref)
    name = type(ours).__name__
    our_copy = type(ours).from_jsondict(ours.to_jsondict()[name])
    their_copy = getattr(ref, name).from_jsondict(theirs.to_jsondict()[name])
    assert our_copy.to_jsondict() == their_copy.to_jsondict()
    assert _serialized(our_copy) == _reference_bytes(their_copy)


@pytest.mark.parametrize("build", [b for _, b in ACTIONS], ids=ACTION_IDS)
def test_action_reparse_round_trip(build):
    """Parsing our own bytes reproduces the object we serialized."""
    ours = build(parser)
    wire = _serialized(ours)
    parsed = base.OFPAction.parser(wire, 0)
    assert parsed.to_jsondict() == ours.to_jsondict()
    assert _serialized(parsed) == wire


@pytest.mark.parametrize(
    "name", ["NXActionCT", "NXActionCTClear", "NXActionNAT", "NXActionUnknown"]
)
def test_constructor_signature_matches_reference(name):
    """A drop-in replacement keeps os-ken's parameter names, order and defaults.

    The abstract ``NXAction`` is excluded: os-ken writes a no-argument
    ``__init__`` on it, while here it inherits the experimenter constructor.
    """
    assert inspect.signature(getattr(parser, name).__init__) == inspect.signature(
        getattr(ref, name).__init__
    )


def test_ct_zone_src_as_int():
    """A numeric zone_src is packed raw, as os-ken packs it."""
    ours = parser.NXActionCT(1, 0x00010204, 5, 4, 0, [])
    theirs = ref.NXActionCT(1, 0x00010204, 5, 4, 0, [])
    assert _serialized(ours) == _reference_bytes(theirs)


def test_unknown_subtype_parses_as_unknown():
    """A Nicira action with an unregistered subtype keeps its body."""
    wire = _serialized(parser.NXActionCTClear())
    wire = wire[:8] + b"\x00\xfe" + wire[10:]
    ours = base.OFPAction.parser(wire, 0)
    theirs = ref.OFPAction.parser(wire, 0)
    assert isinstance(ours, parser.NXActionUnknown)
    assert ours.to_jsondict() == theirs.to_jsondict()
    assert str(ours) == str(theirs)
    assert _serialized(ours) == _serialized(theirs)


def test_unknown_action_without_data():
    """An unknown action with no body serializes to the bare header."""
    ours = parser.NXActionUnknown(0xFE)
    theirs = ref.NXActionUnknown(0xFE)
    assert _serialized(ours) == _reference_bytes(theirs)
    assert ours.to_jsondict() == theirs.to_jsondict()


def test_foreign_experimenter_action_unchanged():
    """A non-Nicira experimenter action still parses as the plain class."""
    action = parser.OFPActionExperimenter(0x00ABCDEF)
    action.len = 8
    wire = _serialized(action)
    parsed = base.OFPAction.parser(wire, 0)
    assert parsed.__class__ is parser.OFPActionExperimenter
    assert (parsed.experimenter, parsed.type, parsed.len) == (0x00ABCDEF, 0xFFFF, 8)


def test_duplicate_subtype_rejected():
    """A subtype may only be claimed once."""
    with pytest.raises(TypeError, match="already registered"):

        @nx._nx_action  # pylint: disable=protected-access
        class _Duplicate(nx.NXActionCTClear):
            pass


# One representative value and mask per type descriptor.
_SAMPLES = {
    MacAddr: ("0e:00:00:00:00:01", "ff:ff:ff:00:00:00"),
    IPv4Addr: ("10.1.12.3", "255.255.0.0"),
    IPv6Addr: ("2001:db8::1", "ffff:ffff::"),
}


def _sample(desc):
    """Return ``(plain, masked)`` user values exercising every byte of a field."""
    if desc in _SAMPLES:
        value, mask = _SAMPLES[desc]
        return value, (value, mask)
    assert isinstance(desc, IntDescr)
    value = int.from_bytes(bytes(range(1, desc.size + 1)), "big")
    return value, (value, (1 << (desc.size * 8)) - 1)


FIELDS = [(f.name, f.type) for f in nx.oxm_types]
FIELD_IDS = [name for name, _ in FIELDS]


@pytest.mark.parametrize("name, desc", FIELDS, ids=FIELD_IDS)
def test_oxm_field_matches_reference(name, desc):
    """Every NXM field encodes and decodes byte identically to os-ken's."""
    for value in _sample(desc):
        ours = oxm.oxm_from_user(name, value)
        assert ours == ref_ofp.oxm_from_user(name, value)
        num, packed, mask = ours

        our_buf, ref_buf = bytearray(), bytearray()
        our_len = oxm.oxm_serialize(num, packed, mask, our_buf, 0)
        ref_len = ref_ofp.oxm_serialize(num, packed, mask, ref_buf, 0)
        assert (bytes(our_buf), our_len) == (bytes(ref_buf), ref_len)

        assert oxm.oxm_parse(bytes(our_buf), 0) == ref_ofp.oxm_parse(bytes(ref_buf), 0)
        parsed = oxm.oxm_parse(bytes(our_buf), 0)
        assert oxm.oxm_to_user(*parsed[:3]) == ref_ofp.oxm_to_user(*parsed[:3])
        assert oxm.oxm_normalize_user(name, value) == ref_ofp.oxm_normalize_user(
            name, value
        )

        our_hdr, ref_hdr = bytearray(), bytearray()
        assert oxm.oxm_serialize_header(
            num, our_hdr, 0
        ) == ref_ofp.oxm_serialize_header(num, ref_hdr, 0)
        assert bytes(our_hdr) == bytes(ref_hdr)
        assert oxm.oxm_parse_header(bytes(our_hdr), 0) == ref_ofp.oxm_parse_header(
            bytes(ref_hdr), 0
        )
        assert oxm.oxm_from_user_header(name) == ref_ofp.oxm_from_user_header(name)
        assert oxm.oxm_to_user_header(num) == ref_ofp.oxm_to_user_header(num)


CT_MATCHES = [
    {"ct_state": (0x21, 0x21)},
    {"ct_zone": 5},
    {"ct_mark": (0xABCD, 0xFFFF)},
    {"ct_label": (1 << 100, (1 << 128) - 1)},
    {"eth_type_nxm": 0x800, "ip_proto_nxm": 6, "nw_ttl": 64},
    {"eth_type": 0x800, "ct_state": 0x21, "ct_zone": 1},
]


@pytest.mark.parametrize("fields", CT_MATCHES, ids=[str(sorted(m)) for m in CT_MATCHES])
def test_match_with_nx_fields(fields):
    """A match over NXM fields is byte identical to os-ken's."""
    ours, theirs = parser.OFPMatch(**fields), ref.OFPMatch(**fields)
    our_buf, ref_buf = bytearray(), bytearray()
    assert ours.serialize(our_buf, 0) == theirs.serialize(ref_buf, 0)
    assert bytes(our_buf) == bytes(ref_buf)
    assert str(ours) == str(theirs)
    assert (
        parser.OFPMatch.parser(bytes(our_buf), 0).to_jsondict()
        == ref.OFPMatch.parser(bytes(ref_buf), 0).to_jsondict()
    )

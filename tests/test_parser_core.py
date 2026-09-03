"""Differential tests: match, actions and instructions vs os-ken."""

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

import os_ken.ofproto.ofproto_v1_3 as ref_ofp
import os_ken.ofproto.ofproto_v1_3_parser as ref
import pytest

from c65of.ofproto import consts, parser

MATCHES = [
    {},
    {"in_port": 1},
    {"eth_type": 0x800, "ipv4_dst": "10.0.0.0/8"},
    {"eth_type": 0x800, "ip_proto": 6, "tcp_dst": 443},
    {"vlan_vid": (0x1000, 0x1000), "eth_dst": "0e:00:00:00:00:01"},
    {"eth_type": 0x86DD, "ipv6_src": "2001:db8::/32", "icmpv6_type": 135},
    {"metadata": (0xFF00, 0xFF00), "tunnel_id": 0xDEADBEEF},
]

# (class name, positional args, keyword args)
ACTIONS = [
    ("OFPActionOutput", (4294967293,), {}),
    ("OFPActionOutput", (1, 128), {}),
    ("OFPActionCopyTtlOut", (), {}),
    ("OFPActionCopyTtlIn", (), {}),
    ("OFPActionSetMplsTtl", (64,), {}),
    ("OFPActionDecMplsTtl", (), {}),
    ("OFPActionPushVlan", (), {}),
    ("OFPActionPushVlan", (0x88A8,), {}),
    ("OFPActionPopVlan", (), {}),
    ("OFPActionPushMpls", (), {}),
    ("OFPActionPopMpls", (), {}),
    ("OFPActionSetQueue", (7,), {}),
    ("OFPActionGroup", (99,), {}),
    ("OFPActionSetNwTtl", (32,), {}),
    ("OFPActionDecNwTtl", (), {}),
    ("OFPActionPushPbb", (0x88E7,), {}),
    ("OFPActionPopPbb", (), {}),
    ("OFPActionSetField", (), {"eth_dst": "0e:00:00:00:00:01"}),
    ("OFPActionSetField", (), {"vlan_vid": 0x1064}),
    ("OFPActionSetField", (), {"ipv6_src": "fe80::1"}),
    ("OFPActionSetField", (), {"ipv4_dst": "10.0.0.1"}),
    ("OFPActionSetField", (), {"in_port": 7}),
]

INSTRUCTIONS = [
    ("OFPInstructionGotoTable", (5,), {}),
    ("OFPInstructionWriteMetadata", (0xABCD, 0xFFFF), {}),
    ("OFPInstructionMeter", (3,), {}),
]

ACTION_IDS = ["%s%s%s" % (n, a, k) for n, a, k in ACTIONS]
INSTRUCTION_IDS = [n for n, _, _ in INSTRUCTIONS]


def _serialized(obj):
    buf = bytearray()
    obj.serialize(buf, 0)
    return bytes(buf)


@pytest.mark.parametrize("fields", MATCHES, ids=[str(sorted(m)) for m in MATCHES])
def test_match_matches_reference(fields):
    """A match serializes, parses and stringifies exactly as os-ken's does."""
    ours, theirs = parser.OFPMatch(**fields), ref.OFPMatch(**fields)
    our_buf, ref_buf = bytearray(), bytearray()
    assert ours.serialize(our_buf, 0) == theirs.serialize(ref_buf, 0)
    assert bytes(our_buf) == bytes(ref_buf)
    assert ours.to_jsondict() == theirs.to_jsondict()
    assert str(ours) == str(theirs)
    assert dict(ours.items()) == dict(theirs.items())

    parsed = parser.OFPMatch.parser(bytes(our_buf), 0)
    assert parsed.to_jsondict() == ref.OFPMatch.parser(bytes(ref_buf), 0).to_jsondict()
    assert (
        parser.OFPMatch.from_jsondict(ours.to_jsondict()["OFPMatch"]).to_jsondict()
        == ref.OFPMatch.from_jsondict(theirs.to_jsondict()["OFPMatch"]).to_jsondict()
    )


def test_match_lookup():
    """A match reads back like a mapping."""
    match = parser.OFPMatch(eth_type=0x800, ipv4_dst="10.0.0.1")
    assert match["eth_type"] == 0x800
    assert "ipv4_dst" in match
    assert "in_port" not in match
    assert match.get("in_port") is None
    assert match.get("in_port", 3) == 3
    assert dict(match.iteritems()) == {"eth_type": 0x800, "ipv4_dst": "10.0.0.1"}


@pytest.mark.parametrize("name, args, kwargs", ACTIONS, ids=ACTION_IDS)
def test_action_matches_reference(name, args, kwargs):
    """An action serializes, parses and stringifies exactly as os-ken's does."""
    ours = getattr(parser, name)(*args, **kwargs)
    theirs = getattr(ref, name)(*args, **kwargs)
    assert ours.len == theirs.len
    our_bytes, ref_bytes = _serialized(ours), _serialized(theirs)
    assert our_bytes == ref_bytes
    assert ours.to_jsondict() == theirs.to_jsondict()
    assert str(ours) == str(theirs)
    assert (
        parser.OFPAction.parser(our_bytes, 0).to_jsondict()
        == ref.OFPAction.parser(ref_bytes, 0).to_jsondict()
    )


@pytest.mark.parametrize("name, args, kwargs", INSTRUCTIONS, ids=INSTRUCTION_IDS)
def test_instruction_matches_reference(name, args, kwargs):
    """An instruction serializes, parses and stringifies as os-ken's does."""
    ours = getattr(parser, name)(*args, **kwargs)
    theirs = getattr(ref, name)(*args, **kwargs)
    our_bytes, ref_bytes = _serialized(ours), _serialized(theirs)
    assert our_bytes == ref_bytes
    assert ours.to_jsondict() == theirs.to_jsondict()
    assert str(ours) == str(theirs)
    assert (
        parser.OFPInstruction.parser(our_bytes, 0).to_jsondict()
        == ref.OFPInstruction.parser(ref_bytes, 0).to_jsondict()
    )


@pytest.mark.parametrize(
    "inst_type",
    [
        consts.OFPIT_APPLY_ACTIONS,
        consts.OFPIT_WRITE_ACTIONS,
        consts.OFPIT_CLEAR_ACTIONS,
    ],
)
def test_instruction_actions_matches_reference(inst_type):
    """An action list instruction round trips for each of its three types."""
    ours = parser.OFPInstructionActions(
        inst_type,
        [
            parser.OFPActionPopVlan(),
            parser.OFPActionSetField(eth_dst="0e:00:00:00:00:01"),
            parser.OFPActionOutput(1, 65535),
        ],
    )
    theirs = ref.OFPInstructionActions(
        inst_type,
        [
            ref.OFPActionPopVlan(),
            ref.OFPActionSetField(eth_dst="0e:00:00:00:00:01"),
            ref.OFPActionOutput(1, 65535),
        ],
    )
    our_bytes, ref_bytes = _serialized(ours), _serialized(theirs)
    assert our_bytes == ref_bytes
    assert ours.to_jsondict() == theirs.to_jsondict()
    assert str(ours) == str(theirs)
    assert (
        parser.OFPInstruction.parser(our_bytes, 0).to_jsondict()
        == ref.OFPInstruction.parser(ref_bytes, 0).to_jsondict()
    )


def test_instruction_actions_defaults_to_empty():
    """An action list instruction with no actions is not None-valued."""
    # pylint: disable=use-implicit-booleaness-not-comparison
    assert (
        parser.OFPInstructionActions(ref_ofp.OFPIT_APPLY_ACTIONS).actions == []
    )  # noqa


def test_unknown_action_type_rejected():
    """An unregistered action type is an error, not a silent skip."""
    with pytest.raises(ValueError, match="unknown action type"):
        parser.OFPAction.parser(b"\x00\x99\x00\x08\x00\x00\x00\x00", 0)


def test_round_up():
    """Padding arithmetic is exact at and around the boundary."""
    assert [parser.round_up(n, 8) for n in (0, 1, 8, 9, 16)] == [0, 8, 8, 16, 16]

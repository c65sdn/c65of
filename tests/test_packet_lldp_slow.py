"""Differential tests: lldp, slow and bpdu must behave exactly like os-ken's."""

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

import pytest
from os_ken.lib.packet import bpdu as ref_bpdu
from os_ken.lib.packet import ethernet as ref_ethernet
from os_ken.lib.packet import lldp as ref_lldp
from os_ken.lib.packet import packet as ref_packet
from os_ken.lib.packet import slow as ref_slow

from c65of.packet import bpdu, ethernet, lldp, packet, slow
from c65of.packet import ether_types as ether
from c65of.packet.packet_base import ETHERTYPES

# One case per TLV class, in the order an LLDPDU carries them.
FRAME_CASES = [
    ("ChassisID", {"subtype": 4, "chassis_id": b"\x0e\x00\x00\x00\x00\x01"}),
    ("PortID", {"subtype": 5, "port_id": b"eth0"}),
    ("TTL", {"ttl": 120}),
    ("PortDescription", {"port_description": b"port one"}),
    ("SystemName", {"system_name": b"faucet-1"}),
    ("SystemDescription", {"system_description": b"c65of switch"}),
    ("SystemCapabilities", {"system_cap": 0x04, "enabled_cap": 0x10}),
    (
        "ManagementAddress",
        {
            "addr_subtype": 1,
            "addr": b"\x0a\x00\x00\x01",
            "intf_subtype": 2,
            "intf_num": 3,
            "oid": b"\x01\x02",
        },
    ),
    (
        "OrganizationallySpecific",
        {"oui": b"\x00\x01\x02", "subtype": 1, "info": b"xyz"},
    ),
    ("End", {}),
]

# Further values exercising the edges of each encoding.
TLV_CASES = FRAME_CASES + [
    ("ChassisID", {"subtype": 7, "chassis_id": b"s" * 255}),
    ("PortID", {"subtype": 3, "port_id": b"\x00\x11\x22\x33\x44\x55"}),
    ("TTL", {"ttl": 0}),
    ("TTL", {"ttl": 0xFFFF}),
    ("PortDescription", {"port_description": b""}),
    ("SystemName", {"system_name": b"n" * 255}),
    ("SystemDescription", {"system_description": b""}),
    ("SystemCapabilities", {"system_cap": 0xFFFF, "enabled_cap": 0}),
    (
        "ManagementAddress",
        {
            "addr_subtype": 2,
            "addr": b"\x20\x01" * 8,
            "intf_subtype": 3,
            "intf_num": 0xFFFFFFFF,
            "oid": b"",
        },
    ),
    ("OrganizationallySpecific", {"oui": b"\x0e\x00\x00", "subtype": 255, "info": b""}),
]

TLV_IDS = ["%s-%d" % (name, i) for i, (name, _) in enumerate(TLV_CASES)]

# The text TLVs name their field with a property, which os-ken's JSON dict form
# drops, so a round trip through it cannot rebuild them.
NO_ROUNDTRIP = ("PortDescription", "SystemName", "SystemDescription")

LACP_CASES = [
    {},
    {
        "version": 1,
        "actor_system_priority": 65535,
        "actor_system": "11:22:33:44:55:66",
        "actor_key": 1,
        "actor_port_priority": 2,
        "actor_port": 3,
        "actor_state_activity": 1,
        "actor_state_timeout": 1,
        "actor_state_aggregation": 0,
        "actor_state_synchronization": 1,
        "actor_state_collecting": 0,
        "actor_state_distributing": 1,
        "actor_state_defaulted": 0,
        "actor_state_expired": 1,
        "partner_system_priority": 100,
        "partner_system": "aa:bb:cc:dd:ee:ff",
        "partner_key": 4,
        "partner_port_priority": 5,
        "partner_port": 6,
        "partner_state_activity": 0,
        "partner_state_timeout": 1,
        "partner_state_aggregation": 1,
        "partner_state_synchronization": 0,
        "partner_state_collecting": 1,
        "partner_state_distributing": 0,
        "partner_state_defaulted": 1,
        "partner_state_expired": 0,
        "collector_max_delay": 7,
    },
    dict(
        {
            "%s_state_%s" % (role, flag): 1
            for role in ("actor", "partner")
            for flag in (
                "activity",
                "timeout",
                "aggregation",
                "synchronization",
                "collecting",
                "distributing",
                "defaulted",
                "expired",
            )
        },
        actor_system="ff:ff:ff:ff:ff:ff",
        partner_system="00:00:00:00:00:01",
        actor_key=0xFFFF,
        partner_key=0xFFFF,
        actor_port=0xFFFF,
        partner_port=0xFFFF,
        collector_max_delay=0xFFFF,
    ),
]

LACP_IDS = ["defaults", "mixed", "all-set"]


def public(name):
    """True for the name of a public constant."""
    return name.isupper() and not name.startswith("_")


def build(module, name, kwargs):
    """Instantiate ``name`` from ``module`` with ``kwargs``."""
    return getattr(module, name)(**kwargs)


def roundtrip(obj):
    """``from_jsondict(to_jsondict())`` of ``obj``."""
    return type(obj).from_jsondict(obj.to_jsondict()[type(obj).__name__])


@pytest.mark.parametrize("name,kwargs", TLV_CASES, ids=TLV_IDS)
def test_tlv_serialize(name, kwargs):
    """A constructed TLV encodes to the same bytes as os-ken's."""
    assert (
        build(lldp, name, kwargs).serialize()
        == build(ref_lldp, name, kwargs).serialize()
    )


@pytest.mark.parametrize("name,kwargs", TLV_CASES, ids=TLV_IDS)
def test_tlv_attrs_and_jsondict(name, kwargs):
    """A constructed TLV holds and stringifies the same attributes."""
    tlv = build(lldp, name, kwargs)
    ref = build(ref_lldp, name, kwargs)
    assert vars(tlv) == vars(ref)
    assert tlv.to_jsondict() == ref.to_jsondict()


@pytest.mark.parametrize("name,kwargs", TLV_CASES, ids=TLV_IDS)
def test_tlv_parse(name, kwargs):
    """A TLV decoded from bytes os-ken produced matches os-ken's decoding."""
    buf = bytes(build(ref_lldp, name, kwargs).serialize())
    tlv = getattr(lldp, name)(buf)
    ref = getattr(ref_lldp, name)(buf)
    assert vars(tlv) == vars(ref)
    assert tlv.to_jsondict() == ref.to_jsondict()
    assert tlv.serialize() == ref.serialize()
    assert lldp.LLDPBasicTLV.get_type(buf) == ref_lldp.LLDPBasicTLV.get_type(buf)


@pytest.mark.parametrize("name,kwargs", TLV_CASES, ids=TLV_IDS)
def test_tlv_jsondict_roundtrip(name, kwargs):
    """A JSON dict round trip rebuilds the TLV, or fails as os-ken's does."""
    tlv = build(lldp, name, kwargs)
    ref = build(ref_lldp, name, kwargs)
    if name in NO_ROUNDTRIP:
        with pytest.raises(KeyError):
            roundtrip(ref)
        with pytest.raises(KeyError):
            roundtrip(tlv)
        return
    assert vars(roundtrip(tlv)) == vars(roundtrip(ref))
    assert roundtrip(tlv).to_jsondict() == tlv.to_jsondict()


@pytest.mark.parametrize(
    "name,kwargs",
    [
        ("ChassisID", {"subtype": 1, "chassis_id": b""}),
        ("PortID", {"subtype": 1, "port_id": b""}),
        ("SystemName", {"system_name": b"n" * 256}),
        (
            "OrganizationallySpecific",
            {"oui": b"\x00" * 3, "subtype": 0, "info": b"i" * 508},
        ),
        (
            "ManagementAddress",
            {
                "addr_subtype": 1,
                "addr": b"\x0a\x00\x00\x01",
                "intf_subtype": 2,
                "intf_num": 3,
                "oid": b"o" * 129,
            },
        ),
    ],
)
def test_tlv_length_rejected(name, kwargs):
    """A TLV whose information string is out of range is rejected, as os-ken's."""
    with pytest.raises(AssertionError):
        build(ref_lldp, name, kwargs)
    with pytest.raises(AssertionError):
        build(lldp, name, kwargs)


def test_tlv_type_registry():
    """Each TLV class registers under the type os-ken gives it."""
    for name, _ in FRAME_CASES:
        tlv_type = getattr(ref_lldp, name).tlv_type
        assert getattr(lldp, name).tlv_type == tlv_type
        assert lldp.lldp.get_type(tlv_type) is getattr(lldp, name)
        assert ref_lldp.lldp.get_type(tlv_type) is getattr(ref_lldp, name)


def lldpdu(module):
    """An LLDPDU carrying one of every TLV class, built from ``module``."""
    return module.lldp([build(module, name, kwargs) for name, kwargs in FRAME_CASES])


def test_lldp_serialize():
    """An LLDPDU of every TLV class encodes to the same bytes as os-ken's."""
    pkt = lldpdu(lldp)
    ref = lldpdu(ref_lldp)
    assert bytes(pkt.serialize(None, None)) == bytes(ref.serialize(None, None))
    assert len(pkt) == len(ref)
    assert pkt.to_jsondict() == ref.to_jsondict()


def test_lldp_parse():
    """An LLDPDU decoded from bytes os-ken produced matches TLV by TLV."""
    buf = bytes(lldpdu(ref_lldp).serialize(None, None))
    pkt, next_cls, rest = lldp.lldp.parser(buf)
    ref, ref_next, ref_rest = ref_lldp.lldp.parser(buf)
    assert (next_cls, bytes(rest)) == (ref_next, bytes(ref_rest))
    assert len(pkt.tlvs) == len(ref.tlvs)
    for tlv, ref_tlv in zip(pkt.tlvs, ref.tlvs):
        assert type(tlv).__name__ == type(ref_tlv).__name__
        assert vars(tlv) == vars(ref_tlv)
    assert pkt.to_jsondict() == ref.to_jsondict()
    assert len(pkt) == len(ref)


def test_lldp_jsondict_roundtrip():
    """An LLDPDU of round trippable TLVs survives a JSON dict round trip."""
    tlvs = [c for c in FRAME_CASES if c[0] not in NO_ROUNDTRIP]
    pkt = lldp.lldp([build(lldp, name, kwargs) for name, kwargs in tlvs])
    ref = ref_lldp.lldp([build(ref_lldp, name, kwargs) for name, kwargs in tlvs])
    assert roundtrip(pkt).to_jsondict() == roundtrip(ref).to_jsondict()
    assert roundtrip(pkt).to_jsondict() == pkt.to_jsondict()


BAD_LLDPDUS = [
    b"",
    b"\x02",
    b"\x02\xff",
    b"\x40\x02\x00\x00",
    bytes(lldpdu(ref_lldp).serialize(None, None))[:-2],
    bytes(
        ref_lldp.lldp(
            [
                build(ref_lldp, "TTL", {"ttl": 1}),
                build(ref_lldp, "PortID", {"subtype": 5, "port_id": b"eth0"}),
                build(ref_lldp, "ChassisID", {"subtype": 7, "chassis_id": b"sw1"}),
                build(ref_lldp, "End", {}),
            ]
        ).serialize(None, None)
    ),
    b"\x02\x03abc\x04\x02\x05x\x06\x02\x00\x78",
]


@pytest.mark.parametrize("buf", BAD_LLDPDUS, ids=range(len(BAD_LLDPDUS)))
def test_lldp_parse_rejects(buf):
    """Bytes that are not an LLDPDU are rejected the way os-ken rejects them."""
    assert lldp.lldp.parser(buf) == ref_lldp.lldp.parser(buf)
    assert lldp.lldp.parser(buf)[0] is None


@pytest.mark.parametrize("kwargs", LACP_CASES, ids=LACP_IDS)
def test_lacp_serialize(kwargs):
    """A LACPDU encodes to the same bytes as os-ken's."""
    pkt = slow.lacp(**kwargs)
    ref = ref_slow.lacp(**kwargs)
    assert bytes(pkt.serialize(None, None)) == bytes(ref.serialize(None, None))
    assert len(pkt) == len(ref) == 110
    assert vars(pkt) == vars(ref)
    assert pkt.to_jsondict() == ref.to_jsondict()


@pytest.mark.parametrize("kwargs", LACP_CASES, ids=LACP_IDS)
def test_lacp_parse(kwargs):
    """A LACPDU decoded from bytes os-ken produced matches attribute by attribute."""
    buf = bytes(ref_slow.lacp(**kwargs).serialize(None, None))
    pkt, next_cls, rest = slow.lacp.parser(buf)
    ref, ref_next, ref_rest = ref_slow.lacp.parser(buf)
    assert (next_cls, bytes(rest)) == (ref_next, bytes(ref_rest))
    assert vars(pkt) == vars(ref)
    assert pkt.to_jsondict() == ref.to_jsondict()
    assert bytes(pkt.serialize(None, None)) == buf


@pytest.mark.parametrize("kwargs", LACP_CASES, ids=LACP_IDS)
def test_lacp_jsondict_roundtrip(kwargs):
    """A LACPDU survives a JSON dict round trip, as os-ken's does."""
    pkt = slow.lacp(**kwargs)
    assert vars(roundtrip(pkt)) == vars(roundtrip(ref_slow.lacp(**kwargs)))
    assert roundtrip(pkt).to_jsondict() == pkt.to_jsondict()


@pytest.mark.parametrize("kwargs", LACP_CASES, ids=LACP_IDS)
def test_slow_dispatches_lacp(kwargs):
    """The slow dispatcher hands a LACP subtype to the LACP parser."""
    buf = bytes(ref_slow.lacp(**kwargs).serialize(None, None))
    pkt, next_cls, rest = slow.slow.parser(buf)
    ref, ref_next, ref_rest = ref_slow.slow.parser(buf)
    assert type(pkt).__name__ == type(ref).__name__ == "lacp"
    assert (next_cls, bytes(rest)) == (ref_next, bytes(ref_rest))
    assert vars(pkt) == vars(ref)


@pytest.mark.parametrize(
    "subtype",
    [
        0x00,
        ref_slow.SLOW_SUBTYPE_MARKER,
        ref_slow.SLOW_SUBTYPE_OAM,
        ref_slow.SLOW_SUBTYPE_OSSP,
    ],
)
def test_slow_undecoded_subtype(subtype):
    """A subtype with no parser is left undecoded, as in os-ken."""
    buf = bytes([subtype]) + b"\x00" * (len(slow.lacp()) - 1)
    assert slow.slow.parser(buf) == ref_slow.slow.parser(buf) == (None, None, buf)


def test_lacp_rejects_wrong_length():
    """A LACPDU that is not exactly 110 octets is rejected, as in os-ken."""
    for bad in (b"\x01\x01", b"\x01\x01" + b"\x00" * 200):
        with pytest.raises(AssertionError):
            ref_slow.slow.parser(bad)
        with pytest.raises(AssertionError):
            slow.slow.parser(bad)


@pytest.mark.parametrize(
    "index,value",
    [
        (0, 2),
        (1, 2),
        (2, 9),
        (3, 19),
        (22, 9),
        (23, 19),
        (42, 9),
        (43, 15),
        (58, 9),
        (59, 1),
    ],
)
def test_lacp_rejects_corrupt_field(index, value):
    """A LACPDU with a wrong fixed subtype, version, tag or length is rejected."""
    buf = bytearray(ref_slow.lacp().serialize(None, None))
    buf[index] = value
    buf = bytes(buf)
    with pytest.raises(AssertionError):
        ref_slow.lacp.parser(buf)
    with pytest.raises(AssertionError):
        slow.lacp.parser(buf)


def test_lacp_rejects_bad_state_bit():
    """A state field that is not a single bit is rejected, as in os-ken."""
    with pytest.raises(AssertionError):
        ref_slow.lacp(actor_state_activity=2)
    with pytest.raises(AssertionError):
        slow.lacp(actor_state_activity=2)


def frame(eth_mod, packet_mod, payload):
    """An ethernet frame carrying ``payload``, serialized."""
    pkt = packet_mod.Packet()
    pkt.add_protocol(
        eth_mod.ethernet(
            dst=lldp.LLDP_MAC_NEAREST_BRIDGE,
            src="0e:00:00:00:00:01",
            ethertype=ether.ETH_TYPE_LLDP,
        )
    )
    pkt.add_protocol(payload)
    pkt.serialize()
    return bytes(pkt.data)


def test_ethertype_registration():
    """lldp and slow are registered under the ethertypes os-ken uses."""
    assert ETHERTYPES[ether.ETH_TYPE_LLDP] is lldp.lldp
    assert ETHERTYPES[ether.ETH_TYPE_SLOW] is slow.slow
    assert ref_ethernet.ethernet.get_packet_type(ether.ETH_TYPE_LLDP) is ref_lldp.lldp
    assert ref_ethernet.ethernet.get_packet_type(ether.ETH_TYPE_SLOW) is ref_slow.slow


def test_lldp_frame():
    """A whole LLDP frame encodes and decodes identically to os-ken's."""
    data = frame(ethernet, packet, lldpdu(lldp))
    assert data == frame(ref_ethernet, ref_packet, lldpdu(ref_lldp))
    pkt = packet.Packet(data)
    ref = ref_packet.Packet(data)
    assert [type(p).__name__ for p in pkt] == [type(p).__name__ for p in ref]
    assert (
        pkt.get_protocol(lldp.lldp).to_jsondict()
        == ref.get_protocol(ref_lldp.lldp).to_jsondict()
    )


def test_lacp_frame():
    """A whole LACP frame decodes through the ethernet ethertype registry."""
    kwargs = LACP_CASES[1]
    pkt = packet.Packet()
    pkt.add_protocol(
        ethernet.ethernet(
            dst=slow.SLOW_PROTOCOL_MULTICAST,
            src="0e:00:00:00:00:01",
            ethertype=ether.ETH_TYPE_SLOW,
        )
    )
    pkt.add_protocol(slow.lacp(**kwargs))
    pkt.serialize()
    data = bytes(pkt.data)
    parsed = packet.Packet(data).get_protocol(slow.lacp)
    ref = ref_packet.Packet(data).get_protocol(ref_slow.lacp)
    assert vars(parsed) == vars(ref)


def test_slow_protocol_multicast():
    """The slow protocol destination address matches os-ken's."""
    assert slow.SLOW_PROTOCOL_MULTICAST == ref_slow.SLOW_PROTOCOL_MULTICAST
    assert slow.SLOW_SUBTYPE_LACP == ref_slow.SLOW_SUBTYPE_LACP
    assert slow.SLOW_SUBTYPE_MARKER == ref_slow.SLOW_SUBTYPE_MARKER
    assert slow.SLOW_SUBTYPE_OAM == ref_slow.SLOW_SUBTYPE_OAM
    assert slow.SLOW_SUBTYPE_OSSP == ref_slow.SLOW_SUBTYPE_OSSP


def test_lldp_module_constants():
    """Every public constant and TLV subtype matches os-ken's."""
    for name in dir(ref_lldp):
        ref = getattr(ref_lldp, name)
        if public(name) and isinstance(ref, (int, str)):
            assert getattr(lldp, name) == ref
    for name, _ in FRAME_CASES:
        cls, ref_cls = getattr(lldp, name), getattr(ref_lldp, name)
        subtypes = [n for n in dir(ref_cls) if n.startswith(("SUB_", "CAP_"))]
        assert subtypes == [n for n in dir(cls) if n.startswith(("SUB_", "CAP_"))]
        for subtype in subtypes:
            assert getattr(cls, subtype) == getattr(ref_cls, subtype)


def test_lacp_class_constants():
    """Every public LACP class constant matches os-ken's."""
    names = [n for n in dir(ref_slow.lacp) if public(n)]
    assert names == [n for n in dir(slow.lacp) if public(n)]
    for name in names:
        assert getattr(slow.lacp, name) == getattr(ref_slow.lacp, name)


def test_bpdu_constants():
    """Every public name in the bpdu module is os-ken's constant of that name."""
    ref = {
        name: value
        for name, value in vars(ref_bpdu).items()
        if public(name) and isinstance(value, (int, str))
    }
    ours = {name: getattr(bpdu, name) for name in dir(bpdu) if not name.startswith("_")}
    assert ours == ref
    assert bpdu.BRIDGE_GROUP_ADDRESS == ref_bpdu.BRIDGE_GROUP_ADDRESS

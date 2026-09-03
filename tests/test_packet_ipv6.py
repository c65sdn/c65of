"""Differential tests: IPv6 and ICMPv6 coding must match os-ken's byte for byte."""

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

import os_ken.lib.packet.icmpv6 as ref_icmpv6
import os_ken.lib.packet.ipv6 as ref_ipv6
import os_ken.lib.packet.packet as ref_packet
import pytest

from c65of.packet import ether_types as ether
from c65of.packet import icmpv6, ipv6, packet_utils
from c65of.packet.ethernet import ethernet
from c65of.packet.packet import Packet

# The icmpv6 module is searched first: os-ken's ipv6 module holds the icmpv6
# module under that name, while both icmpv6 modules hold the icmpv6 class.
C65OF = (icmpv6, ipv6)
OSKEN = (ref_icmpv6, ref_ipv6)

SRC = "fe80::200:ff:fe00:1"
DST = "ff02::1:ff00:2"


class Obj:
    """A constructor call replayed against either implementation."""

    def __init__(self, name, *args, **kwargs):
        self.name = name
        self.args = args
        self.kwargs = kwargs

    def __str__(self):
        parts = [str(a) for a in self.args]
        parts += ["%s=%s" % (k, v) for k, v in self.kwargs.items()]
        return "%s(%s)" % (self.name, ",".join(parts))

    __repr__ = __str__


def build(mods, value):
    """Instantiate ``value`` using the classes of ``mods``."""
    if isinstance(value, Obj):
        cls = next(
            c
            for c in (getattr(mod, value.name, None) for mod in mods)
            if isinstance(c, type)
        )
        return cls(
            *[build(mods, a) for a in value.args],
            **{k: build(mods, v) for k, v in value.kwargs.items()}
        )
    if isinstance(value, list):
        return [build(mods, v) for v in value]
    return value


def attrs(obj):
    """The attribute view compared across implementations."""
    ((_, fields),) = obj.to_jsondict().items()
    return fields


def restore(mods, name, fields):
    """What ``from_jsondict`` yields, or the name of the exception it raises."""
    cls = next(
        c for c in (getattr(mod, name, None) for mod in mods) if isinstance(c, type)
    )
    try:
        return attrs(cls.from_jsondict(fields))
    except TypeError as err:
        return type(err).__name__


SLA = Obj("nd_option_sla", hw_src="00:11:22:33:44:55")
TLA = Obj("nd_option_tla", 0, "0e:00:00:00:00:04", b"\x01\x02")
PI = Obj("nd_option_pi", 0, 64, 3, 0xFFFFFFFF, 0x1234, 0, "2001:db8::")
MTU = Obj("nd_option_mtu", 9000)

ND_OPTIONS = [
    SLA,
    Obj("nd_option_sla", 2, "00:11:22:33:44:55", b"\x66\x77" + b"\x00" * 6),
    TLA,
    Obj("nd_option_tla", 1, "0e:00:00:00:00:04"),
    PI,
    Obj("nd_option_pi", 4, 0, 0, 0, 0, 0, "::"),
    MTU,
]

EXT_HEADERS = [
    Obj("hop_opts", 58, 0, [Obj("option", 5, 2, b"\x00\x00"), Obj("option", 1, 0)]),
    Obj(
        "hop_opts",
        58,
        0,
        [Obj("option", 5, 2, b"\x00\x00"), Obj("option"), Obj("option")],
    ),
    Obj(
        "dst_opts",
        58,
        8,
        [Obj("option", 1, 4, b"\x00" * 4), Obj("option", 1, 6, b"\x00" * 6)],
    ),
    Obj("dst_opts", 58),
    Obj("fragment", 58, 0, 0, 0),
    Obj("fragment", 58, 8191, 1, 0xDEADBEEF),
    Obj("auth", 58, 4, 0x1234, 0x5678, b"\xa5" * 12),
    Obj("auth"),
    Obj("routing_type3", 58, 0, 3, 2, 0, 0, ["2001:db8::1", "2001:db8::2"]),
    Obj("routing_type3", 58, 0, 3, 1, 8, 8, ["2001:db8::1", "2001:db8::2"]),
    Obj("routing_type3", 58, 0, 3, 0, 0, 0, []),
    Obj("routing_type3", 58, 4, 3, 2, 0, 0, ["2001:db8::1", "2001:db8::2"]),
]

IPV6_CASES = [
    Obj("ipv6"),
    Obj("ipv6", 6, 0xFF, 0xFFFFF, 0, 58, 64, SRC, DST),
    Obj("ipv6", 6, 1, 2, 24, 58, 255, SRC, DST),
    Obj(
        "ipv6",
        6,
        0,
        0,
        0,
        0,
        64,
        SRC,
        DST,
        [EXT_HEADERS[0], Obj("fragment", 58, 1, 0, 7)],
    ),
] + [
    Obj("ipv6", 6, 0, 0, 0, nxt, 64, SRC, DST, [hdr])
    for nxt, hdr in zip([0, 0, 60, 60, 44, 44, 51, 51, 43, 43, 43], EXT_HEADERS)
]

ICMPV6_CASES = [
    Obj("icmpv6"),
    Obj("icmpv6", icmpv6.ICMPV6_TIME_EXCEEDED, 0, 0, b"\x00" * 8),
    Obj("icmpv6", icmpv6.ICMPV6_DST_UNREACH, 3, 0x1234, b"\xff" * 12),
    Obj("icmpv6", icmpv6.ICMPV6_PACKET_TOO_BIG, 0, 0, b"\x00\x00\x05\xdc"),
    Obj("icmpv6", icmpv6.ICMPV6_PARAM_PROB, 1, 0, b"\x00" * 4),
    Obj("icmpv6", icmpv6.ICMPV6_ECHO_REQUEST, 0, 0, Obj("echo", 1, 2, b"hello")),
    Obj("icmpv6", icmpv6.ICMPV6_ECHO_REPLY, 0, 0, Obj("echo")),
    Obj(
        "icmpv6",
        icmpv6.ND_NEIGHBOR_SOLICIT,
        0,
        0,
        Obj("nd_neighbor", 0, DST, SLA),
    ),
    Obj(
        "icmpv6",
        icmpv6.ND_NEIGHBOR_ADVERT,
        0,
        0,
        Obj("nd_neighbor", 7, SRC, TLA),
    ),
    Obj("icmpv6", icmpv6.ND_NEIGHBOR_ADVERT, 0, 0, Obj("nd_neighbor", 1, SRC)),
    Obj(
        "icmpv6",
        icmpv6.ND_NEIGHBOR_SOLICIT,
        0,
        0,
        Obj("nd_neighbor", 0, DST, b"\x09\x01" + b"\x00" * 6),
    ),
    Obj("icmpv6", icmpv6.ND_ROUTER_SOLICIT, 0, 0, Obj("nd_router_solicit", 0, SLA)),
    Obj("icmpv6", icmpv6.ND_ROUTER_SOLICIT, 0, 0, Obj("nd_router_solicit")),
    Obj(
        "icmpv6",
        icmpv6.ND_ROUTER_ADVERT,
        0,
        0,
        Obj("nd_router_advert", 64, 3, 1800, 10, 20, [PI, SLA]),
    ),
    Obj("icmpv6", icmpv6.ND_ROUTER_ADVERT, 0, 0, Obj("nd_router_advert")),
    Obj(
        "icmpv6",
        icmpv6.ND_ROUTER_ADVERT,
        0,
        0,
        Obj("nd_router_advert", 64, 0, 1800, 0, 0, [b"\x09\x01" + b"\x00" * 6]),
    ),
    Obj("icmpv6", icmpv6.MLD_LISTENER_QUERY, 0, 0, Obj("mld", 10000, "ff02::1")),
    Obj("icmpv6", icmpv6.MLD_LISTENER_DONE, 0, 0, Obj("mld")),
    Obj(
        "icmpv6",
        icmpv6.MLD_LISTENER_QUERY,
        0,
        0,
        Obj(
            "mldv2_query", 10000, "ff02::1", 1, 2, 3, 0, ["2001:db8::1", "2001:db8::2"]
        ),
    ),
    Obj(
        "icmpv6",
        icmpv6.MLDV2_LISTENER_REPORT,
        0,
        0,
        Obj(
            "mldv2_report",
            0,
            [
                Obj(
                    "mldv2_report_group",
                    icmpv6.MODE_IS_INCLUDE,
                    0,
                    0,
                    "ff02::1",
                    ["2001:db8::1"],
                    b"ab",
                ),
                Obj(
                    "mldv2_report_group", icmpv6.CHANGE_TO_EXCLUDE_MODE, 0, 0, "ff02::2"
                ),
            ],
        ),
    ),
    Obj(
        "icmpv6",
        icmpv6.MLDV2_LISTENER_REPORT,
        0,
        0,
        Obj(
            "mldv2_report",
            1,
            [
                Obj(
                    "mldv2_report_group",
                    icmpv6.ALLOW_NEW_SOURCES,
                    1,
                    2,
                    "ff02::3",
                    ["2001:db8::1", "2001:db8::2"],
                    b"abcd",
                )
            ],
        ),
    ),
]

PREV = Obj("ipv6", 6, 0, 0, 0, 58, 255, SRC, DST)


def serialized(mods, case, payload=b"", prev=None):
    """Wire bytes of ``case`` built for ``mods``."""
    obj = build(mods, case)
    return bytes(obj.serialize(bytearray(payload), prev))


@pytest.mark.parametrize("case", IPV6_CASES, ids=str)
def test_ipv6_serialize(case):
    """An IPv6 header encodes to the same bytes as os-ken's."""
    assert serialized(C65OF, case, b"payload") == serialized(OSKEN, case, b"payload")


@pytest.mark.parametrize("case", IPV6_CASES, ids=str)
def test_ipv6_to_jsondict(case):
    """An IPv6 header has the same JSON dict form as os-ken's."""
    assert build(C65OF, case).to_jsondict() == build(OSKEN, case).to_jsondict()


@pytest.mark.parametrize("case", IPV6_CASES, ids=str)
def test_ipv6_jsondict_roundtrip(case):
    """from_jsondict(to_jsondict()) restores the same IPv6 header as os-ken."""
    fields = attrs(build(C65OF, case))
    assert restore(C65OF, "ipv6", fields) == restore(OSKEN, "ipv6", fields)
    assert restore(C65OF, "ipv6", fields) == fields


@pytest.mark.parametrize("case", IPV6_CASES, ids=str)
def test_ipv6_parse(case):
    """Both implementations decode either implementation's bytes alike."""
    buf = serialized(C65OF, case, b"payload") + b"payload"
    assert buf == serialized(OSKEN, case, b"payload") + b"payload"
    ours, our_next, our_rest = ipv6.ipv6.parser(buf)
    ref, ref_next, ref_rest = ref_ipv6.ipv6.parser(buf)
    assert attrs(ours) == attrs(ref)
    assert bytes(our_rest) == bytes(ref_rest)
    if ref_next is ref_icmpv6.icmpv6:
        assert our_next is icmpv6.icmpv6
    else:
        assert our_next is None


@pytest.mark.parametrize("case", EXT_HEADERS, ids=str)
def test_ext_header(case):
    """An extension header encodes, decodes and stringifies like os-ken's."""
    ours, ref = build(C65OF, case), build(OSKEN, case)
    buf = bytes(ours.serialize())
    assert buf == bytes(ref.serialize())
    assert len(ours) == len(ref)
    assert attrs(ours) == attrs(ref)
    our_cls = type(build(C65OF, case))
    ref_cls = type(build(OSKEN, case))
    assert attrs(our_cls.parser(buf)) == attrs(ref_cls.parser(buf))
    fields = attrs(ours)
    assert restore(C65OF, case.name, fields) == restore(OSKEN, case.name, fields)


@pytest.mark.parametrize("case", ICMPV6_CASES, ids=str)
def test_icmpv6_serialize(case):
    """An ICMPv6 message encodes to the same bytes as os-ken's."""
    ours = serialized(C65OF, case, b"", build(C65OF, PREV))
    ref = serialized(OSKEN, case, b"", build(OSKEN, PREV))
    assert ours == ref


@pytest.mark.parametrize("case", ICMPV6_CASES, ids=str)
def test_icmpv6_to_jsondict(case):
    """An ICMPv6 message has the same JSON dict form as os-ken's."""
    assert build(C65OF, case).to_jsondict() == build(OSKEN, case).to_jsondict()


@pytest.mark.parametrize("case", ICMPV6_CASES, ids=str)
def test_icmpv6_jsondict_roundtrip(case):
    """from_jsondict(to_jsondict()) restores the same message as os-ken."""
    fields = attrs(build(C65OF, case))
    assert restore(C65OF, "icmpv6", fields) == restore(OSKEN, "icmpv6", fields)
    assert restore(C65OF, "icmpv6", fields) == fields


@pytest.mark.parametrize("case", ICMPV6_CASES, ids=str)
def test_icmpv6_parse(case):
    """Both implementations decode either implementation's bytes alike."""
    buf = serialized(C65OF, case, b"", build(C65OF, PREV))
    assert buf == serialized(OSKEN, case, b"", build(OSKEN, PREV))
    ours, our_next, our_rest = icmpv6.icmpv6.parser(buf)
    ref, ref_next, ref_rest = ref_icmpv6.icmpv6.parser(buf)
    assert (our_next, our_rest) == (ref_next, ref_rest)
    assert attrs(ours) == attrs(ref)
    assert len(ours) == len(ref)
    assert bytes(ours.serialize(bytearray(), build(C65OF, PREV))) == buf


@pytest.mark.parametrize("case", ICMPV6_CASES, ids=str)
def test_icmpv6_checksum(case):
    """A zero checksum is computed over the IPv6 pseudo header, as os-ken does."""
    prev = build(C65OF, PREV)
    ours = build(C65OF, case)
    buf = bytes(ours.serialize(bytearray(), prev))
    ref = build(OSKEN, case)
    ref.serialize(bytearray(), build(OSKEN, PREV))
    assert ours.csum == ref.csum == struct.unpack_from("!H", buf, 2)[0]
    given = case.args[2] if len(case.args) > 2 else 0
    if given:
        assert ours.csum == given
    else:
        assert packet_utils.checksum_ip(prev, len(buf), buf) == 0
    fixed = build(C65OF, case)
    fixed.csum = ours.csum
    assert bytes(fixed.serialize(bytearray(), None)) == buf


@pytest.mark.parametrize("case", ND_OPTIONS, ids=str)
def test_nd_option(case):
    """An ND option encodes, decodes and stringifies like os-ken's."""
    ours, ref = build(C65OF, case), build(OSKEN, case)
    buf = bytes(ours.serialize())
    assert buf == bytes(ref.serialize())
    assert attrs(ours) == attrs(ref)
    our_cls = type(build(C65OF, case))
    ref_cls = type(build(OSKEN, case))
    assert attrs(our_cls.parser(buf, 0)) == attrs(ref_cls.parser(buf, 0))
    fields = attrs(ours)
    assert restore(C65OF, case.name, fields) == restore(OSKEN, case.name, fields)


def test_ipv6_in_ethertypes():
    """The IPv6 header is registered for its ethertype."""
    assert ethernet.get_packet_type(ether.ETH_TYPE_IPV6) is ipv6.ipv6


def test_icmpv6_in_ip_protos():
    """The ICMPv6 header is registered for its IP protocol number."""
    assert ipv6.ipv6.get_packet_type(icmpv6.inet.IPPROTO_ICMPV6) is icmpv6.icmpv6


def test_ipv6_len_counts_ext_hdrs():
    """len() of an IPv6 header covers its extension headers."""
    case = Obj("ipv6", 6, 0, 0, 0, 44, 64, SRC, DST, [Obj("fragment", 58, 1, 0, 7)])
    assert len(build(C65OF, case)) == len(build(OSKEN, case)) == 48


@pytest.mark.parametrize("routing_type", [0, 1, 2, 4, 255])
def test_routing_unsupported_type(routing_type):
    """Only the RPL routing header has a parser, as in os-ken."""
    buf = struct.pack("!BBBBBB2x", 58, 0, routing_type, 0, 0, 0)
    assert ipv6.routing.parser(buf) is None
    assert ref_ipv6.routing.parser(buf) is None


def test_routing_type3_dispatch():
    """The routing dispatcher decodes an RPL source route header."""
    buf = bytes(build(C65OF, EXT_HEADERS[8]).serialize())
    assert attrs(ipv6.routing.parser(buf)) == attrs(ref_ipv6.routing.parser(buf))


def test_nd_option_zero_length_rejected():
    """A zero length ND option is rejected, as in os-ken."""
    buf = struct.pack("!I16s", 0, b"\x00" * 16) + b"\x01\x00"
    with pytest.raises(struct.error):
        icmpv6.nd_neighbor.parser(buf, 0)
    with pytest.raises(struct.error):
        ref_icmpv6.nd_neighbor.parser(buf, 0)


def test_nd_option_type_is_abstract():
    """The ND option base declares no type of its own."""
    with pytest.raises(NotImplementedError):
        icmpv6.nd_option.option_type()


def test_nd_option_mtu_len():
    """len() of an MTU option is its fixed 8 octets; os-ken raises instead."""
    assert len(build(C65OF, MTU)) == 8
    with pytest.raises(AttributeError):
        len(build(OSKEN, MTU))


@pytest.mark.parametrize(
    "buf", [b"\x00", b"\x01\x00", b"\x05\x02\xaa\xbb"], ids=["pad1", "padn", "value"]
)
def test_option_parser(buf):
    """A standalone option decodes like os-ken's."""
    assert attrs(ipv6.option.parser(buf)) == attrs(ref_ipv6.option.parser(buf))
    assert bytes(ipv6.option.parser(buf).serialize()) == buf


def neighbor_solicit(eth_cls, ipv6_mod, icmpv6_mod, packet_cls):
    """A neighbour solicitation built with one implementation's classes."""
    pkt = packet_cls()
    pkt.add_protocol(
        eth_cls(dst="33:33:00:00:00:01", src="0e:00:00:00:00:01", ethertype=0x86DD)
    )
    pkt.add_protocol(ipv6_mod.ipv6(nxt=58, hop_limit=255, src=SRC, dst=DST))
    pkt.add_protocol(
        icmpv6_mod.icmpv6(
            type_=icmpv6_mod.ND_NEIGHBOR_SOLICIT,
            data=icmpv6_mod.nd_neighbor(
                dst=SRC, option=icmpv6_mod.nd_option_sla(hw_src="0e:00:00:00:00:01")
            ),
        )
    )
    pkt.serialize()
    return bytes(pkt.data)


def test_ethernet_ipv6_icmpv6_stack():
    """A whole ethernet/IPv6/ICMPv6 packet encodes and decodes like os-ken's."""
    buf = neighbor_solicit(ethernet, ipv6, icmpv6, Packet)
    assert buf == neighbor_solicit(
        ref_packet.ethernet.ethernet, ref_ipv6, ref_icmpv6, ref_packet.Packet
    )
    ours = Packet(bytearray(buf)).protocols
    ref = ref_packet.Packet(bytearray(buf)).protocols
    assert len(ours) == len(ref)
    assert [attrs(p) for p in ours] == [attrs(p) for p in ref]

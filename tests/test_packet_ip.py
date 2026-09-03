"""Differential tests: arp, ipv4 and icmp must agree with os-ken, byte for byte."""

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

import os_ken.lib.packet.arp as ref_arp
import os_ken.lib.packet.ethernet as ref_ethernet
import os_ken.lib.packet.icmp as ref_icmp
import os_ken.lib.packet.ipv4 as ref_ipv4
import pytest

from c65of.packet import arp, icmp, ipv4
from c65of.packet import ether_types as ether
from c65of.packet import in_proto as inet
from c65of.packet.packet_base import ETHERTYPES, IP_PROTOS
from c65of.packet.packet_utils import checksum

ORIGINAL = bytes(range(0x40, 0x60))
IPV4_PAYLOAD = b"\xde\xad\xbe\xef" * 3

# Each builder is called once with our module and once with os-ken's; the two
# modules expose the same names, so one lambda constructs both objects.
ARP_BUILDERS = [
    ("arp-default", lambda m: m.arp()),
    (
        "arp-request",
        lambda m: m.arp(
            opcode=m.ARP_REQUEST,
            src_mac="0e:00:00:00:00:01",
            src_ip="10.0.0.1",
            dst_mac="00:00:00:00:00:00",
            dst_ip="10.0.0.254",
        ),
    ),
    (
        "arp-reply",
        lambda m: m.arp(
            opcode=m.ARP_REPLY,
            src_mac="ff:ff:ff:ff:ff:ff",
            src_ip="192.0.2.1",
            dst_mac="08:60:6e:7f:74:e7",
            dst_ip="192.0.2.2",
        ),
    ),
    (
        "arp-rev-request",
        lambda m: m.arp(
            hwtype=6,
            proto=ether.ETH_TYPE_ARP,
            hlen=6,
            plen=4,
            opcode=m.ARP_REV_REQUEST,
            src_ip="255.255.255.255",
            dst_ip="0.0.0.0",
        ),
    ),
    ("arp-rev-reply", lambda m: m.arp(opcode=m.ARP_REV_REPLY)),
    (
        "arp-ip-helper",
        lambda m: m.arp_ip(
            m.ARP_REPLY,
            "0e:00:00:00:00:02",
            "172.16.0.1",
            "0e:00:00:00:00:03",
            "172.16.0.2",
        ),
    ),
]

IPV4_BUILDERS = [
    ("ipv4-default", lambda m: m.ipv4()),
    (
        "ipv4-fields",
        lambda m: m.ipv4(
            tos=0xB8,
            identification=0x1234,
            flags=2,
            offset=0x1FFF,
            ttl=64,
            proto=inet.IPPROTO_ICMP,
            src="192.0.2.1",
            dst="198.51.100.9",
        ),
    ),
    (
        "ipv4-total-length-set",
        lambda m: m.ipv4(total_length=32, ttl=1, proto=254, csum=0xABCD),
    ),
    (
        "ipv4-option-bytes",
        lambda m: m.ipv4(header_length=6, option=b"\x83\x04\x0a\x00", proto=1),
    ),
    (
        "ipv4-option-bytearray",
        lambda m: m.ipv4(
            header_length=7, option=bytearray(b"\x07\x08\x01\x02\x03\x04")
        ),
    ),
    (
        "ipv4-option-padded",
        lambda m: m.ipv4(header_length=8, option=b"\x01\x02", flags=1, offset=1),
    ),
]

ICMP_BUILDERS = [
    ("icmp-default-echo", lambda m: m.icmp()),
    (
        "icmp-echo-request",
        lambda m: m.icmp(
            type_=m.ICMP_ECHO_REQUEST, data=m.echo(id_=0x1234, seq=7, data=ORIGINAL)
        ),
    ),
    (
        "icmp-echo-reply",
        lambda m: m.icmp(
            type_=m.ICMP_ECHO_REPLY,
            code=m.ICMP_ECHO_REPLY_CODE,
            data=m.echo(id_=1, seq=2),
        ),
    ),
    (
        "icmp-echo-preset-csum",
        lambda m: m.icmp(csum=0x1234, data=m.echo(id_=3, seq=4, data=b"abc")),
    ),
    (
        "icmp-dest-unreach",
        lambda m: m.icmp(
            type_=m.ICMP_DEST_UNREACH,
            code=m.ICMP_HOST_UNREACH_CODE,
            data=m.dest_unreach(data_len=len(ORIGINAL) // 4, data=ORIGINAL),
        ),
    ),
    (
        "icmp-dest-unreach-mtu",
        lambda m: m.icmp(
            type_=m.ICMP_DEST_UNREACH, code=4, data=m.dest_unreach(mtu=1500)
        ),
    ),
    (
        "icmp-time-exceeded",
        lambda m: m.icmp(
            type_=m.ICMP_TIME_EXCEEDED,
            code=m.ICMP_TTL_EXPIRED_CODE,
            data=m.TimeExceeded(data=ORIGINAL),
        ),
    ),
    (
        "icmp-time-exceeded-empty",
        lambda m: m.icmp(type_=m.ICMP_TIME_EXCEEDED, data=m.TimeExceeded(data_len=255)),
    ),
    (
        "icmp-unregistered-type",
        lambda m: m.icmp(type_=m.ICMP_SRC_QUENCH, code=1, data=ORIGINAL),
    ),
    ("icmp-redirect-no-data", lambda m: m.icmp(type_=m.ICMP_REDIRECT, csum=0x4321)),
]

GROUPS = [
    (arp, ref_arp, ARP_BUILDERS, b""),
    (ipv4, ref_ipv4, IPV4_BUILDERS, IPV4_PAYLOAD),
    (icmp, ref_icmp, ICMP_BUILDERS, b""),
]
CASES = [
    (ours, reference, builder, payload)
    for ours, reference, builders, payload in GROUPS
    for _, builder in builders
]
IDS = [name for _, _, builders, _ in GROUPS for name, _ in builders]


def flat(obj):
    """Structural form of a header, so ours and os-ken's can be compared."""
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj)
    if hasattr(obj, "__dict__"):
        return {name: flat(value) for name, value in vars(obj).items()}
    return obj


def encode(module, builder, payload):
    """Build and serialize a header, returning it with its bytes and payload."""
    obj = builder(module)
    buf = bytearray(payload)
    return obj, bytes(obj.serialize(buf, None)), bytes(buf)


@pytest.mark.parametrize("ours, reference, builder, payload", CASES, ids=IDS)
def test_serialize_matches_reference(ours, reference, builder, payload):
    """Encoding, the payload it leaves behind and the header state all agree."""
    our_obj, our_hdr, our_payload = encode(ours, builder, payload)
    ref_obj, ref_hdr, ref_payload = encode(reference, builder, payload)
    assert our_hdr == ref_hdr
    assert our_payload == ref_payload
    assert flat(our_obj) == flat(ref_obj)
    assert len(our_obj) == len(ref_obj)


@pytest.mark.parametrize("ours, reference, builder, payload", CASES, ids=IDS)
def test_parse_matches_reference(ours, reference, builder, payload):
    """Both parse os-ken's own bytes into the same header and the same rest."""
    _, ref_hdr, ref_payload = encode(reference, builder, payload)
    buf = ref_hdr + ref_payload
    our_obj, our_next, our_rest = type(builder(ours)).parser(buf)
    ref_obj, ref_next, ref_rest = type(builder(reference)).parser(buf)
    assert flat(our_obj) == flat(ref_obj)
    assert flat(our_rest) == flat(ref_rest)
    assert getattr(our_next, "__name__", None) == getattr(ref_next, "__name__", None)


@pytest.mark.parametrize("ours, reference, builder, payload", CASES, ids=IDS)
def test_jsondict_matches_reference(ours, reference, builder, payload):
    """The JSON dict form is identical, constructed and parsed."""
    assert builder(ours).to_jsondict() == builder(reference).to_jsondict()
    _, ref_hdr, ref_payload = encode(reference, builder, payload)
    buf = ref_hdr + ref_payload
    our_obj = type(builder(ours)).parser(buf)[0]
    ref_obj = type(builder(reference)).parser(buf)[0]
    assert our_obj.to_jsondict() == ref_obj.to_jsondict()


@pytest.mark.parametrize("ours, reference, builder, payload", CASES, ids=IDS)
def test_jsondict_round_trip(ours, reference, builder, payload):
    """from_jsondict(to_jsondict()) returns an equal object, as it does for os-ken."""
    del reference, payload
    obj = builder(ours)
    ((_, params),) = obj.to_jsondict().items()
    assert flat(type(obj).from_jsondict(params)) == flat(obj)


@pytest.mark.parametrize(
    "name, builder", IPV4_BUILDERS, ids=[n for n, _ in IPV4_BUILDERS]
)
def test_ipv4_checksum(name, builder):
    """The header checksum is recomputed on every encode and verifies to zero."""
    del name
    our_obj, our_hdr, _ = encode(ipv4, builder, IPV4_PAYLOAD)
    ref_obj, _, _ = encode(ref_ipv4, builder, IPV4_PAYLOAD)
    assert our_obj.csum == ref_obj.csum
    assert checksum(our_hdr) == 0
    assert our_obj.total_length == ref_obj.total_length


@pytest.mark.parametrize(
    "name, builder", ICMP_BUILDERS, ids=[n for n, _ in ICMP_BUILDERS]
)
def test_icmp_checksum(name, builder):
    """A zero checksum is computed over the whole message; a set one is kept."""
    del name
    our_obj, our_hdr, _ = encode(icmp, builder, b"")
    ref_obj, _, _ = encode(ref_icmp, builder, b"")
    assert our_obj.csum == ref_obj.csum
    if builder(icmp).csum == 0:
        assert checksum(our_hdr) == 0
    else:
        assert our_obj.csum == builder(icmp).csum


def test_ipv4_option_longer_than_header():
    """An option that does not fit the declared header length is rejected."""
    for module in (ipv4, ref_ipv4):
        with pytest.raises(AssertionError):
            module.ipv4(header_length=5, option=b"\x01\x02\x03\x04").serialize(
                bytearray(), None
            )


@pytest.mark.parametrize("cls_name", ["dest_unreach", "TimeExceeded"])
@pytest.mark.parametrize("data_len", [-1, 256])
def test_icmp_payload_data_len_rejected(cls_name, data_len):
    """A data length outside one octet is an error, as it is for os-ken."""
    for module in (icmp, ref_icmp):
        with pytest.raises(ValueError):
            getattr(module, cls_name)(data_len=data_len)


def test_registered_packet_types():
    """arp and ipv4 answer for their ethertypes, icmp for its IP protocol."""
    assert ETHERTYPES[ether.ETH_TYPE_ARP] is arp.arp
    assert ETHERTYPES[ether.ETH_TYPE_IP] is ipv4.ipv4
    assert IP_PROTOS[inet.IPPROTO_ICMP] is icmp.icmp
    assert ipv4.ipv4.get_packet_type(inet.IPPROTO_ICMP) is icmp.icmp
    for type_ in (ether.ETH_TYPE_ARP, ether.ETH_TYPE_IP):
        ref_cls = ref_ethernet.ethernet.get_packet_type(type_)
        assert ETHERTYPES[type_].__name__ == ref_cls.__name__
    assert (
        ref_ipv4.ipv4.get_packet_type(inet.IPPROTO_ICMP).__name__ == icmp.icmp.__name__
    )


def test_icmp_parse_header_only():
    """A message with nothing after the header parses to an empty body."""
    buf = bytes.fromhex("0800f7ff")
    our_obj, our_next, our_rest = icmp.icmp.parser(buf)
    ref_obj, ref_next, ref_rest = ref_icmp.icmp.parser(buf)
    assert flat(our_obj) == flat(ref_obj)
    assert (our_next, our_rest) == (ref_next, ref_rest)
    assert our_obj.data == b""

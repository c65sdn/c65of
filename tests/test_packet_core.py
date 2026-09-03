"""The Packet container, VLAN tags, checksums and the stream parser."""

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
import os_ken.lib.packet.ethernet as ref_eth
import os_ken.lib.packet.packet as ref_packet
import os_ken.lib.packet.packet_utils as ref_utils
import os_ken.lib.packet.vlan as ref_vlan
import pytest

from c65of.packet import packet_utils
from c65of.packet.arp import arp
from c65of.packet.ethernet import ethernet
from c65of.packet.ipv4 import ipv4
from c65of.packet.packet import Packet
from c65of.packet.stream_parser import StreamParser
from c65of.packet.vlan import svlan, vlan


def _arp_frame():
    pkt = Packet()
    pkt.add_protocol(
        ethernet(dst="ff:ff:ff:ff:ff:ff", src="0e:00:00:00:00:01", ethertype=0x8100)
    )
    pkt.add_protocol(vlan(pcp=0, cfi=0, vid=100, ethertype=0x0806))
    pkt.add_protocol(
        arp(
            opcode=1,
            src_mac="0e:00:00:00:00:01",
            src_ip="10.0.0.1",
            dst_mac="00:00:00:00:00:00",
            dst_ip="10.0.0.2",
        )
    )
    return pkt


def _ref_arp_frame():
    pkt = ref_packet.Packet()
    pkt.add_protocol(
        ref_eth.ethernet(
            dst="ff:ff:ff:ff:ff:ff", src="0e:00:00:00:00:01", ethertype=0x8100
        )
    )
    pkt.add_protocol(ref_vlan.vlan(pcp=0, cfi=0, vid=100, ethertype=0x0806))
    pkt.add_protocol(
        ref_arp.arp(
            opcode=1,
            src_mac="0e:00:00:00:00:01",
            src_ip="10.0.0.1",
            dst_mac="00:00:00:00:00:00",
            dst_ip="10.0.0.2",
        )
    )
    return pkt


def test_serialize_matches_reference():
    """A VLAN tagged ARP frame serializes byte for byte like os-ken's."""
    ours, theirs = _arp_frame(), _ref_arp_frame()
    ours.serialize()
    theirs.serialize()
    assert bytes(ours.data) == bytes(theirs.data)


def test_parse_matches_reference():
    """Decoding that frame yields the same headers in the same order."""
    theirs = _ref_arp_frame()
    theirs.serialize()
    raw = bytes(theirs.data)
    decoded, ref_decoded = Packet(raw), ref_packet.Packet(raw)
    assert [type(p).__name__ for p in decoded] == [
        type(p).__name__ for p in ref_decoded
    ]
    assert decoded.get_protocol(ethernet).src == "0e:00:00:00:00:01"
    assert decoded.get_protocol(vlan).vid == 100
    assert decoded.get_protocol(arp).src_ip == "10.0.0.1"


def test_container_protocol_lookup():
    """get_protocol, get_protocols and containment behave as documented."""
    pkt = _arp_frame()
    assert isinstance(pkt.get_protocol(ethernet), ethernet)
    assert pkt.get_protocol(ipv4) is None
    assert len(pkt.get_protocols(vlan)) == 1
    assert pkt.get_protocols(pkt.get_protocol(vlan)) == pkt.get_protocols(vlan)
    assert ethernet in pkt
    assert ipv4 not in pkt
    assert pkt.get_protocol(arp) in pkt
    assert len(pkt) == 3


def test_container_is_a_sequence():
    """Indexing, assignment, deletion and iteration all work."""
    pkt = _arp_frame()
    first = pkt[0]
    assert isinstance(first, ethernet)
    pkt[0] = first
    del pkt[2]
    assert len(pkt) == 2
    assert [type(p) for p in pkt] == [ethernet, vlan]


def test_truediv_appends():
    """The division operator appends a header."""
    pkt = Packet()
    pkt = pkt / ethernet()
    assert len(pkt) == 1


def test_str_lists_the_headers():
    """A packet stringifies as its headers, comma separated."""
    pkt = _arp_frame()
    assert str(pkt).count(", ") == 2
    assert repr(pkt) == str(pkt)


def test_raw_trailer_is_kept():
    """Bytes past the last recognised header survive as a payload."""
    frame = ethernet(ethertype=0x88B5).serialize(
        bytearray(b"payloadpayloadpayload"), None
    )
    pkt = Packet(bytes(frame) + b"payloadpayloadpayload")
    assert pkt.protocols[-1] == b"payloadpayloadpayload"


def test_all_padding_payload_is_dropped():
    """A trailer of nothing but padding is not mistaken for a payload."""
    frame = bytes(ethernet(ethertype=0x88B5).serialize(bytearray(), None))
    padded = Packet(frame + b"\x00" * 20)
    assert [type(p) for p in padded] == [ethernet]
    assert padded.to_jsondict() == Packet(frame).to_jsondict()


def test_truncated_buffer_stops_cleanly():
    """A header cut short ends the walk rather than raising."""
    pkt = Packet(b"\x00" * 4 + b"\x01")
    assert len(pkt) <= 1


def test_jsondict_round_trip():
    """A whole packet survives the JSON dict form."""
    pkt = _arp_frame()
    restored = Packet.from_jsondict(pkt.to_jsondict()["Packet"])
    pkt.serialize()
    restored.serialize()
    assert bytes(restored.data) == bytes(pkt.data)


def test_jsondict_rejects_an_unknown_protocol():
    """A name that is not a packet class is an error."""
    with pytest.raises(ValueError, match="unknown protocol name"):
        Packet.from_jsondict({"protocols": [{"NotAProtocol": {}}]})


@pytest.mark.parametrize(
    "tag_cls, ref_cls", [(vlan, ref_vlan.vlan), (svlan, ref_vlan.svlan)]
)
@pytest.mark.parametrize(
    "pcp, cfi, vid", [(0, 0, 0), (3, 0, 100), (7, 1, 4095), (0, 1, 1)]
)
def test_vlan_tag_matches_reference(tag_cls, ref_cls, pcp, cfi, vid):
    """Every TCI field packs and unpacks exactly as os-ken's does."""
    ours = tag_cls(pcp=pcp, cfi=cfi, vid=vid, ethertype=0x0800)
    theirs = ref_cls(pcp=pcp, cfi=cfi, vid=vid, ethertype=0x0800)
    raw = ours.serialize(None, None)
    assert raw == theirs.serialize(None, None)
    assert ours.to_jsondict() == theirs.to_jsondict()
    assert str(ours) == str(theirs)
    parsed, _, rest = tag_cls.parser(raw + b"zz")
    ref_parsed, _, ref_rest = ref_cls.parser(raw + b"zz")
    assert (parsed.pcp, parsed.cfi, parsed.vid, parsed.ethertype) == (
        ref_parsed.pcp,
        ref_parsed.cfi,
        ref_parsed.vid,
        ref_parsed.ethertype,
    )
    assert bytes(rest) == bytes(ref_rest)


def test_vlan_next_protocol_lookup():
    """A tag resolves the ethertype it carries."""
    _, next_cls, _ = vlan.parser(vlan(vid=1, ethertype=0x0806).serialize(None, None))
    assert next_cls is arp


def test_ethernet_length_type_selects_llc():
    """A Length/Type of 1500 or less is a length, not an ethertype."""
    assert ethernet.get_packet_type(0x100) is ethernet.get_packet_type(0x05DC)


@pytest.mark.parametrize("length", [0, 1, 2, 19, 20, 63, 64, 255])
def test_checksum_matches_reference(length):
    """The internet checksum agrees with os-ken at every length parity."""
    data = bytes(range(length % 256))[:length]
    assert packet_utils.checksum(data) == ref_utils.checksum(data)


@pytest.mark.parametrize("version", [4, 6])
def test_checksum_ip_matches_reference(version):
    """The pseudo header checksum agrees with os-ken for both versions."""

    class Header:  # pylint: disable=too-few-public-methods
        """Minimal stand-in for the enclosing IP header."""

        def __init__(self):
            self.version = version
            self.src = "10.0.0.1" if version == 4 else "fe80::1"
            self.dst = "10.0.0.2" if version == 4 else "fe80::2"
            self.proto = 6
            self.nxt = 58

    payload = bytes(range(40))
    header = Header()
    assert packet_utils.checksum_ip(
        header, len(payload), payload
    ) == ref_utils.checksum_ip(header, len(payload), payload)


def test_checksum_ip_rejects_an_unknown_version():
    """An IP version that is neither 4 nor 6 is an error."""

    class Header:  # pylint: disable=too-few-public-methods
        """Stand-in with a nonsense version."""

        version = 5

    with pytest.raises(ValueError, match="Unknown IP version"):
        packet_utils.checksum_ip(Header(), 0, b"")


@pytest.mark.parametrize("a, b", [(0, 0), (1, 2), (0xFFFF, 1), (0x12345, 0x9999)])
def test_carry_around_add_matches_reference(a, b):
    """Ones-complement addition agrees with os-ken."""
    assert packet_utils.carry_around_add(a, b) == ref_utils.carry_around_add(a, b)


def test_fletcher_checksum_matches_reference():
    """The Fletcher checksum agrees with os-ken."""
    data = bytes(range(60))
    assert packet_utils.fletcher_checksum(data, 4) == ref_utils.fletcher_checksum(
        data, 4
    )


class LineParser(StreamParser):
    """Extracts NUL terminated records, to exercise the base class."""

    def try_parse(self, q):
        """Return the first record and the rest, or ask for more bytes."""
        end = q.find(b"\x00")
        if end < 0:
            raise self.TooSmallException()
        return bytes(q[:end]), q[end + 1 :]


def test_stream_parser_reassembles_across_reads():
    """Records split across reads come out whole and in order."""
    parser = LineParser()
    assert parser.parse(b"one\x00tw") == [b"one"]
    assert parser.parse(b"o\x00three\x00") == [b"two", b"three"]
    assert not parser.parse(b"")

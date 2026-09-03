"""Differential tests: OpenFlow 1.3 messages vs os-ken."""

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

import os_ken.ofproto.ofproto_v1_3 as ref_ofp
import os_ken.ofproto.ofproto_v1_3_parser as ref
import pytest

from c65of.ofproto import consts, messages, parser


class _Datapath:
    """The part of a datapath os-ken's serialize() reads."""

    def __init__(self, ofproto, ofproto_parser):
        self.ofproto = ofproto
        self.ofproto_parser = ofproto_parser


class _Ours:
    """The c65of classes, under the one namespace os-ken keeps them in."""

    def __getattr__(self, name):
        for module in (messages, parser):
            value = getattr(module, name, None)
            if value is not None:
                return value
        raise AttributeError(name)


OURS = _Ours()
OUR_DP = _Datapath(consts, OURS)
REF_DP = _Datapath(ref_ofp, ref)

MAC = "0e:00:00:00:00:01"
PORT_NAME = b"eth0"


def _wire(msg_type, body, xid=0x12345678):
    """An OpenFlow message: a header sized for ``body``, then ``body``."""
    return (
        struct.pack(
            ref_ofp.OFP_HEADER_PACK_STR,
            ref_ofp.OFP_VERSION,
            msg_type,
            ref_ofp.OFP_HEADER_SIZE + len(body),
            xid,
        )
        + body
    )


def _match_bytes(**fields):
    buf = bytearray()
    ref.OFPMatch(**fields).serialize(buf, 0)
    return bytes(buf)


def _port_bytes(port_no=1):
    return struct.pack(
        ref_ofp.OFP_PORT_PACK_STR,
        port_no,
        b"\x0e\x00\x00\x00\x00\x01",
        PORT_NAME,
        1,
        2,
        0x20,
        0x40,
        0x80,
        0x100,
        10000,
        40000,
    )


def _round_trip(message, datapath):
    cls = type(message)
    return cls.from_jsondict(message.to_jsondict()[cls.__name__], datapath=datapath)


# Each case builds the same message from whichever namespace it is handed.
CASES = [
    ("hello", lambda p, dp: p.OFPHello(dp)),
    (
        "hello-elements",
        lambda p, dp: p.OFPHello(dp, [p.OFPHelloElemVersionBitmap([1, 4])]),
    ),
    (
        "error",
        lambda p, dp: p.OFPErrorMsg(dp, type_=1, code=2, data=b"\xde\xad\xbe\xef"),
    ),
    ("error-empty-data", lambda p, dp: p.OFPErrorMsg(dp, type_=4, code=0, data=b"")),
    ("error-text-data", lambda p, dp: p.OFPErrorMsg(dp, type_=0, code=0, data="oops")),
    (
        "error-experimenter",
        lambda p, dp: p.OFPErrorMsg(
            dp,
            type_=ref_ofp.OFPET_EXPERIMENTER,
            exp_type=7,
            experimenter=0x2320,
            data=b"xyz",
        ),
    ),
    ("echo-request", lambda p, dp: p.OFPEchoRequest(dp)),
    ("echo-request-data", lambda p, dp: p.OFPEchoRequest(dp, b"ping")),
    ("echo-reply", lambda p, dp: p.OFPEchoReply(dp, b"pong")),
    (
        "experimenter",
        lambda p, dp: p.OFPExperimenter(dp, experimenter=0x2320, exp_type=3, data=b"e"),
    ),
    ("features-request", lambda p, dp: p.OFPFeaturesRequest(dp)),
    (
        "switch-features",
        lambda p, dp: p.OFPSwitchFeatures(dp, 0x1122334455667788, 256, 254, 0, 0x4F),
    ),
    ("get-config-request", lambda p, dp: p.OFPGetConfigRequest(dp)),
    ("get-config-reply", lambda p, dp: p.OFPGetConfigReply(dp, 1, 128)),
    ("set-config", lambda p, dp: p.OFPSetConfig(dp)),
    ("set-config-values", lambda p, dp: p.OFPSetConfig(dp, 2, 0xFFFF)),
    (
        "packet-in",
        lambda p, dp: p.OFPPacketIn(
            dp, 0xFFFFFFFF, 6, 0, 1, 0xABCD, p.OFPMatch(in_port=3), b"abcdef"
        ),
    ),
    (
        "flow-removed",
        lambda p, dp: p.OFPFlowRemoved(
            dp, 1, 0x8000, 0, 2, 30, 40, 5, 6, 7, 8, p.OFPMatch(eth_type=0x800)
        ),
    ),
    (
        "port-status",
        lambda p, dp: p.OFPPortStatus(
            dp, 2, p.OFPPort(1, MAC, PORT_NAME, 1, 2, 0x20, 0x40, 0x80, 0x100, 1, 2)
        ),
    ),
    (
        "packet-out",
        lambda p, dp: p.OFPPacketOut(
            dp, 0xFFFFFFFF, 4294967293, [p.OFPActionOutput(1)], b"pkt"
        ),
    ),
    (
        "packet-out-no-data",
        lambda p, dp: p.OFPPacketOut(dp, 7, 1, [p.OFPActionPopVlan()]),
    ),
    ("packet-out-no-actions", lambda p, dp: p.OFPPacketOut(dp, 7, 1, [])),
    ("flow-mod-empty", lambda p, dp: p.OFPFlowMod(dp)),
    (
        "flow-mod",
        lambda p, dp: p.OFPFlowMod(
            dp,
            0xDEADBEEF,
            0xFFFFFFFF,
            3,
            ref_ofp.OFPFC_MODIFY,
            10,
            20,
            0x7FFF,
            0xFFFFFFFF,
            4294967295,
            4294967295,
            ref_ofp.OFPFF_SEND_FLOW_REM,
            p.OFPMatch(eth_type=0x800, ipv4_dst="10.0.0.0/8"),
            [
                p.OFPInstructionGotoTable(4),
                p.OFPInstructionActions(
                    ref_ofp.OFPIT_APPLY_ACTIONS,
                    [p.OFPActionSetField(vlan_vid=0x1064), p.OFPActionOutput(2, 128)],
                ),
            ],
        ),
    ),
    ("group-mod-empty", lambda p, dp: p.OFPGroupMod(dp)),
    (
        "group-mod",
        lambda p, dp: p.OFPGroupMod(
            dp,
            ref_ofp.OFPGC_MODIFY,
            ref_ofp.OFPGT_SELECT,
            9,
            [
                p.OFPBucket(1, 2, 3, [p.OFPActionOutput(1)]),
                p.OFPBucket(actions=[p.OFPActionPopVlan(), p.OFPActionOutput(2)]),
            ],
        ),
    ),
    ("port-mod-default", lambda p, dp: p.OFPPortMod(dp)),
    ("port-mod", lambda p, dp: p.OFPPortMod(dp, 3, MAC, 1, 0xFF, 0x40)),
    ("table-mod", lambda p, dp: p.OFPTableMod(dp, 5, 3)),
    ("meter-mod-empty", lambda p, dp: p.OFPMeterMod(dp)),
    (
        "meter-mod",
        lambda p, dp: p.OFPMeterMod(
            dp,
            ref_ofp.OFPMC_MODIFY,
            ref_ofp.OFPMF_PKTPS,
            7,
            [
                p.OFPMeterBandDrop(1000, 10),
                p.OFPMeterBandDscpRemark(2000, 20, 3),
                p.OFPMeterBandExperimenter(3000, 30, 0x2320),
            ],
        ),
    ),
    ("barrier-request", lambda p, dp: p.OFPBarrierRequest(dp)),
    ("barrier-reply", lambda p, dp: p.OFPBarrierReply(dp)),
    ("queue-get-config-request", lambda p, dp: p.OFPQueueGetConfigRequest(dp, 3)),
    (
        "queue-get-config-reply",
        lambda p, dp: p.OFPQueueGetConfigReply(
            dp,
            [
                p.OFPPacketQueue(
                    1,
                    2,
                    [
                        p.OFPQueuePropMinRate(700),
                        p.OFPQueuePropMaxRate(900),
                        p.OFPQueuePropExperimenter(0x2320, [1, 2, 3, 4]),
                    ],
                )
            ],
            2,
        ),
    ),
    ("role-request", lambda p, dp: p.OFPRoleRequest(dp, ref_ofp.OFPCR_ROLE_MASTER, 42)),
    ("role-reply", lambda p, dp: p.OFPRoleReply(dp, ref_ofp.OFPCR_ROLE_EQUAL, 7)),
    ("get-async-request", lambda p, dp: p.OFPGetAsyncRequest(dp)),
    (
        "get-async-reply",
        lambda p, dp: p.OFPGetAsyncReply(dp, [1, 2], [3, 4], [5, 6]),
    ),
    ("set-async", lambda p, dp: p.OFPSetAsync(dp, [7, 0], [0, 7], [3, 3])),
]

CASE_IDS = [name for name, _ in CASES]
BUILDERS = [build for _, build in CASES]

# Messages whose wire form only a switch produces, built by hand.
PARSE_CASES = [
    ("OFPHello", ref_ofp.OFPT_HELLO, struct.pack("!HHI", 1, 8, (1 << 1) | (1 << 4))),
    (
        "OFPHello",
        ref_ofp.OFPT_HELLO,
        struct.pack("!HH4x", 99, 8) + struct.pack("!HHI", 1, 8, 1 << 4),
    ),
    ("OFPErrorMsg", ref_ofp.OFPT_ERROR, struct.pack("!HH", 1, 9) + b"\xde\xad"),
    (
        "OFPErrorMsg",
        ref_ofp.OFPT_ERROR,
        struct.pack("!HHI", ref_ofp.OFPET_EXPERIMENTER, 7, 0x2320) + b"xyz",
    ),
    ("OFPEchoRequest", ref_ofp.OFPT_ECHO_REQUEST, b"ping"),
    ("OFPEchoReply", ref_ofp.OFPT_ECHO_REPLY, b"pong"),
    (
        "OFPExperimenter",
        ref_ofp.OFPT_EXPERIMENTER,
        struct.pack("!II", 0x2320, 3) + b"d",
    ),
    (
        "OFPSwitchFeatures",
        ref_ofp.OFPT_FEATURES_REPLY,
        struct.pack(
            ref_ofp.OFP_SWITCH_FEATURES_PACK_STR,
            0x1122334455667788,
            256,
            254,
            0,
            0x4F,
            0,
        ),
    ),
    ("OFPGetConfigReply", ref_ofp.OFPT_GET_CONFIG_REPLY, struct.pack("!HH", 1, 128)),
    (
        "OFPPacketIn",
        ref_ofp.OFPT_PACKET_IN,
        struct.pack("!IHBBQ", 0xFFFFFFFF, 6, 0, 1, 0xABCD)
        + _match_bytes(in_port=3)
        + b"\x00\x00"
        + b"abcdef",
    ),
    (
        # More bytes present than total_len reports: the data is truncated.
        "OFPPacketIn",
        ref_ofp.OFPT_PACKET_IN,
        struct.pack("!IHBBQ", 1, 2, 1, 0, 0) + _match_bytes() + b"\x00\x00" + b"abcdef",
    ),
    (
        "OFPFlowRemoved",
        ref_ofp.OFPT_FLOW_REMOVED,
        struct.pack(
            ref_ofp.OFP_FLOW_REMOVED_PACK_STR0, 1, 0x8000, 0, 2, 30, 40, 5, 6, 7, 8
        )
        + _match_bytes(eth_type=0x800, ipv4_dst="10.0.0.0/8"),
    ),
    (
        "OFPPortStatus",
        ref_ofp.OFPT_PORT_STATUS,
        struct.pack("!B7x", 2) + _port_bytes(),
    ),
    (
        "OFPQueueGetConfigReply",
        ref_ofp.OFPT_QUEUE_GET_CONFIG_REPLY,
        struct.pack("!I4x", 5)
        + struct.pack("!IIH6x", 1, 5, 68)
        + struct.pack("!HH4xH6x", ref_ofp.OFPQT_MIN_RATE, 16, 700)
        + struct.pack("!HH4xH6x", ref_ofp.OFPQT_MAX_RATE, 16, 900)
        + struct.pack("!HH4xI4x", ref_ofp.OFPQT_EXPERIMENTER, 20, 0x2320)
        + b"\x01\x02\x03\x04",
    ),
    ("OFPBarrierReply", ref_ofp.OFPT_BARRIER_REPLY, b""),
    ("OFPRoleReply", ref_ofp.OFPT_ROLE_REPLY, struct.pack("!I4xQ", 2, 42)),
    (
        "OFPGetAsyncReply",
        ref_ofp.OFPT_GET_ASYNC_REPLY,
        struct.pack("!2I2I2I", 1, 2, 3, 4, 5, 6),
    ),
]


def _serialized_body(case_id):
    """The body of a message os-ken serializes, for feeding back to a parser."""
    message = BUILDERS[CASE_IDS.index(case_id)](ref, REF_DP)
    message.serialize()
    return bytes(message.buf)[ref_ofp.OFP_HEADER_SIZE :]


PARSE_CASES.append(("OFPFlowMod", ref_ofp.OFPT_FLOW_MOD, _serialized_body("flow-mod")))

PARSE_IDS = ["%s-%d" % (name, i) for i, (name, _, _) in enumerate(PARSE_CASES)]

# Controller to switch messages: os-ken has no parser for these, so the wire
# form is checked by feeding our own serialization back through our parser.
REPARSE_IDS = [
    "packet-out",
    "packet-out-no-data",
    "packet-out-no-actions",
    "flow-mod-empty",
    "flow-mod",
    "group-mod-empty",
    "group-mod",
    "port-mod",
    "table-mod",
    "meter-mod-empty",
    "meter-mod",
    "queue-get-config-request",
    "role-request",
    "set-async",
    "set-config-values",
    "echo-request-data",
    "experimenter",
    "barrier-request",
    "features-request",
]


# os-ken's OFPInstructionActions leaves ``len`` unset until it is serialized,
# where c65of's parser.py initialises it to None. A message carrying one is
# therefore only comparable in its serialized form.
INSTRUCTION_ACTIONS = frozenset(["flow-mod", "OFPFlowMod"])


@pytest.mark.parametrize("build", BUILDERS, ids=CASE_IDS)
def test_message_matches_reference(build, request):
    """A message stringifies, serializes and round trips as os-ken's does."""
    comparable = request.node.callspec.id not in INSTRUCTION_ACTIONS
    ours, theirs = build(OURS, OUR_DP), build(ref, REF_DP)
    if comparable:
        assert str(ours) == str(theirs)
        assert ours.to_jsondict() == theirs.to_jsondict()

    ours.serialize()
    theirs.serialize()
    assert bytes(ours.buf) == bytes(theirs.buf)
    assert (ours.version, ours.msg_type, ours.msg_len, ours.xid) == (
        theirs.version,
        theirs.msg_type,
        theirs.msg_len,
        theirs.xid,
    )
    assert str(ours) == str(theirs)
    assert ours.to_jsondict() == theirs.to_jsondict()

    rt_ours, rt_theirs = _round_trip(ours, OUR_DP), _round_trip(theirs, REF_DP)
    if comparable:
        assert rt_ours.to_jsondict() == rt_theirs.to_jsondict()
    rt_ours.serialize()
    rt_theirs.serialize()
    assert bytes(rt_ours.buf) == bytes(rt_theirs.buf) == bytes(ours.buf)


@pytest.mark.parametrize("name, msg_type, body", PARSE_CASES, ids=PARSE_IDS)
def test_parse_matches_reference(name, msg_type, body):
    """Parsing switch-sent bytes yields exactly what os-ken's parser does."""
    buf = _wire(msg_type, body)
    version, msg_type, msg_len, xid = struct.unpack_from(
        ref_ofp.OFP_HEADER_PACK_STR, buf
    )
    args = (version, msg_type, msg_len, xid, buf)
    ours = getattr(OURS, name).parser(OUR_DP, *args)
    theirs = getattr(ref, name).parser(REF_DP, *args)
    assert ours.to_jsondict() == theirs.to_jsondict()
    assert str(ours) == str(theirs)
    assert ours.buf == theirs.buf
    assert parser.msg(OUR_DP, *args).to_jsondict() == ours.to_jsondict()
    if name not in INSTRUCTION_ACTIONS:
        assert (
            _round_trip(ours, OUR_DP).to_jsondict()
            == _round_trip(theirs, REF_DP).to_jsondict()
        )


@pytest.mark.parametrize("case_id", REPARSE_IDS)
def test_serialize_parse_round_trip(case_id):
    """Our own parser reads back everything our serializer writes."""
    message = BUILDERS[CASE_IDS.index(case_id)](OURS, OUR_DP)
    message.serialize()
    reparsed = parser.msg(
        OUR_DP,
        message.version,
        message.msg_type,
        message.msg_len,
        message.xid,
        bytes(message.buf),
    )
    reparsed.serialize()
    assert bytes(reparsed.buf) == bytes(message.buf)
    assert reparsed.to_jsondict() == message.to_jsondict()


def test_switch_message_serializes_header_only():
    """os-ken gives switch-sent messages no body serializer, and nor do we."""
    for build in (
        lambda p, dp: p.OFPPacketIn(dp, 1, 2, 0, 0, 0, p.OFPMatch(), b"data"),
        lambda p, dp: p.OFPBarrierReply(dp),
    ):
        ours, theirs = build(OURS, OUR_DP), build(ref, REF_DP)
        ours.serialize()
        theirs.serialize()
        assert len(ours.buf) == consts.OFP_HEADER_SIZE
        assert bytes(ours.buf) == bytes(theirs.buf)


def test_error_experimenter_helper():
    """The deprecated experimenter error spelling matches os-ken's."""
    ours = messages.OFPErrorExperimenterMsg(
        OUR_DP, exp_type=3, experimenter=0x2320, data=b"z"
    )
    theirs = ref.OFPErrorExperimenterMsg(
        REF_DP, exp_type=3, experimenter=0x2320, data=b"z"
    )
    ours.serialize()
    theirs.serialize()
    assert bytes(ours.buf) == bytes(theirs.buf)
    assert str(ours) == str(theirs)


def test_hello_element_bitmaps():
    """A parsed version bitmap keeps the raw words it was built from."""
    buf = _wire(consts.OFPT_HELLO, struct.pack("!HHI", 1, 8, (1 << 1) | (1 << 4)))
    elements = messages.OFPHello.parser(
        OUR_DP, consts.OFP_VERSION, consts.OFPT_HELLO, len(buf), 0, buf
    ).elements
    assert [e.versions for e in elements] == [[1, 4]]
    # os-ken keeps the raw words privately; matched so callers reading them do
    # not notice the swap.
    assert getattr(elements[0], "_bitmaps") == [(1 << 1) | (1 << 4)]
    assert elements[0].length == 8


def test_bucket_len_absent_until_serialized():
    """A bucket reports no length until parsing or serializing sets one."""
    bucket = messages.OFPBucket(actions=[])
    assert "len" not in bucket.to_jsondict()["OFPBucket"]
    assert bucket.serialize(bytearray(), 0) == consts.OFP_BUCKET_SIZE
    assert bucket.to_jsondict()["OFPBucket"]["len"] == consts.OFP_BUCKET_SIZE


def test_queue_property_serialize_round_trip():
    """A queue property serializes to its own wire form and reads back."""
    for prop in (
        messages.OFPQueuePropMinRate(700),
        messages.OFPQueuePropMaxRate(900),
        messages.OFPQueuePropExperimenter(0x2320, [1, 2, 3, 4]),
    ):
        buf = bytearray()
        length = prop.serialize(buf, 0)
        assert length == len(buf)
        assert messages.OFPQueueProp.parser(bytes(buf), 0).to_jsondict() == (
            prop.to_jsondict()
        )


def test_unknown_queue_property_skipped():
    """A queue property of an unknown type is skipped, not fatal."""
    buf = struct.pack("!IIH6x", 1, 2, 32) + struct.pack("!HH4x8x", 0x1234, 16)
    queue = messages.OFPPacketQueue.parser(buf + bytes(16), 0)
    assert queue.properties == []
    assert messages.OFPQueueProp.parser(struct.pack("!HH4x", 0x1234, 16), 0) is None


def test_packet_out_requires_in_port():
    """os-ken rejects a packet out with no ingress port, and so do we."""
    with pytest.raises(AssertionError):
        messages.OFPPacketOut(OUR_DP, buffer_id=0xFFFFFFFF, actions=[])


def test_echo_reply_requires_data():
    """An echo reply with no data is an error, as in os-ken."""
    with pytest.raises(AssertionError):
        messages.OFPEchoReply(OUR_DP).serialize()


def test_flow_mod_rejects_non_match():
    """A flow mod insists its match really is one."""
    with pytest.raises(AssertionError):
        messages.OFPFlowMod(OUR_DP, match="not a match")

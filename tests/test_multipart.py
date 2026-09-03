"""Differential tests: multipart requests, replies and bodies vs os-ken."""

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

from c65of.ofproto import consts, messages, multipart, parser


class _Datapath:
    """The two attributes os-ken's serialize path reads off a datapath."""

    def __init__(self, ofproto, ofproto_parser):
        self.ofproto = ofproto
        self.ofproto_parser = ofproto_parser


DP = _Datapath(consts, parser)
REF_DP = _Datapath(ref_ofp, ref)


def ours(name):
    """Resolve a class name in c65of."""
    for module in (multipart, parser, messages):
        cls = getattr(module, name, None)
        if cls is not None:
            return cls
    raise AttributeError(name)


def theirs(name):
    """Resolve a class name in os-ken."""
    return getattr(ref, name)


# -- requests ---------------------------------------------------------------

# (class name, callable taking a name resolver and returning (args, kwargs))
REQUESTS = [
    ("OFPDescStatsRequest", lambda ns: ((), {})),
    ("OFPDescStatsRequest", lambda ns: ((ref_ofp.OFPMPF_REQ_MORE,), {})),
    ("OFPFlowStatsRequest", lambda ns: ((), {})),
    (
        "OFPFlowStatsRequest",
        lambda ns: ((0, 1, 2, 3, 0xAB, 0xFF, ns("OFPMatch")(in_port=4)), {}),
    ),
    (
        "OFPFlowStatsRequest",
        lambda ns: (
            (),
            {"match": ns("OFPMatch")(eth_type=0x800, ipv4_dst="10.0.0.0/8")},
        ),
    ),
    (
        "OFPAggregateStatsRequest",
        lambda ns: ((0, 0xFF, 1, 2, 3, 4, ns("OFPMatch")(in_port=9)), {}),
    ),
    ("OFPTableStatsRequest", lambda ns: ((), {})),
    ("OFPPortStatsRequest", lambda ns: ((), {})),
    ("OFPPortStatsRequest", lambda ns: ((1, 7), {})),
    ("OFPQueueStatsRequest", lambda ns: ((), {})),
    ("OFPQueueStatsRequest", lambda ns: ((0, 3, 5), {})),
    ("OFPGroupStatsRequest", lambda ns: ((), {})),
    ("OFPGroupStatsRequest", lambda ns: ((0, 11), {})),
    ("OFPGroupDescStatsRequest", lambda ns: ((), {})),
    ("OFPGroupFeaturesStatsRequest", lambda ns: ((), {})),
    ("OFPMeterStatsRequest", lambda ns: ((), {})),
    ("OFPMeterStatsRequest", lambda ns: ((0, 13), {})),
    ("OFPMeterConfigStatsRequest", lambda ns: ((), {})),
    ("OFPMeterConfigStatsRequest", lambda ns: ((0, 17), {})),
    ("OFPMeterFeaturesStatsRequest", lambda ns: ((), {})),
    ("OFPTableFeaturesStatsRequest", lambda ns: ((), {})),
    (
        "OFPTableFeaturesStatsRequest",
        lambda ns: (
            (
                0,
                [
                    ns("OFPTableFeaturesStats")(
                        table_id=0,
                        name=b"table0",
                        metadata_match=0xFF,
                        metadata_write=0xF0,
                        config=0,
                        max_entries=4096,
                        properties=[
                            ns("OFPTableFeaturePropInstructions")(
                                ref_ofp.OFPTFPT_INSTRUCTIONS,
                                instruction_ids=[
                                    ns("OFPInstructionId")(ref_ofp.OFPIT_GOTO_TABLE)
                                ],
                            ),
                            ns("OFPTableFeaturePropNextTables")(
                                ref_ofp.OFPTFPT_NEXT_TABLES, table_ids=[1, 2, 3]
                            ),
                            ns("OFPTableFeaturePropActions")(
                                ref_ofp.OFPTFPT_APPLY_ACTIONS,
                                action_ids=[ns("OFPActionId")(ref_ofp.OFPAT_OUTPUT)],
                            ),
                            ns("OFPTableFeaturePropOxm")(
                                ref_ofp.OFPTFPT_MATCH,
                                oxm_ids=[
                                    ns("OFPOxmId")("in_port"),
                                    ns("OFPOxmId")("eth_dst", hasmask=True),
                                ],
                            ),
                        ],
                    ),
                    ns("OFPTableFeaturesStats")(
                        table_id=1,
                        name=b"table1",
                        metadata_match=0,
                        metadata_write=0,
                        config=0,
                        max_entries=8,
                        properties=[],
                    ),
                ],
            ),
            {},
        ),
    ),
    ("OFPPortDescStatsRequest", lambda ns: ((), {})),
    ("OFPExperimenterStatsRequest", lambda ns: ((0, 0xABCD, 2, b"payload"), {})),
    ("ONFFlowMonitorStatsRequest", lambda ns: ((0,), {})),
    (
        "ONFFlowMonitorStatsRequest",
        lambda ns: (
            (
                0,
                [
                    ns("ONFFlowMonitorRequest")(1, 2),
                    ns("ONFFlowMonitorRequest")(
                        3, 4, ns("OFPMatch")(in_port=1, eth_type=0x806), 7, 9
                    ),
                ],
            ),
            {},
        ),
    ),
]

REQUEST_IDS = ["%s-%d" % (name, i) for i, (name, _) in enumerate(REQUESTS)]


def _built(name, case, resolve, datapath):
    args, kwargs = case(resolve)
    return resolve(name)(datapath, *args, **kwargs)


@pytest.mark.parametrize("name, case", REQUESTS, ids=REQUEST_IDS)
def test_request_matches_reference(name, case):
    """A request serializes, stringifies and round trips as os-ken's does."""
    our_msg = _built(name, case, ours, DP)
    ref_msg = _built(name, case, theirs, REF_DP)
    our_msg.serialize()
    ref_msg.serialize()
    assert bytes(our_msg.buf) == bytes(ref_msg.buf)
    assert our_msg.msg_len == ref_msg.msg_len
    assert our_msg.to_jsondict() == ref_msg.to_jsondict()
    assert str(our_msg) == str(ref_msg)


@pytest.mark.parametrize("name, case", REQUESTS, ids=REQUEST_IDS)
def test_request_from_jsondict_matches_reference(name, case):
    """A request survives a JSON dict round trip, as os-ken's does."""
    our_json = _built(name, case, ours, DP).to_jsondict()
    ref_json = _built(name, case, theirs, REF_DP).to_jsondict()
    assert our_json == ref_json
    our_msg = ours(name).from_jsondict(our_json[name], datapath=DP)
    ref_msg = theirs(name).from_jsondict(ref_json[name], datapath=REF_DP)
    assert our_msg.to_jsondict() == ref_msg.to_jsondict()
    our_msg.serialize()
    ref_msg.serialize()
    assert bytes(our_msg.buf) == bytes(ref_msg.buf)


def test_request_type_argument_is_ignored():
    """os-ken accepts a type_ argument and takes the type from the class."""
    assert (
        multipart.OFPPortStatsRequest(DP, 0, 1, type_=99).type
        == consts.OFPMP_PORT_STATS
    )
    assert (
        ref.OFPPortStatsRequest(REF_DP, 0, 1, type_=99).type == ref_ofp.OFPMP_PORT_STATS
    )


# -- reply bodies -----------------------------------------------------------


def _serialized(obj):
    buf = bytearray()
    obj.serialize(buf, 0)
    return bytes(buf)


def _desc_body():
    return struct.pack(
        ref_ofp.OFP_DESC_PACK_STR, b"mfr", b"hw", b"sw", b"serial", b"dp"
    )


def _flow_entry(priority, insts):
    match = bytearray()
    ref.OFPMatch(in_port=1, eth_type=0x800).serialize(match, 0)
    body = bytearray()
    for inst in insts:
        inst.serialize(body, len(body))
    length = ref_ofp.OFP_FLOW_STATS_0_SIZE + len(match) + len(body)
    return (
        struct.pack(
            ref_ofp.OFP_FLOW_STATS_0_PACK_STR,
            length,
            1,
            2,
            3,
            priority,
            4,
            5,
            6,
            7,
            8,
            9,
        )
        + bytes(match)
        + bytes(body)
    )


def _flow_body():
    return _flow_entry(
        100,
        [
            ref.OFPInstructionGotoTable(3),
            ref.OFPInstructionActions(
                ref_ofp.OFPIT_APPLY_ACTIONS, [ref.OFPActionOutput(2)]
            ),
        ],
    ) + _flow_entry(200, [])


def _group_body():
    entry = struct.pack(
        ref_ofp.OFP_GROUP_STATS_PACK_STR,
        ref_ofp.OFP_GROUP_STATS_SIZE + 2 * ref_ofp.OFP_BUCKET_COUNTER_SIZE,
        7,
        1,
        2,
        3,
        4,
        5,
    ) + struct.pack("!QQQQ", 10, 20, 30, 40)
    empty = struct.pack(
        ref_ofp.OFP_GROUP_STATS_PACK_STR, ref_ofp.OFP_GROUP_STATS_SIZE, 8, 0, 0, 0, 0, 0
    )
    return entry + empty


def _group_desc_body():
    buckets = bytearray()
    for bucket in (
        ref.OFPBucket(1, 2, 3, [ref.OFPActionOutput(1)]),
        ref.OFPBucket(4, 5, 6, []),
    ):
        bucket.serialize(buckets, len(buckets))
    return struct.pack(
        ref_ofp.OFP_GROUP_DESC_STATS_PACK_STR,
        ref_ofp.OFP_GROUP_DESC_STATS_SIZE + len(buckets),
        ref_ofp.OFPGT_ALL,
        5,
    ) + bytes(buckets)


def _meter_body():
    bands = struct.pack("!QQ", 7, 8)
    return (
        struct.pack(
            ref_ofp.OFP_METER_STATS_PACK_STR,
            1,
            ref_ofp.OFP_METER_STATS_SIZE + len(bands),
            2,
            3,
            4,
            5,
            6,
        )
        + bands
    )


def _meter_config_body():
    bands = bytearray()
    ref.OFPMeterBandDrop(100, 10).serialize(bands, 0)
    ref.OFPMeterBandDscpRemark(200, 20, 3).serialize(bands, len(bands))
    return struct.pack(
        ref_ofp.OFP_METER_CONFIG_PACK_STR,
        ref_ofp.OFP_METER_CONFIG_SIZE + len(bands),
        ref_ofp.OFPMF_KBPS,
        2,
    ) + bytes(bands)


def _table_features_body():
    props = [
        ref.OFPTableFeaturePropInstructions(
            ref_ofp.OFPTFPT_INSTRUCTIONS,
            instruction_ids=[
                ref.OFPInstructionId(ref_ofp.OFPIT_GOTO_TABLE),
                ref.OFPInstructionId(ref_ofp.OFPIT_APPLY_ACTIONS),
            ],
        ),
        ref.OFPTableFeaturePropNextTables(
            ref_ofp.OFPTFPT_NEXT_TABLES_MISS, table_ids=[2, 3]
        ),
        ref.OFPTableFeaturePropActions(
            ref_ofp.OFPTFPT_WRITE_ACTIONS,
            action_ids=[ref.OFPActionId(ref_ofp.OFPAT_SET_FIELD)],
        ),
        ref.OFPTableFeaturePropOxm(
            ref_ofp.OFPTFPT_WILDCARDS,
            oxm_ids=[ref.OFPOxmId("eth_src"), ref.OFPOxmId("vlan_vid", hasmask=True)],
        ),
        ref.OFPTableFeaturePropExperimenter(
            ref_ofp.OFPTFPT_EXPERIMENTER, None, 0xDEAD, 1, [7, 8]
        ),
    ]
    first = ref.OFPTableFeaturesStats(0, b"t0", 1, 2, 0, 4096, props).serialize()
    second = ref.OFPTableFeaturesStats(1, b"t1", 0, 0, 0, 8, []).serialize()
    return bytes(first) + bytes(second)


def _port_desc_body():
    return struct.pack(
        ref_ofp.OFP_PORT_PACK_STR,
        1,
        b"\x0e\x00\x00\x00\x00\x01",
        b"port1",
        0,
        1,
        0x800,
        0x800,
        0x800,
        0,
        1000,
        2000,
    )


def _experimenter_body():
    return (
        struct.pack(
            ref_ofp.OFP_EXPERIMENTER_MULTIPART_HEADER_PACK_STR, 0x4F4E4600, 1870
        )
        + b"\x01\x02\x03\x04\x05\x06\x07\x08"
    )


BODIES = [
    ("desc", ref_ofp.OFPMP_DESC, _desc_body),
    ("flow", ref_ofp.OFPMP_FLOW, _flow_body),
    ("aggregate", ref_ofp.OFPMP_AGGREGATE, lambda: struct.pack("!QQI4x", 1, 2, 3)),
    ("table", ref_ofp.OFPMP_TABLE, lambda: struct.pack("!B3xIQQ", 1, 2, 3, 4) * 2),
    (
        "port_stats",
        ref_ofp.OFPMP_PORT_STATS,
        lambda: struct.pack(ref_ofp.OFP_PORT_STATS_PACK_STR, *range(15)),
    ),
    (
        "queue",
        ref_ofp.OFPMP_QUEUE,
        lambda: struct.pack(ref_ofp.OFP_QUEUE_STATS_PACK_STR, *range(7)),
    ),
    ("group", ref_ofp.OFPMP_GROUP, _group_body),
    ("group_desc", ref_ofp.OFPMP_GROUP_DESC, _group_desc_body),
    (
        "group_features",
        ref_ofp.OFPMP_GROUP_FEATURES,
        lambda: struct.pack(ref_ofp.OFP_GROUP_FEATURES_PACK_STR, *range(10)),
    ),
    ("meter", ref_ofp.OFPMP_METER, _meter_body),
    ("meter_config", ref_ofp.OFPMP_METER_CONFIG, _meter_config_body),
    (
        "meter_features",
        ref_ofp.OFPMP_METER_FEATURES,
        lambda: struct.pack(ref_ofp.OFP_METER_FEATURES_PACK_STR, 1, 2, 3, 4, 5),
    ),
    ("table_features", ref_ofp.OFPMP_TABLE_FEATURES, _table_features_body),
    ("port_desc", ref_ofp.OFPMP_PORT_DESC, _port_desc_body),
    ("experimenter", ref_ofp.OFPMP_EXPERIMENTER, _experimenter_body),
]

BODY_IDS = [name for name, _, _ in BODIES]


def _reply_bytes(stats_type, body, flags=0):
    header = struct.pack(ref_ofp.OFP_MULTIPART_REPLY_PACK_STR, stats_type, flags)
    length = ref_ofp.OFP_MULTIPART_REPLY_SIZE + len(body)
    return (
        struct.pack(
            ref_ofp.OFP_HEADER_PACK_STR,
            ref_ofp.OFP_VERSION,
            ref_ofp.OFPT_MULTIPART_REPLY,
            length,
            0x12345678,
        )
        + header
        + body
    )


@pytest.mark.parametrize("_name, stats_type, builder", BODIES, ids=BODY_IDS)
@pytest.mark.parametrize("flags", [0, ref_ofp.OFPMPF_REPLY_MORE])
def test_reply_matches_reference(_name, stats_type, builder, flags):
    """A reply parses into the same body os-ken parses."""
    buf = _reply_bytes(stats_type, builder(), flags)
    args = (
        ref_ofp.OFP_VERSION,
        ref_ofp.OFPT_MULTIPART_REPLY,
        len(buf),
        0x12345678,
        buf,
    )
    our_msg = multipart.OFPMultipartReply.parser(DP, *args)
    ref_msg = ref.OFPMultipartReply.parser(REF_DP, *args)
    assert type(our_msg).__name__ == type(ref_msg).__name__
    assert our_msg.type == ref_msg.type
    assert our_msg.flags == ref_msg.flags
    assert our_msg.to_jsondict() == ref_msg.to_jsondict()
    assert str(our_msg) == str(ref_msg)


@pytest.mark.parametrize("_name, stats_type, builder", BODIES, ids=BODY_IDS)
def test_reply_from_jsondict_matches_reference(_name, stats_type, builder):
    """A parsed reply survives a JSON dict round trip, as os-ken's does."""
    buf = _reply_bytes(stats_type, builder())
    args = (
        ref_ofp.OFP_VERSION,
        ref_ofp.OFPT_MULTIPART_REPLY,
        len(buf),
        0x12345678,
        buf,
    )
    our_json = multipart.OFPMultipartReply.parser(DP, *args).to_jsondict()
    ref_json = ref.OFPMultipartReply.parser(REF_DP, *args).to_jsondict()
    ((cls_name, our_params),) = our_json.items()
    our_back = ours(cls_name).from_jsondict(our_params, datapath=DP)
    ref_back = theirs(cls_name).from_jsondict(ref_json[cls_name], datapath=REF_DP)
    assert our_back.to_jsondict() == ref_back.to_jsondict()
    assert str(our_back) == str(ref_back)


def test_reply_dispatches_through_the_message_registry():
    """A multipart reply is reachable from the generic message parser."""
    buf = _reply_bytes(ref_ofp.OFPMP_DESC, _desc_body())
    msg = parser.msg(
        DP, ref_ofp.OFP_VERSION, ref_ofp.OFPT_MULTIPART_REPLY, len(buf), 0x11, buf
    )
    assert isinstance(msg, multipart.OFPDescStatsReply)
    assert msg.body.mfr_desc == b"mfr"
    assert msg.xid == 0x11


def test_reply_of_an_unknown_type_is_rejected():
    """An unregistered multipart type is an error, not a silent None."""
    buf = _reply_bytes(0x1234, b"")
    with pytest.raises(ValueError, match="unknown multipart reply type"):
        multipart.OFPMultipartReply.parser(
            DP, ref_ofp.OFP_VERSION, ref_ofp.OFPT_MULTIPART_REPLY, len(buf), 0, buf
        )


def test_group_desc_stats_length_is_parse_only():
    """os-ken drops the length argument, so a built entry has no length."""
    built = multipart.OFPGroupDescStats(1, 2, [], length=99)
    assert built.to_jsondict() == ref.OFPGroupDescStats(1, 2, [], 99).to_jsondict()
    assert "length" not in built.to_jsondict()["OFPGroupDescStats"]
    parsed = multipart.OFPGroupDescStats.parser(_group_desc_body(), 0)
    assert parsed.to_jsondict()["OFPGroupDescStats"]["length"] == parsed.length


@pytest.mark.parametrize(
    "name, args",
    [
        ("OFPMeterStats", (1, 2, 3, 4, 5, 6, [], 99)),
        ("OFPMeterConfigStats", (1, 2, [], 99)),
        ("OFPTableFeaturesStats", (0, b"n", 1, 2, 3, 4, [], 99)),
    ],
)
def test_body_length_argument_is_ignored(name, args):
    """os-ken accepts a length argument on these bodies and drops it."""
    assert ours(name)(*args).to_jsondict() == theirs(name)(*args).to_jsondict()


# -- table feature properties and ids ---------------------------------------

PROPS = [
    lambda ns: ns("OFPTableFeaturePropInstructions")(ref_ofp.OFPTFPT_INSTRUCTIONS),
    lambda ns: ns("OFPTableFeaturePropInstructions")(
        ref_ofp.OFPTFPT_INSTRUCTIONS_MISS,
        instruction_ids=[
            ns("OFPInstructionId")(ref_ofp.OFPIT_GOTO_TABLE),
            ns("OFPInstructionId")(ref_ofp.OFPIT_WRITE_METADATA),
            ns("OFPInstructionId")(ref_ofp.OFPIT_METER),
        ],
    ),
    lambda ns: ns("OFPTableFeaturePropNextTables")(ref_ofp.OFPTFPT_NEXT_TABLES),
    lambda ns: ns("OFPTableFeaturePropNextTables")(
        ref_ofp.OFPTFPT_NEXT_TABLES_MISS, table_ids=list(range(9))
    ),
    lambda ns: ns("OFPTableFeaturePropActions")(ref_ofp.OFPTFPT_WRITE_ACTIONS),
    lambda ns: ns("OFPTableFeaturePropActions")(
        ref_ofp.OFPTFPT_APPLY_ACTIONS_MISS,
        action_ids=[
            ns("OFPActionId")(ref_ofp.OFPAT_OUTPUT),
            ns("OFPActionId")(ref_ofp.OFPAT_POP_VLAN),
        ],
    ),
    lambda ns: ns("OFPTableFeaturePropOxm")(ref_ofp.OFPTFPT_MATCH),
    lambda ns: ns("OFPTableFeaturePropOxm")(
        ref_ofp.OFPTFPT_APPLY_SETFIELD,
        oxm_ids=[
            ns("OFPOxmId")("in_port"),
            ns("OFPOxmId")("ipv4_dst", hasmask=True),
            ns("OFPOxmId")("tunnel_id"),
        ],
    ),
    lambda ns: ns("OFPTableFeaturePropExperimenter")(
        ref_ofp.OFPTFPT_EXPERIMENTER, None, 0xDEADBEEF, 3, [1, 2, 3]
    ),
    lambda ns: ns("OFPTableFeaturePropExperimenter")(
        ref_ofp.OFPTFPT_EXPERIMENTER_MISS, None, 1, 2, []
    ),
]

PROP_IDS = [str(case(theirs)) for case in PROPS]


@pytest.mark.parametrize("case", PROPS, ids=PROP_IDS)
def test_table_feature_prop_matches_reference(case):
    """A table feature property serializes and parses as os-ken's does."""
    our_prop, ref_prop = case(ours), case(theirs)
    assert our_prop.to_jsondict() == ref_prop.to_jsondict()
    assert str(our_prop) == str(ref_prop)
    our_bytes = bytes(our_prop.serialize())
    ref_bytes = bytes(ref_prop.serialize())
    assert our_bytes == ref_bytes
    assert len(our_bytes) % 8 == 0
    our_parsed, our_rest = multipart.OFPTableFeatureProp.parse(our_bytes + b"tail")
    ref_parsed, ref_rest = ref.OFPTableFeatureProp.parse(ref_bytes + b"tail")
    assert our_rest == ref_rest == b"tail"
    assert our_parsed.to_jsondict() == ref_parsed.to_jsondict()
    assert str(our_parsed) == str(ref_parsed)


def test_table_feature_prop_of_an_unknown_type():
    """An unknown property keeps its body; os-ken keeps the whole buffer."""
    buf = struct.pack("!HH", 0x63, 6) + b"ab\x00\x00" + b"tail"
    prop, rest = multipart.OFPTableFeatureProp.parse(buf)
    assert isinstance(prop, multipart.OFPTableFeaturePropUnknown)
    assert (prop.type, prop.length, prop.data) == (0x63, 6, b"ab")
    assert rest == b"tail"
    assert bytes(prop.serialize()) == buf[:8]


def test_table_feature_prop_with_no_body():
    """The base property serializes to a bare, padded header."""
    prop = multipart.OFPTableFeatureProp(ref_ofp.OFPTFPT_MATCH)
    assert bytes(prop.serialize()) == struct.pack("!HH4x", ref_ofp.OFPTFPT_MATCH, 4)
    assert prop.length == 4


def test_table_feature_prop_with_zero_length_is_rejected():
    """A zero length property would not advance the parse."""
    with pytest.raises(ValueError, match="zero length"):
        multipart.OFPTableFeatureProp.parse(struct.pack("!HH", 0, 0))


@pytest.mark.parametrize("name", ["OFPActionId", "OFPInstructionId"])
def test_id_matches_reference(name):
    """An action or instruction id serializes and parses as os-ken's does."""
    our_id, ref_id = ours(name)(7), theirs(name)(7)
    assert our_id.to_jsondict() == ref_id.to_jsondict()
    assert str(our_id) == str(ref_id)
    our_bytes = bytes(our_id.serialize())
    assert our_bytes == bytes(ref_id.serialize())
    our_parsed, our_rest = ours(name).parse(our_bytes + b"more")
    ref_parsed, ref_rest = theirs(name).parse(our_bytes + b"more")
    assert our_rest == ref_rest == b"more"
    assert our_parsed.to_jsondict() == ref_parsed.to_jsondict()


@pytest.mark.parametrize("name", ["OFPActionId", "OFPInstructionId"])
def test_id_with_zero_length_is_rejected(name):
    """os-ken loops forever on a zero length id; reject it instead."""
    with pytest.raises(ValueError, match="zero length"):
        ours(name).parse(struct.pack("!HH", 1, 0))


@pytest.mark.parametrize(
    "field, hasmask",
    [("in_port", False), ("eth_dst", True), ("tunnel_id", False), ("vlan_vid", True)],
)
def test_oxm_id_matches_reference(field, hasmask):
    """An OXM id serializes and parses as os-ken's does."""
    our_id = multipart.OFPOxmId(field, hasmask)
    ref_id = ref.OFPOxmId(field, hasmask)
    assert our_id.to_jsondict() == ref_id.to_jsondict()
    assert str(our_id) == str(ref_id)
    our_bytes = bytes(our_id.serialize())
    assert our_bytes == bytes(ref_id.serialize())
    our_parsed, our_rest = multipart.OFPOxmId.parse(our_bytes + b"rest")
    ref_parsed, ref_rest = ref.OFPOxmId.parse(our_bytes + b"rest")
    assert our_rest == ref_rest == b"rest"
    assert our_parsed.to_jsondict() == ref_parsed.to_jsondict()


def test_experimenter_oxm_id_parses_as_reference():
    """An experimenter OXM id carries its experimenter after the header."""
    oxm_type = (0xFFFF << 7) | 3
    buf = struct.pack("!II", oxm_type << 9, 0xABCD) + b"rest"
    our_parsed, our_rest = multipart.OFPOxmId.parse(buf)
    ref_parsed, ref_rest = ref.OFPOxmId.parse(buf)
    assert isinstance(our_parsed, multipart.OFPExperimenterOxmId)
    assert our_rest == ref_rest == b"rest"
    assert our_parsed.to_jsondict() == ref_parsed.to_jsondict()
    assert our_parsed.exp_id == 0xABCD


def test_experimenter_oxm_id_serializes():
    """os-ken's serialize returns None here; ours returns the eight bytes."""
    our_id = multipart.OFPExperimenterOxmId("in_port", 0xABCD)
    assert bytes(our_id.serialize()) == bytes(
        multipart.OFPOxmId("in_port").serialize()
    ) + struct.pack("!I", 0xABCD)
    assert ref.OFPExperimenterOxmId("in_port", 0xABCD).serialize() is None


def test_onf_flow_monitor_request_matches_reference():
    """The ONF flow monitor request body serializes as os-ken's does."""
    our_req = multipart.ONFFlowMonitorRequest(1, 2, parser.OFPMatch(in_port=3), 4, 5)
    ref_req = ref.ONFFlowMonitorRequest(1, 2, ref.OFPMatch(in_port=3), 4, 5)
    assert bytes(our_req.serialize()) == bytes(ref_req.serialize())
    assert our_req.match_len == ref_req.match_len
    assert our_req.to_jsondict() == ref_req.to_jsondict()
    assert str(our_req) == str(ref_req)


def test_experimenter_multipart_matches_reference():
    """The experimenter body serializes and parses as os-ken's does."""
    our_body = multipart.OFPExperimenterMultipart(1, 2, b"data")
    ref_body = ref.OFPExperimenterMultipart(1, 2, b"data")
    assert bytes(our_body.serialize()) == bytes(ref_body.serialize())
    assert our_body.to_jsondict() == ref_body.to_jsondict()
    buf = bytes(our_body.serialize())
    assert (
        multipart.OFPExperimenterMultipart.parser(buf, 0).to_jsondict()
        == ref.OFPExperimenterMultipart.parser(buf, 0).to_jsondict()
    )

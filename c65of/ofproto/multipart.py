"""OpenFlow 1.3 multipart (statistics) messages.

A multipart message is an OpenFlow header, a two field multipart header and a
body whose shape depends on the multipart type. A request declares its body
fields in ``_EXTRA`` so that :mod:`c65of.codec` compiles the constructor, and
writes only the line that packs them; a reply parses a body of zero or more
entries and is otherwise declarative.
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

# Structures read the layout configuration of sibling classes.
# pylint: disable=protected-access
# One module per OpenFlow message family; this one covers fifteen of them.
# pylint: disable=too-many-lines

import struct

from c65of.codec import REQUIRED, Codec, TLVRegistry, msg_pack_into
from c65of.ofproto import consts as ofproto
from c65of.ofproto import oxm
from c65of.ofproto.messages import OFPBucket, OFPMeterBandHeader
from c65of.ofproto.base import (
    MsgBase,
    OFPInstruction,
    OFPMatch,
    OFPPort,
    _message,
    _NulString,
    round_up,
)

TABLE_FEATURE_PROPS = TLVRegistry("table feature property")

_HDR = ofproto.OFP_HEADER_SIZE
_MP_SIZE = ofproto.OFP_MULTIPART_REQUEST_SIZE
_TLV_HDR = struct.Struct("!HH")


def _defaults(fields, value):
    """``{name: value}`` for every name in a ``_FIELDS`` style string."""
    return {name: value for name in fields.split()}


# -- multipart bases --------------------------------------------------------


class OFPMultipartRequest(MsgBase):
    """Base for the multipart requests a controller sends.

    ``type`` comes from the class, not from the caller; os-ken's constructors
    accept a ``type_`` argument and ignore it, and so do these.
    """

    _EXTRA = "flags type"
    _DEFAULTS = {"flags": 0}
    _PASS_ARGS = False

    cls_msg_type = ofproto.OFPT_MULTIPART_REQUEST
    cls_stats_type = None
    cls_stats_body_cls = None

    def _init_hook(self):
        self.type = self.cls_stats_type

    def _serialize_body(self):
        msg_pack_into(
            ofproto.OFP_MULTIPART_REQUEST_PACK_STR,
            self.buf,
            _HDR,
            self.type,
            self.flags,
        )
        self._serialize_stats_body()

    def _serialize_stats_body(self):
        """Bytes following the multipart header. An override point."""


@_message
class OFPMultipartReply(MsgBase):
    """Base for the multipart replies a switch sends."""

    # No leading parameter and an explicit attribute set: every reply shares
    # _StatsReply's constructor, and carries only the multipart header and the
    # parsed body.
    _LEAD = ""
    _EXTRA = "body flags type"
    _PASS_ARGS = False

    cls_msg_type = ofproto.OFPT_MULTIPART_REPLY
    cls_stats_type = None
    cls_stats_body_cls = None
    cls_body_single_struct = False
    _STATS_MSG_TYPES = {}
    # os-ken's constructors take a type_ argument and drop it: the attribute
    # exists only on a parsed reply, and only then does it appear in str/json.
    type = None

    def __init__(self, datapath, body=None, flags=None):
        self.datapath = datapath
        self.body = body
        self.flags = flags

    def iter_attrs(self):
        for name in self._ATTRS:
            if name == "type" and self.type is None:
                continue
            yield name, getattr(self, name)

    @staticmethod
    def register_stats_type(body_single_struct=False):
        """Class decorator recording a reply under its multipart type."""

        def _register(cls):
            assert cls.cls_stats_type is not None
            assert cls.cls_stats_type not in OFPMultipartReply._STATS_MSG_TYPES
            assert cls.cls_stats_body_cls is not None
            cls.cls_body_single_struct = body_single_struct
            OFPMultipartReply._STATS_MSG_TYPES[cls.cls_stats_type] = cls
            return cls

        return _register

    @staticmethod
    def _entry_length(entry):
        """Wire length of one body entry. An override point."""
        return entry.length if hasattr(entry, "length") else entry.len

    @classmethod
    def parser_stats_body(cls, buf, msg_len, offset):
        """Parse the body entries between ``offset`` and ``msg_len``."""
        body = []
        while offset < msg_len:
            entry = cls.cls_stats_body_cls.parser(buf, offset)
            body.append(entry)
            offset += cls._entry_length(entry)
        if cls.cls_body_single_struct:
            return body[0]
        return body

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        type_, flags = struct.unpack_from(
            ofproto.OFP_MULTIPART_REPLY_PACK_STR, bytes(buf), _HDR
        )
        subcls = OFPMultipartReply._STATS_MSG_TYPES.get(type_)
        if subcls is None:
            raise ValueError("unknown multipart reply type %d" % type_)
        msg = subcls(datapath)
        msg.set_headers(version, msg_type, msg_len, xid)
        msg.set_buf(buf)
        msg.type = type_
        msg.flags = flags
        msg.body = subcls.parser_stats_body(msg.buf, msg_len, _MP_SIZE)
        return msg


class _StatsReply(OFPMultipartReply):
    """A reply for one multipart type.

    Every one of them takes os-ken's ``(datapath, type_=None, **kwargs)``, so
    they share this constructor rather than repeating it.
    """

    def __init__(self, datapath, type_=None, **kwargs):
        # pylint: disable=unused-argument
        super().__init__(datapath, **kwargs)


class _Stats(Codec):
    """A multipart body entry that is exactly its fixed struct."""

    _ABSTRACT = True
    length = None

    @classmethod
    def parser(cls, buf, offset):
        """Read one body entry from ``buf`` at ``offset``."""
        stats = cls.from_fields(cls.unpack_fixed(buf, offset))
        stats.length = cls._SIZE
        return stats


# -- oxm, action and instruction ids ----------------------------------------


class OFPOxmId(Codec):
    """An OXM field named in a table feature property."""

    _LEAD = "type"
    _EXTRA = "hasmask length"
    _DEFAULTS = {"hasmask": False, "length": None}
    _TYPE = {"ascii": ("type",)}
    _PACK_STR = "!I"
    _EXPERIMENTER_ID_PACK_STR = "!I"

    @classmethod
    def parse(cls, buf):
        """Return ``(id, rest)`` for the OXM id at the head of ``buf``."""
        (header,) = struct.unpack_from(cls._PACK_STR, bytes(buf), 0)
        type_ = oxm.oxm_to_user_header(header >> 9)
        hasmask = ofproto.oxm_tlv_header_extract_hasmask(header)
        # os-ken carries the length of the header itself, always zero on the
        # wire for an id, rather than the length of the field it names.
        length = header & 0xFF
        rest = buf[4:]
        if header >> 16 == oxm.OFPXMC_EXPERIMENTER:
            (exp_id,) = struct.unpack_from(
                cls._EXPERIMENTER_ID_PACK_STR, bytes(rest), 0
            )
            oxm_id = OFPExperimenterOxmId(
                type_=type_, exp_id=exp_id, hasmask=hasmask, length=length
            )
            return oxm_id, rest[4:]
        return cls(type_=type_, hasmask=hasmask, length=length), rest

    def serialize(self):
        """Return the four byte OXM id."""
        self.length = 0
        num = oxm.oxm_from_user_header(self.type)
        assert num >> 7 != oxm.OFPXMC_EXPERIMENTER
        buf = bytearray()
        msg_pack_into(
            self._PACK_STR, buf, 0, (num << 9) | (self.hasmask << 8) | self.length
        )
        return buf


class OFPExperimenterOxmId(OFPOxmId):
    """An OXM field in the experimenter class."""

    _LEAD = "type exp_id"
    _EXTRA = "hasmask length"

    def serialize(self):
        buf = super().serialize()
        msg_pack_into(self._EXPERIMENTER_ID_PACK_STR, buf, 4, self.exp_id)
        return buf


class _Id(Codec):
    """A bare type and length pair naming an action or an instruction."""

    _ABSTRACT = True
    _LEAD = "type"
    _EXTRA = "len"
    _PACK_STR = "!HH"

    @classmethod
    def parse(cls, buf):
        """Return ``(id, rest)`` for the id at the head of ``buf``."""
        type_, len_ = _TLV_HDR.unpack_from(bytes(buf), 0)
        if not len_:
            raise ValueError("%s with zero length" % cls.__name__)
        return cls(type_=type_, len_=len_), buf[len_:]

    def serialize(self):
        """Return the four byte id."""
        self.len = _TLV_HDR.size
        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type, self.len)
        return buf


class OFPActionId(_Id):
    """An action type named in a table feature property."""


class OFPInstructionId(_Id):
    """An instruction type named in a table feature property."""


# -- table feature properties -----------------------------------------------


class OFPTableFeatureProp(Codec):
    """Base for the properties of a table features entry.

    A property is a type and length header, a body, and padding out to an
    eight byte boundary; the padding is not counted in the length.
    """

    _LEAD = "type"
    _EXTRA = "length"
    _PACK_STR = "!HH"

    @classmethod
    def parse(cls, buf):
        """Return ``(property, rest)`` for the property at the head of ``buf``."""
        type_, length = _TLV_HDR.unpack_from(bytes(buf), 0)
        if not length:
            raise ValueError("table feature property with zero length")
        rest = buf[round_up(length, 8) :]
        subcls = TABLE_FEATURE_PROPS.lookup(type_) or OFPTableFeaturePropUnknown
        prop = subcls.parser(buf)
        prop.type = type_
        prop.length = length
        return prop, rest

    @classmethod
    def get_rest(cls, buf):
        """The body of the property at the head of ``buf``."""
        _, length = _TLV_HDR.unpack_from(bytes(buf), 0)
        return buf[_TLV_HDR.size : length]

    def serialize(self):
        """Return the property, padded out to an eight byte boundary."""
        body = self.serialize_body()
        self.length = _TLV_HDR.size + len(body)
        buf = bytearray()
        msg_pack_into(self._PACK_STR, buf, 0, self.type, self.length)
        buf += body
        pad_len = round_up(self.length, 8) - self.length
        msg_pack_into("!%dx" % pad_len, buf, len(buf))
        return buf

    def serialize_body(self):
        """The body between the header and the padding. An override point."""
        return bytearray()


def _prop(*types):
    """Class decorator registering a property class under each of ``types``."""

    def _register(cls):
        for type_ in types:
            TABLE_FEATURE_PROPS.classes[type_] = cls
        return cls

    return _register


class OFPTableFeaturePropUnknown(OFPTableFeatureProp):
    """A property of a type this library does not know."""

    _LEAD = "type"
    _EXTRA = "length data"

    @classmethod
    def parser(cls, buf):
        """Keep the body as opaque bytes."""
        return cls(type_=None, data=cls.get_rest(buf))

    def serialize_body(self):
        return self.data


@_prop(ofproto.OFPTFPT_INSTRUCTIONS, ofproto.OFPTFPT_INSTRUCTIONS_MISS)
class OFPTableFeaturePropInstructions(OFPTableFeatureProp):
    """The instructions a table supports."""

    _LEAD = ""
    _EXTRA = "type length instruction_ids"

    def _init_hook(self):
        if not self.instruction_ids:
            self.instruction_ids = []

    @classmethod
    def parser(cls, buf):
        """Read the instruction ids."""
        rest = cls.get_rest(buf)
        ids = []
        while rest:
            inst_id, rest = OFPInstructionId.parse(rest)
            ids.append(inst_id)
        return cls(instruction_ids=ids)

    def serialize_body(self):
        body = bytearray()
        for inst_id in self.instruction_ids:
            body += inst_id.serialize()
        return body


@_prop(ofproto.OFPTFPT_NEXT_TABLES, ofproto.OFPTFPT_NEXT_TABLES_MISS)
class OFPTableFeaturePropNextTables(OFPTableFeatureProp):
    """The tables a table can go to."""

    _LEAD = ""
    _EXTRA = "type length table_ids"
    _TABLE_ID_PACK_STR = "!B"

    def _init_hook(self):
        if not self.table_ids:
            self.table_ids = []

    @classmethod
    def parser(cls, buf):
        """Read the table ids."""
        rest = cls.get_rest(buf)
        return cls(table_ids=list(rest))

    def serialize_body(self):
        body = bytearray()
        for table_id in self.table_ids:
            msg_pack_into(self._TABLE_ID_PACK_STR, body, len(body), table_id)
        return body


@_prop(
    ofproto.OFPTFPT_WRITE_ACTIONS,
    ofproto.OFPTFPT_WRITE_ACTIONS_MISS,
    ofproto.OFPTFPT_APPLY_ACTIONS,
    ofproto.OFPTFPT_APPLY_ACTIONS_MISS,
)
class OFPTableFeaturePropActions(OFPTableFeatureProp):
    """The actions a table supports."""

    _LEAD = ""
    _EXTRA = "type length action_ids"

    def _init_hook(self):
        if not self.action_ids:
            self.action_ids = []

    @classmethod
    def parser(cls, buf):
        """Read the action ids."""
        rest = cls.get_rest(buf)
        ids = []
        while rest:
            action_id, rest = OFPActionId.parse(rest)
            ids.append(action_id)
        return cls(action_ids=ids)

    def serialize_body(self):
        body = bytearray()
        for action_id in self.action_ids:
            body += action_id.serialize()
        return body


@_prop(
    ofproto.OFPTFPT_MATCH,
    ofproto.OFPTFPT_WILDCARDS,
    ofproto.OFPTFPT_WRITE_SETFIELD,
    ofproto.OFPTFPT_WRITE_SETFIELD_MISS,
    ofproto.OFPTFPT_APPLY_SETFIELD,
    ofproto.OFPTFPT_APPLY_SETFIELD_MISS,
)
class OFPTableFeaturePropOxm(OFPTableFeatureProp):
    """The match fields a table supports."""

    _LEAD = ""
    _EXTRA = "type length oxm_ids"

    def _init_hook(self):
        if not self.oxm_ids:
            self.oxm_ids = []

    @classmethod
    def parser(cls, buf):
        """Read the OXM ids."""
        rest = cls.get_rest(buf)
        ids = []
        while rest:
            oxm_id, rest = OFPOxmId.parse(rest)
            ids.append(oxm_id)
        return cls(oxm_ids=ids)

    def serialize_body(self):
        body = bytearray()
        for oxm_id in self.oxm_ids:
            body += oxm_id.serialize()
        return body


@_prop(ofproto.OFPTFPT_EXPERIMENTER, ofproto.OFPTFPT_EXPERIMENTER_MISS)
class OFPTableFeaturePropExperimenter(Codec):
    """A vendor defined property, carrying a list of 32 bit words."""

    _EXTRA = "type length experimenter exp_type data"
    _DEFAULTS = {"data": bytearray()}
    _PACK_STR = "!HHII"
    _EXPERIMENTER_DATA_PACK_STR = "!I"
    _EXPERIMENTER_DATA_SIZE = 4

    @classmethod
    def parser(cls, buf):
        """Read the experimenter header and the words that follow it."""
        type_, length, experimenter, exp_type = struct.unpack_from(
            ofproto.OFP_PROP_EXPERIMENTER_PACK_STR, bytes(buf), 0
        )
        rest = buf[ofproto.OFP_PROP_EXPERIMENTER_SIZE : length]
        data = [
            word
            for (word,) in struct.iter_unpack(cls._EXPERIMENTER_DATA_PACK_STR, rest)
        ]
        return cls(type_, length, experimenter, exp_type, data)

    def serialize(self):
        """Return the property, padded out to an eight byte boundary."""
        body = bytearray()
        for word in self.data:
            msg_pack_into(self._EXPERIMENTER_DATA_PACK_STR, body, len(body), word)
        self.length = struct.calcsize(self._PACK_STR) + len(body)
        buf = bytearray()
        msg_pack_into(
            self._PACK_STR,
            buf,
            0,
            self.type,
            self.length,
            self.experimenter,
            self.exp_type,
        )
        buf += body
        pad_len = round_up(self.length, 8) - self.length
        msg_pack_into("!%dx" % pad_len, buf, len(buf))
        return buf


# -- OFPMP_DESC -------------------------------------------------------------


class OFPDescStats(_Stats):
    """The switch description: fixed width, NUL padded ASCII strings."""

    _FMT = "256s256s256s32s256s"
    _FIELDS = "mfr_desc hw_desc sw_desc serial_num dp_desc"
    _ATTRS = tuple(_FIELDS.split())
    _DEFAULTS = _defaults(_FIELDS, REQUIRED)
    _CODERS = dict.fromkeys(_ATTRS, _NulString)
    _TYPE = {"ascii": _ATTRS}


class OFPDescStatsRequest(OFPMultipartRequest):
    """Ask for the switch description."""

    cls_stats_type = ofproto.OFPMP_DESC
    cls_stats_body_cls = OFPDescStats


@OFPMultipartReply.register_stats_type(body_single_struct=True)
class OFPDescStatsReply(_StatsReply):
    """The switch description. ``body`` is one ``OFPDescStats``."""

    cls_stats_type = ofproto.OFPMP_DESC
    cls_stats_body_cls = OFPDescStats


# -- OFPMP_FLOW -------------------------------------------------------------


class OFPFlowStats(Codec):
    """One flow entry with its counters, match and instructions."""

    _EXTRA = (
        "table_id duration_sec duration_nsec priority idle_timeout hard_timeout "
        "flags cookie packet_count byte_count match instructions length"
    )

    @classmethod
    def parser(cls, buf, offset):
        """Read one flow entry from ``buf`` at ``offset``."""
        # The fixed part is the length followed by the first ten constructor
        # arguments, in order.
        values = struct.unpack_from(ofproto.OFP_FLOW_STATS_0_PACK_STR, buf, offset)
        length = values[0]
        offset += ofproto.OFP_FLOW_STATS_0_SIZE
        match = OFPMatch.parser(buf, offset)
        match_length = round_up(match.length, 8)
        inst_length = length - (
            ofproto.OFP_FLOW_STATS_SIZE - ofproto.OFP_MATCH_SIZE + match_length
        )
        offset += match_length
        instructions = []
        while inst_length > 0:
            inst = OFPInstruction.parser(buf, offset)
            instructions.append(inst)
            offset += inst.len
            inst_length -= inst.len
        return cls(*values[1:], match, instructions, length)


class OFPFlowStatsRequestBase(OFPMultipartRequest):
    """Base for the two requests that select flows with a match."""

    _EXTRA = "flags table_id out_port out_group cookie cookie_mask match type"
    _DEFAULTS = _defaults(
        "flags table_id out_port out_group cookie cookie_mask match", REQUIRED
    )

    def _serialize_stats_body(self):
        msg_pack_into(
            ofproto.OFP_FLOW_STATS_REQUEST_0_PACK_STR,
            self.buf,
            _MP_SIZE,
            self.table_id,
            self.out_port,
            self.out_group,
            self.cookie,
            self.cookie_mask,
        )
        self.match.serialize(self.buf, _MP_SIZE + ofproto.OFP_FLOW_STATS_REQUEST_0_SIZE)


class OFPFlowStatsRequest(OFPFlowStatsRequestBase):
    """Ask for individual flow statistics."""

    _DEFAULTS = {
        "flags": 0,
        "table_id": ofproto.OFPTT_ALL,
        "out_port": ofproto.OFPP_ANY,
        "out_group": ofproto.OFPG_ANY,
        "cookie": 0,
        "cookie_mask": 0,
    }
    cls_stats_type = ofproto.OFPMP_FLOW
    cls_stats_body_cls = OFPFlowStats

    def _init_hook(self):
        super()._init_hook()
        if self.match is None:
            self.match = OFPMatch()


@OFPMultipartReply.register_stats_type()
class OFPFlowStatsReply(_StatsReply):
    """Individual flow statistics. ``body`` is a list of ``OFPFlowStats``."""

    cls_stats_type = ofproto.OFPMP_FLOW
    cls_stats_body_cls = OFPFlowStats


# -- OFPMP_AGGREGATE --------------------------------------------------------


class OFPAggregateStats(_Stats):
    """Counters summed over the flows a request selected."""

    _FMT = "QQI4x"
    _FIELDS = "packet_count byte_count flow_count"
    _ATTRS = tuple(_FIELDS.split())
    _DEFAULTS = _defaults(_FIELDS, REQUIRED)


class OFPAggregateStatsRequest(OFPFlowStatsRequestBase):
    """Ask for aggregate flow statistics."""

    cls_stats_type = ofproto.OFPMP_AGGREGATE
    cls_stats_body_cls = OFPAggregateStats


@OFPMultipartReply.register_stats_type(body_single_struct=True)
class OFPAggregateStatsReply(_StatsReply):
    """Aggregate flow statistics. ``body`` is one ``OFPAggregateStats``."""

    cls_stats_type = ofproto.OFPMP_AGGREGATE
    cls_stats_body_cls = OFPAggregateStats


# -- OFPMP_TABLE ------------------------------------------------------------


class OFPTableStats(_Stats):
    """Counters for one flow table."""

    _FMT = "B3xIQQ"
    _FIELDS = "table_id active_count lookup_count matched_count"
    _ATTRS = tuple(_FIELDS.split())
    _DEFAULTS = _defaults(_FIELDS, REQUIRED)


class OFPTableStatsRequest(OFPMultipartRequest):
    """Ask for per table statistics."""

    cls_stats_type = ofproto.OFPMP_TABLE
    cls_stats_body_cls = OFPTableStats


@OFPMultipartReply.register_stats_type()
class OFPTableStatsReply(_StatsReply):
    """Per table statistics. ``body`` is a list of ``OFPTableStats``."""

    cls_stats_type = ofproto.OFPMP_TABLE
    cls_stats_body_cls = OFPTableStats


# -- OFPMP_PORT_STATS -------------------------------------------------------


class OFPPortStats(_Stats):
    """Counters for one port."""

    _FMT = "I4xQQQQQQQQQQQQII"
    _FIELDS = (
        "port_no rx_packets tx_packets rx_bytes tx_bytes rx_dropped tx_dropped "
        "rx_errors tx_errors rx_frame_err rx_over_err rx_crc_err collisions "
        "duration_sec duration_nsec"
    )
    _ATTRS = tuple(_FIELDS.split())
    _DEFAULTS = _defaults(_FIELDS, REQUIRED)


class OFPPortStatsRequest(OFPMultipartRequest):
    """Ask for the counters of one port, or of every port."""

    _EXTRA = "flags port_no type"
    _DEFAULTS = {"flags": 0, "port_no": ofproto.OFPP_ANY}
    cls_stats_type = ofproto.OFPMP_PORT_STATS
    cls_stats_body_cls = OFPPortStats

    def _serialize_stats_body(self):
        msg_pack_into(
            ofproto.OFP_PORT_STATS_REQUEST_PACK_STR, self.buf, _MP_SIZE, self.port_no
        )


@OFPMultipartReply.register_stats_type()
class OFPPortStatsReply(_StatsReply):
    """Port counters. ``body`` is a list of ``OFPPortStats``."""

    cls_stats_type = ofproto.OFPMP_PORT_STATS
    cls_stats_body_cls = OFPPortStats


# -- OFPMP_QUEUE ------------------------------------------------------------


class OFPQueueStats(_Stats):
    """Counters for one queue on one port."""

    _FMT = "IIQQQII"
    _FIELDS = (
        "port_no queue_id tx_bytes tx_packets tx_errors duration_sec duration_nsec"
    )
    _ATTRS = tuple(_FIELDS.split())
    _DEFAULTS = _defaults(_FIELDS, REQUIRED)


class OFPQueueStatsRequest(OFPMultipartRequest):
    """Ask for queue counters."""

    _EXTRA = "flags port_no queue_id type"
    _DEFAULTS = {
        "flags": 0,
        "port_no": ofproto.OFPP_ANY,
        "queue_id": ofproto.OFPQ_ALL,
    }
    cls_stats_type = ofproto.OFPMP_QUEUE
    cls_stats_body_cls = OFPQueueStats

    def _serialize_stats_body(self):
        msg_pack_into(
            ofproto.OFP_QUEUE_STATS_REQUEST_PACK_STR,
            self.buf,
            _MP_SIZE,
            self.port_no,
            self.queue_id,
        )


@OFPMultipartReply.register_stats_type()
class OFPQueueStatsReply(_StatsReply):
    """Queue counters. ``body`` is a list of ``OFPQueueStats``."""

    cls_stats_type = ofproto.OFPMP_QUEUE
    cls_stats_body_cls = OFPQueueStats


# -- OFPMP_GROUP ------------------------------------------------------------


class OFPBucketCounter(_Stats):
    """Counters for one bucket of a group."""

    _FMT = "QQ"
    _FIELDS = "packet_count byte_count"
    _DEFAULTS = _defaults(_FIELDS, REQUIRED)


class OFPGroupStats(Codec):
    """Counters for one group, and for each of its buckets."""

    _FMT = "H2xII4xQQII"
    _FIELDS = (
        "length group_id ref_count packet_count byte_count duration_sec duration_nsec"
    )
    _DEFAULTS = _defaults(_FIELDS, None)
    _EXTRA = "bucket_stats"

    @classmethod
    def parser(cls, buf, offset):
        """Read one group's counters from ``buf`` at ``offset``."""
        stats = cls.from_fields(cls.unpack_fixed(buf, offset))
        stats.bucket_stats = []
        end = offset + stats.length
        offset += ofproto.OFP_GROUP_STATS_SIZE
        while end > offset:
            stats.bucket_stats.append(OFPBucketCounter.parser(buf, offset))
            offset += ofproto.OFP_BUCKET_COUNTER_SIZE
        return stats


class OFPGroupStatsRequest(OFPMultipartRequest):
    """Ask for the counters of one group, or of every group."""

    _EXTRA = "flags group_id type"
    _DEFAULTS = {"flags": 0, "group_id": ofproto.OFPG_ALL}
    cls_stats_type = ofproto.OFPMP_GROUP
    cls_stats_body_cls = OFPGroupStats

    def _serialize_stats_body(self):
        msg_pack_into(
            ofproto.OFP_GROUP_STATS_REQUEST_PACK_STR, self.buf, _MP_SIZE, self.group_id
        )


@OFPMultipartReply.register_stats_type()
class OFPGroupStatsReply(_StatsReply):
    """Group counters. ``body`` is a list of ``OFPGroupStats``."""

    cls_stats_type = ofproto.OFPMP_GROUP
    cls_stats_body_cls = OFPGroupStats


# -- OFPMP_GROUP_DESC -------------------------------------------------------


class OFPGroupDescStats(Codec):
    """The definition of one group: its type and its buckets."""

    _EXTRA = "type group_id buckets length"

    def _init_hook(self):
        # os-ken takes a length argument and drops it: the attribute exists
        # only on a parsed entry, and only then does it appear in str/json.
        self.length = None

    def iter_attrs(self):
        for name in self._ATTRS:
            if name == "length" and self.length is None:
                continue
            yield name, getattr(self, name)

    @classmethod
    def parser(cls, buf, offset):
        """Read one group definition from ``buf`` at ``offset``."""
        length, type_, group_id = struct.unpack_from(
            ofproto.OFP_GROUP_DESC_STATS_PACK_STR, buf, offset
        )
        stats = cls(type_, group_id, [])
        stats.length = length
        offset += ofproto.OFP_GROUP_DESC_STATS_SIZE
        parsed = ofproto.OFP_GROUP_DESC_STATS_SIZE
        while parsed < length:
            bucket = OFPBucket.parser(buf, offset)
            stats.buckets.append(bucket)
            offset += bucket.len
            parsed += bucket.len
        return stats


class OFPGroupDescStatsRequest(OFPMultipartRequest):
    """Ask for the definition of every group."""

    cls_stats_type = ofproto.OFPMP_GROUP_DESC
    cls_stats_body_cls = OFPGroupDescStats


@OFPMultipartReply.register_stats_type()
class OFPGroupDescStatsReply(_StatsReply):
    """Group definitions. ``body`` is a list of ``OFPGroupDescStats``."""

    cls_stats_type = ofproto.OFPMP_GROUP_DESC
    cls_stats_body_cls = OFPGroupDescStats


# -- OFPMP_GROUP_FEATURES ---------------------------------------------------


class OFPGroupFeaturesStats(Codec):
    """What the switch's group table supports."""

    _EXTRA = "types capabilities max_groups actions"
    _ATTRS = tuple(_EXTRA.split())
    _DEFAULTS = _defaults(_EXTRA, REQUIRED)
    length = None

    @classmethod
    def parser(cls, buf, offset):
        """Read the group features from ``buf`` at ``offset``."""
        values = struct.unpack_from(ofproto.OFP_GROUP_FEATURES_PACK_STR, buf, offset)
        stats = cls(values[0], values[1], list(values[2:6]), list(values[6:10]))
        stats.length = ofproto.OFP_GROUP_FEATURES_SIZE
        return stats


class OFPGroupFeaturesStatsRequest(OFPMultipartRequest):
    """Ask what the group table supports."""

    cls_stats_type = ofproto.OFPMP_GROUP_FEATURES
    cls_stats_body_cls = OFPGroupFeaturesStats


@OFPMultipartReply.register_stats_type(body_single_struct=True)
class OFPGroupFeaturesStatsReply(_StatsReply):
    """Group table features. ``body`` is one ``OFPGroupFeaturesStats``."""

    cls_stats_type = ofproto.OFPMP_GROUP_FEATURES
    cls_stats_body_cls = OFPGroupFeaturesStats


# -- OFPMP_METER ------------------------------------------------------------


class OFPMeterBandStats(_Stats):
    """Counters for one band of a meter."""

    _FMT = "QQ"
    _FIELDS = "packet_band_count byte_band_count"
    _DEFAULTS = _defaults(_FIELDS, REQUIRED)


class OFPMeterStats(Codec):
    """Counters for one meter, and for each of its bands."""

    _EXTRA = (
        "meter_id flow_count packet_in_count byte_in_count duration_sec "
        "duration_nsec band_stats len"
    )

    def _init_hook(self):
        # os-ken takes a len_ argument and drops it.
        self.len = 0

    @classmethod
    def parser(cls, buf, offset):
        """Read one meter's counters from ``buf`` at ``offset``."""
        # The fixed part is the meter id, the length, and then the rest of the
        # constructor arguments in order.
        values = struct.unpack_from(ofproto.OFP_METER_STATS_PACK_STR, buf, offset)
        len_ = values[1]
        stats = cls(values[0], *values[2:], [])
        stats.len = len_
        offset += ofproto.OFP_METER_STATS_SIZE
        parsed = ofproto.OFP_METER_STATS_SIZE
        while parsed < len_:
            stats.band_stats.append(OFPMeterBandStats.parser(buf, offset))
            offset += ofproto.OFP_METER_BAND_STATS_SIZE
            parsed += ofproto.OFP_METER_BAND_STATS_SIZE
        return stats


class OFPMeterStatsRequest(OFPMultipartRequest):
    """Ask for the counters of one meter, or of every meter."""

    _EXTRA = "flags meter_id type"
    _DEFAULTS = {"flags": 0, "meter_id": ofproto.OFPM_ALL}
    cls_stats_type = ofproto.OFPMP_METER
    cls_stats_body_cls = OFPMeterStats

    def _serialize_stats_body(self):
        msg_pack_into(
            ofproto.OFP_METER_MULTIPART_REQUEST_PACK_STR,
            self.buf,
            _MP_SIZE,
            self.meter_id,
        )


@OFPMultipartReply.register_stats_type()
class OFPMeterStatsReply(_StatsReply):
    """Meter counters. ``body`` is a list of ``OFPMeterStats``."""

    cls_stats_type = ofproto.OFPMP_METER
    cls_stats_body_cls = OFPMeterStats


# -- OFPMP_METER_CONFIG -----------------------------------------------------


class OFPMeterConfigStats(Codec):
    """The definition of one meter: its flags and its bands."""

    _EXTRA = "flags meter_id bands length"

    def _init_hook(self):
        # os-ken takes a length argument and drops it.
        self.length = None

    @classmethod
    def parser(cls, buf, offset):
        """Read one meter definition from ``buf`` at ``offset``."""
        length, flags, meter_id = struct.unpack_from(
            ofproto.OFP_METER_CONFIG_PACK_STR, buf, offset
        )
        config = cls(flags, meter_id, [])
        config.length = length
        offset += ofproto.OFP_METER_CONFIG_SIZE
        parsed = ofproto.OFP_METER_CONFIG_SIZE
        while parsed < length:
            band = OFPMeterBandHeader.parser(buf, offset)
            config.bands.append(band)
            offset += band.len
            parsed += band.len
        return config


class OFPMeterConfigStatsRequest(OFPMultipartRequest):
    """Ask for the definition of one meter, or of every meter."""

    _EXTRA = "flags meter_id type"
    _DEFAULTS = {"flags": 0, "meter_id": ofproto.OFPM_ALL}
    cls_stats_type = ofproto.OFPMP_METER_CONFIG
    cls_stats_body_cls = OFPMeterConfigStats

    def _serialize_stats_body(self):
        msg_pack_into(
            ofproto.OFP_METER_MULTIPART_REQUEST_PACK_STR,
            self.buf,
            _MP_SIZE,
            self.meter_id,
        )


@OFPMultipartReply.register_stats_type()
class OFPMeterConfigStatsReply(_StatsReply):
    """Meter definitions. ``body`` is a list of ``OFPMeterConfigStats``."""

    cls_stats_type = ofproto.OFPMP_METER_CONFIG
    cls_stats_body_cls = OFPMeterConfigStats


# -- OFPMP_METER_FEATURES ---------------------------------------------------


class OFPMeterFeaturesStats(_Stats):
    """What the switch's meter table supports."""

    _FMT = "IIIBB2x"
    _FIELDS = "max_meter band_types capabilities max_bands max_color"
    _ATTRS = tuple(_FIELDS.split())
    _DEFAULTS = _defaults(_FIELDS, REQUIRED)


class OFPMeterFeaturesStatsRequest(OFPMultipartRequest):
    """Ask what the meter table supports."""

    cls_stats_type = ofproto.OFPMP_METER_FEATURES
    cls_stats_body_cls = OFPMeterFeaturesStats


@OFPMultipartReply.register_stats_type()
class OFPMeterFeaturesStatsReply(_StatsReply):
    """Meter table features. ``body`` is a list of ``OFPMeterFeaturesStats``."""

    cls_stats_type = ofproto.OFPMP_METER_FEATURES
    cls_stats_body_cls = OFPMeterFeaturesStats


# -- OFPMP_TABLE_FEATURES ---------------------------------------------------


class OFPTableFeaturesStats(Codec):
    """The capabilities of one flow table, as a list of properties."""

    _EXTRA = (
        "table_id name metadata_match metadata_write config max_entries "
        "properties length"
    )
    _TYPE = {"utf-8": ("name",)}

    def _init_hook(self):
        # os-ken takes a length argument and drops it.
        self.length = None

    @classmethod
    def parser(cls, buf, offset):
        """Read one table's features from ``buf`` at ``offset``."""
        # The fixed part is the length followed by the first six constructor
        # arguments, in order.
        values = struct.unpack_from(ofproto.OFP_TABLE_FEATURES_PACK_STR, buf, offset)
        length = values[0]
        properties = []
        rest = buf[offset + ofproto.OFP_TABLE_FEATURES_SIZE : offset + length]
        while rest:
            prop, rest = OFPTableFeatureProp.parse(rest)
            properties.append(prop)
        stats = cls(values[1], values[2].rstrip(b"\0"), *values[3:], properties)
        stats.length = length
        return stats

    def serialize(self):
        """Return this table's features and every one of its properties."""
        body = bytearray()
        for prop in self.properties:
            body += prop.serialize()
        self.length = ofproto.OFP_TABLE_FEATURES_SIZE + len(body)
        buf = bytearray()
        msg_pack_into(
            ofproto.OFP_TABLE_FEATURES_PACK_STR,
            buf,
            0,
            self.length,
            self.table_id,
            self.name,
            self.metadata_match,
            self.metadata_write,
            self.config,
            self.max_entries,
        )
        return buf + body


class OFPTableFeaturesStatsRequest(OFPMultipartRequest):
    """Ask for, or set, the features of every table."""

    _EXTRA = "flags body type"
    _DEFAULTS = {"flags": 0}
    cls_stats_type = ofproto.OFPMP_TABLE_FEATURES
    cls_stats_body_cls = OFPTableFeaturesStats

    def _init_hook(self):
        super()._init_hook()
        if not self.body:
            self.body = []

    def _serialize_stats_body(self):
        for stats in self.body:
            self.buf += stats.serialize()


@OFPMultipartReply.register_stats_type()
class OFPTableFeaturesStatsReply(_StatsReply):
    """Table features. ``body`` is a list of ``OFPTableFeaturesStats``."""

    cls_stats_type = ofproto.OFPMP_TABLE_FEATURES
    cls_stats_body_cls = OFPTableFeaturesStats


# -- OFPMP_PORT_DESC --------------------------------------------------------


class OFPPortDescStatsRequest(OFPMultipartRequest):
    """Ask for a description of every port."""

    cls_stats_type = ofproto.OFPMP_PORT_DESC
    cls_stats_body_cls = OFPPort


@OFPMultipartReply.register_stats_type()
class OFPPortDescStatsReply(_StatsReply):
    """Port descriptions. ``body`` is a list of ``OFPPort``."""

    cls_stats_type = ofproto.OFPMP_PORT_DESC
    cls_stats_body_cls = OFPPort

    @staticmethod
    def _entry_length(entry):
        # pylint: disable=unused-argument
        # OFPPort is a fixed size struct and carries no length of its own.
        return ofproto.OFP_PORT_SIZE


# -- OFPMP_EXPERIMENTER -----------------------------------------------------


class OFPExperimenterMultipart(Codec):
    """A vendor defined multipart body."""

    _EXTRA = "experimenter exp_type data"
    _ATTRS = tuple(_EXTRA.split())
    _DEFAULTS = _defaults(_EXTRA, REQUIRED)
    length = None

    @classmethod
    def parser(cls, buf, offset):
        """Read the experimenter header and keep the rest as opaque bytes."""
        experimenter, exp_type = struct.unpack_from(
            ofproto.OFP_EXPERIMENTER_MULTIPART_HEADER_PACK_STR, buf, offset
        )
        data = buf[offset + ofproto.OFP_EXPERIMENTER_MULTIPART_HEADER_SIZE :]
        stats = cls(experimenter, exp_type, data)
        # os-ken advances the reply body loop by the meter features size here.
        stats.length = ofproto.OFP_METER_FEATURES_SIZE
        return stats

    def serialize(self):
        """Return the experimenter header followed by the data."""
        buf = bytearray()
        msg_pack_into(
            ofproto.OFP_EXPERIMENTER_MULTIPART_HEADER_PACK_STR,
            buf,
            0,
            self.experimenter,
            self.exp_type,
        )
        return buf + self.data


class OFPExperimenterStatsRequestBase(OFPMultipartRequest):
    """Base for the vendor defined requests."""

    _EXTRA = "flags experimenter exp_type type"
    _DEFAULTS = _defaults("flags experimenter exp_type", REQUIRED)
    cls_stats_type = ofproto.OFPMP_EXPERIMENTER
    cls_stats_body_cls = OFPExperimenterMultipart


class OFPExperimenterStatsRequest(OFPExperimenterStatsRequestBase):
    """A vendor defined request carrying opaque data."""

    _EXTRA = "flags experimenter exp_type data type"
    _DEFAULTS = _defaults("flags experimenter exp_type data", REQUIRED)

    def _serialize_stats_body(self):
        body = OFPExperimenterMultipart(
            experimenter=self.experimenter, exp_type=self.exp_type, data=self.data
        )
        self.buf += body.serialize()


class ONFFlowMonitorRequest(Codec):
    """One ONF flow monitor request, the body of ``ONFFlowMonitorStatsRequest``."""

    _LEAD = "id flags"
    _EXTRA = "match out_port table_id match_len"
    _DEFAULTS = {
        "match": OFPMatch(),
        "out_port": ofproto.OFPP_ANY,
        "table_id": ofproto.OFPTT_ALL,
    }

    def serialize(self):
        """Return the request, with the match stripped of its own header."""
        bin_match = bytearray()
        self.match.serialize(bin_match, 0)
        # Carry the OXM TLVs only: drop the match header, keep the padding.
        bin_match = bin_match[ofproto.OFP_MATCH_SIZE - 4 : self.match.length]
        self.match_len = len(bin_match)
        buf = bytearray()
        msg_pack_into(
            ofproto.ONF_FLOW_MONITOR_REQUEST_PACK_STR,
            buf,
            0,
            self.id,
            self.flags,
            self.match_len,
            self.out_port,
            self.table_id,
        )
        buf += bin_match
        buf += bytearray(round_up(self.match_len, 8) - self.match_len)
        return buf


class ONFFlowMonitorStatsRequest(OFPExperimenterStatsRequestBase):
    """The ONF flow monitor request, an experimenter multipart request."""

    _EXTRA = "flags body type experimenter exp_type"
    _DEFAULTS = {"flags": REQUIRED}

    def _init_hook(self):
        super()._init_hook()
        self.experimenter = ofproto.ONF_EXPERIMENTER_ID
        self.exp_type = ofproto.ONFMP_FLOW_MONITOR
        if not self.body:
            self.body = []

    def _serialize_stats_body(self):
        data = bytearray()
        for request in self.body:
            data += request.serialize()
        body = OFPExperimenterMultipart(
            experimenter=self.experimenter, exp_type=self.exp_type, data=data
        )
        self.buf += body.serialize()


@OFPMultipartReply.register_stats_type(body_single_struct=True)
class OFPExperimenterStatsReply(_StatsReply):
    """A vendor defined reply. ``body`` is one ``OFPExperimenterMultipart``."""

    cls_stats_type = ofproto.OFPMP_EXPERIMENTER
    cls_stats_body_cls = OFPExperimenterMultipart

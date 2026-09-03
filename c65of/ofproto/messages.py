"""OpenFlow 1.3 messages other than the multipart family.

Each message declares its wire layout and lets :mod:`c65of.codec` compile the
constructor, the packer and the JSON dict form; only the variable length tails
-- a match, an action list, a bucket list -- are written by hand. The
structures messages carry but multipart does not (hello elements, buckets,
meter bands, queues and their properties) live here too.

Switch to controller messages do not serialize their body, which is what
os-ken does: their ``serialize`` emits the OpenFlow header alone.
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

import struct

from c65of.codec import REQUIRED, Codec, msg_pack_into
from c65of.lib.type_desc import MacAddr as _MAC
from c65of.ofproto import consts as ofproto
from c65of.ofproto.parser import (
    METER_BANDS,
    QUEUE_PROPS,
    MsgBase,
    OFPAction,
    OFPInstruction,
    OFPMatch,
    OFPPort,
    _message,
    _Tagged,
    _TLV_HDR,
    round_up,
)

_HDR = ofproto.OFP_HEADER_SIZE


def _none(names):
    """``_DEFAULTS`` giving each of ``names`` a default of ``None``."""
    return dict.fromkeys(names.split(), None)


def _required(names):
    """``_DEFAULTS`` making each of ``names`` a parameter with no default."""
    return dict.fromkeys(names.split(), REQUIRED)


class _SwitchMsg(MsgBase):
    """A message only a switch sends.

    os-ken gives these no body serializer, so serializing one emits the
    OpenFlow header and nothing else. Kept for byte compatibility.
    """

    _ABSTRACT = True

    def _serialize_body(self):
        pass


# -- hello ------------------------------------------------------------------


class OFPHelloElemVersionBitmap(Codec):
    """The versions a device speaks, as a bitmap hello element."""

    _LEAD = "versions"
    _EXTRA = "type length"

    _bitmaps = None

    def _init_hook(self):
        self.type = ofproto.OFPHET_VERSIONBITMAP
        self.length = None
        self._bitmaps = None

    @classmethod
    def parser(cls, buf, offset):
        """Read a version bitmap element from ``buf`` at ``offset``."""
        type_, length = struct.unpack_from(
            ofproto.OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_PACK_STR, buf, offset
        )
        assert type_ == ofproto.OFPHET_VERSIONBITMAP
        count = (length - ofproto.OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_SIZE) // 4
        bitmaps = struct.unpack_from(
            "!%dI" % count,
            buf,
            offset + ofproto.OFP_HELLO_ELEM_VERSIONBITMAP_HEADER_SIZE,
        )
        # os-ken stops at bit 30 of each word; matched for compatibility.
        elem = cls(
            [
                i * 32 + shift
                for i, bitmap in enumerate(bitmaps)
                for shift in range(31)
                if bitmap & (1 << shift)
            ]
        )
        elem.length = length
        elem._bitmaps = list(bitmaps)
        return elem


@_message
class OFPHello(MsgBase):
    """Version negotiation, exchanged when a connection opens."""

    cls_msg_type = ofproto.OFPT_HELLO
    _EXTRA = "elements"

    def _init_hook(self):
        if not self.elements:
            self.elements = []

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        buf = bytes(buf)
        elements = []
        while offset < msg_len:
            type_, length = struct.unpack_from(
                ofproto.OFP_HELLO_ELEM_HEADER_PACK_STR, buf, offset
            )
            # Only the version bitmap element is defined by OpenFlow 1.3.
            if type_ == ofproto.OFPHET_VERSIONBITMAP:
                elements.append(OFPHelloElemVersionBitmap.parser(buf, offset))
            offset += length
        return {"elements": elements}


# -- errors, echoes and experimenter ----------------------------------------


@_message
class OFPErrorMsg(MsgBase):
    """A problem report from the switch.

    ``type == OFPET_EXPERIMENTER`` replaces ``code`` with an experimenter id
    and an experimenter defined type, so both the body layout and the set of
    attributes depend on the type.
    """

    cls_msg_type = ofproto.OFPT_ERROR
    _EXTRA = "type code data"

    exp_type = None
    experimenter = None

    def __init__(self, datapath, type_=None, code=None, data=None, **kwargs):
        self.datapath = datapath
        self.type = type_
        self.code = code
        self.data = data.encode("ascii") if isinstance(data, str) else data
        if self.type == ofproto.OFPET_EXPERIMENTER:
            self.exp_type = kwargs.get("exp_type", None)
            self.experimenter = kwargs.get("experimenter", None)

    def iter_attrs(self):
        yield "code", self.code
        yield "data", self.data
        if self.type == ofproto.OFPET_EXPERIMENTER:
            yield "exp_type", self.exp_type
            yield "experimenter", self.experimenter
        yield "type", self.type

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        (type_,) = struct.unpack_from("!H", bytes(buf), _HDR)
        if type_ == ofproto.OFPET_EXPERIMENTER:
            type_, exp_type, experimenter = struct.unpack_from(
                ofproto.OFP_ERROR_EXPERIMENTER_MSG_PACK_STR, buf, _HDR
            )
            message = cls(
                datapath,
                type_=type_,
                exp_type=exp_type,
                experimenter=experimenter,
                data=buf[ofproto.OFP_ERROR_EXPERIMENTER_MSG_SIZE :],
            )
        else:
            type_, code = struct.unpack_from(ofproto.OFP_ERROR_MSG_PACK_STR, buf, _HDR)
            message = cls(
                datapath, type_=type_, code=code, data=buf[ofproto.OFP_ERROR_MSG_SIZE :]
            )
        message.set_headers(version, msg_type, msg_len, xid)
        message.set_buf(buf)
        return message

    def _serialize_body(self):
        assert self.data is not None
        if self.type == ofproto.OFPET_EXPERIMENTER:
            self.buf += struct.pack(
                ofproto.OFP_ERROR_EXPERIMENTER_MSG_PACK_STR,
                self.type,
                self.exp_type,
                self.experimenter,
            )
        else:
            self.buf += struct.pack(
                ofproto.OFP_ERROR_MSG_PACK_STR, self.type, self.code
            )
        self.buf += self.data


def OFPErrorExperimenterMsg(  # pylint: disable=invalid-name
    datapath, type_=None, exp_type=None, experimenter=None, data=None
):
    """Deprecated spelling of an experimenter error, kept from os-ken."""
    del type_
    message = OFPErrorMsg(datapath, data=data)
    message.type = ofproto.OFPET_EXPERIMENTER
    message.exp_type = exp_type
    message.experimenter = experimenter
    return message


class _EchoMsg(MsgBase):
    """An echo request or reply: a header and arbitrary data."""

    _ABSTRACT = True
    _EXTRA = "data"

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        return {"data": bytes(buf)[offset:]}

    def _serialize_tail(self):
        if self.data is not None:
            self.buf += self.data


@_message
class OFPEchoRequest(_EchoMsg):
    """Liveness probe."""

    cls_msg_type = ofproto.OFPT_ECHO_REQUEST


@_message
class OFPEchoReply(_EchoMsg):
    """Answer to a liveness probe."""

    cls_msg_type = ofproto.OFPT_ECHO_REPLY

    def _serialize_tail(self):
        assert self.data is not None
        self.buf += self.data


@_message
class OFPExperimenter(MsgBase):
    """Vendor defined message."""

    cls_msg_type = ofproto.OFPT_EXPERIMENTER
    _FMT = "II"
    _FIELDS = "experimenter exp_type"
    _DEFAULTS = _none("experimenter exp_type")
    _EXTRA = "data"

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        return {"data": bytes(buf)[offset:]}

    def _serialize_tail(self):
        assert self.data is not None
        self.buf += self.data


# -- features and configuration ---------------------------------------------


@_message
class OFPFeaturesRequest(MsgBase):
    """Ask the switch what it is."""

    cls_msg_type = ofproto.OFPT_FEATURES_REQUEST


@_message
class OFPSwitchFeatures(_SwitchMsg):
    """What the switch is: its datapath id, table count and capabilities."""

    cls_msg_type = ofproto.OFPT_FEATURES_REPLY
    # The trailing reserved word is skipped rather than kept as an attribute.
    _FMT = "QIBB2xI4x"
    _FIELDS = "datapath_id n_buffers n_tables auxiliary_id capabilities"
    _DEFAULTS = _none(_FIELDS)


@_message
class OFPGetConfigRequest(MsgBase):
    """Ask for the switch's fragment handling and miss send length."""

    cls_msg_type = ofproto.OFPT_GET_CONFIG_REQUEST


@_message
class OFPGetConfigReply(_SwitchMsg):
    """The switch's fragment handling and miss send length."""

    cls_msg_type = ofproto.OFPT_GET_CONFIG_REPLY
    _FMT = "HH"
    _FIELDS = "flags miss_send_len"
    _DEFAULTS = _none(_FIELDS)


@_message
class OFPSetConfig(MsgBase):
    """Set the switch's fragment handling and miss send length."""

    cls_msg_type = ofproto.OFPT_SET_CONFIG
    _FMT = "HH"
    _FIELDS = "flags miss_send_len"


# -- asynchronous switch to controller messages -----------------------------


@_message
class OFPPacketIn(_SwitchMsg):
    """A packet punted to the controller."""

    cls_msg_type = ofproto.OFPT_PACKET_IN
    _FMT = "IHBBQ"
    _FIELDS = "buffer_id total_len reason table_id cookie"
    _DEFAULTS = _none(_FIELDS)
    _EXTRA = "match data"

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        buf = bytes(buf)
        match = OFPMatch.parser(buf, offset)
        # The match is padded to eight bytes, then two more pad bytes precede
        # the packet itself, which is truncated to the reported total length.
        data = buf[offset + round_up(match.length, 8) + 2 :]
        (total_len,) = struct.unpack_from("!H", buf, _HDR + 4)
        if total_len < len(data):
            data = data[:total_len]
        return {"match": match, "data": data}


@_message
class OFPFlowRemoved(_SwitchMsg):
    """Notification that a flow entry has gone."""

    cls_msg_type = ofproto.OFPT_FLOW_REMOVED
    _FMT = "QHBBIIHHQQ"
    _FIELDS = (
        "cookie priority reason table_id duration_sec duration_nsec "
        "idle_timeout hard_timeout packet_count byte_count"
    )
    _DEFAULTS = _none(_FIELDS)
    _EXTRA = "match"

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        return {"match": OFPMatch.parser(bytes(buf), offset)}


@_message
class OFPPortStatus(_SwitchMsg):
    """Notification that a port has been added, removed or changed."""

    cls_msg_type = ofproto.OFPT_PORT_STATUS
    _FMT = "B7x"
    _FIELDS = "reason"
    _DEFAULTS = _none(_FIELDS)
    _EXTRA = "desc"

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        return {"desc": OFPPort.parser(bytes(buf), offset)}


# -- controller to switch messages ------------------------------------------


@_message
class OFPPacketOut(MsgBase):
    """Send a packet out of the switch, optionally through an action list."""

    cls_msg_type = ofproto.OFPT_PACKET_OUT
    _EXTRA = "buffer_id in_port actions data actions_len"

    def _init_hook(self):
        assert self.in_port is not None
        # os-ken ignores the actions_len argument; the value is computed.
        self.actions_len = 0

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        buf = bytes(buf)
        buffer_id, in_port, actions_len = struct.unpack_from(
            ofproto.OFP_PACKET_OUT_PACK_STR, buf, offset
        )
        offset = ofproto.OFP_PACKET_OUT_SIZE
        end = offset + actions_len
        actions = []
        while offset < end:
            action = OFPAction.parser(buf, offset)
            actions.append(action)
            offset += action.len
        return {
            "buffer_id": buffer_id,
            "in_port": in_port,
            "actions": actions,
            # An empty tail is no data, so that a parsed message serializes
            # back to the bytes it came from.
            "data": buf[end:] or None,
        }

    def _serialize_body(self):
        body = bytearray()
        for action in self.actions:
            action.serialize(body, len(body))
        self.actions_len = len(body)
        self.buf += struct.pack(
            ofproto.OFP_PACKET_OUT_PACK_STR,
            self.buffer_id,
            self.in_port,
            self.actions_len,
        )
        self.buf += body
        if self.data is not None:
            assert self.buffer_id == ofproto.OFP_NO_BUFFER
            self.buf += self.data


@_message
class OFPFlowMod(MsgBase):
    """Add, change or delete a flow entry."""

    cls_msg_type = ofproto.OFPT_FLOW_MOD
    _FMT = "QQBBHHHIIIH2x"
    _FIELDS = (
        "cookie cookie_mask table_id command idle_timeout hard_timeout "
        "priority buffer_id out_port out_group flags"
    )
    _DEFAULTS = {
        "command": ofproto.OFPFC_ADD,
        "priority": ofproto.OFP_DEFAULT_PRIORITY,
        "buffer_id": ofproto.OFP_NO_BUFFER,
    }
    _EXTRA = "match instructions"

    def _init_hook(self):
        if self.match is None:
            self.match = OFPMatch()
        assert isinstance(self.match, OFPMatch)
        if not self.instructions:
            self.instructions = []

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        match = OFPMatch.parser(buf, offset)
        offset += round_up(match.length, 8)
        instructions = []
        while offset < msg_len:
            inst = OFPInstruction.parser(buf, offset)
            instructions.append(inst)
            offset += inst.len
        return {"match": match, "instructions": instructions}

    def _serialize_tail(self):
        offset = len(self.buf) + self.match.serialize(self.buf, len(self.buf))
        for inst in self.instructions:
            inst.serialize(self.buf, offset)
            offset += inst.len


class OFPBucket(Codec):
    """One action bucket of a group.

    ``len`` is not set by the constructor, only by parsing or serializing, so
    it stays out of the JSON dict form until one of those has run.
    """

    _EXTRA = "weight watch_port watch_group actions len"
    _DEFAULTS = {
        "weight": 0,
        "watch_port": ofproto.OFPP_ANY,
        "watch_group": ofproto.OFPG_ANY,
        "actions": None,
        "len": None,
    }

    def _init_hook(self):
        self.len = None

    def iter_attrs(self):
        for name in self._ATTRS:
            if name != "len" or self.len is not None:
                yield name, getattr(self, name)

    @classmethod
    def parser(cls, buf, offset):
        """Read one bucket from ``buf`` at ``offset``."""
        len_, weight, watch_port, watch_group = struct.unpack_from(
            ofproto.OFP_BUCKET_PACK_STR, buf, offset
        )
        bucket = cls(weight, watch_port, watch_group, [])
        bucket.len = len_
        offset += ofproto.OFP_BUCKET_SIZE
        end = offset + len_ - ofproto.OFP_BUCKET_SIZE
        while offset < end:
            action = OFPAction.parser(buf, offset)
            bucket.actions.append(action)
            offset += action.len
        return bucket

    def serialize(self, buf, offset):
        """Write this bucket into ``buf``, returning its length."""
        action_offset = offset + ofproto.OFP_BUCKET_SIZE
        for action in self.actions:
            action_offset += action.serialize(buf, action_offset)
        self.len = round_up(action_offset - offset, 8)
        msg_pack_into(
            ofproto.OFP_BUCKET_PACK_STR,
            buf,
            offset,
            self.len,
            self.weight,
            self.watch_port,
            self.watch_group,
        )
        return self.len


@_message
class OFPGroupMod(MsgBase):
    """Add, change or delete a group."""

    cls_msg_type = ofproto.OFPT_GROUP_MOD
    _FMT = "HBxI"
    _FIELDS = "command type group_id"
    _DEFAULTS = {"command": ofproto.OFPGC_ADD, "type": ofproto.OFPGT_ALL}
    _EXTRA = "buckets"

    def _init_hook(self):
        if not self.buckets:
            self.buckets = []

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        buckets = []
        while offset < msg_len:
            bucket = OFPBucket.parser(buf, offset)
            buckets.append(bucket)
            offset += bucket.len
        return {"buckets": buckets}

    def _serialize_tail(self):
        offset = len(self.buf)
        for bucket in self.buckets:
            offset += bucket.serialize(self.buf, offset)


@_message
class OFPPortMod(MsgBase):
    """Change the administrative state of a port."""

    cls_msg_type = ofproto.OFPT_PORT_MOD
    _FMT = "I4x6s2xIII4x"
    _FIELDS = "port_no hw_addr config mask advertise"
    _DEFAULTS = {"hw_addr": "00:00:00:00:00:00"}
    _CODERS = {"hw_addr": _MAC}
    _TYPE = {"ascii": ("hw_addr",)}


@_message
class OFPTableMod(MsgBase):
    """Change a table's configuration."""

    cls_msg_type = ofproto.OFPT_TABLE_MOD
    _FMT = "B3xI"
    _FIELDS = "table_id config"
    _DEFAULTS = _required(_FIELDS)


# -- meters -----------------------------------------------------------------


class OFPMeterBandHeader(_Tagged):
    """Base for meter bands, dispatching on the band type."""

    _ABSTRACT = True
    _REGISTRY = METER_BANDS


@METER_BANDS.register
class OFPMeterBandDrop(OFPMeterBandHeader):
    """Drop packets above the band's rate."""

    _TYPE_ID = ofproto.OFPMBT_DROP
    _FMT = "II4x"
    _FIELDS = "rate burst_size"


@METER_BANDS.register
class OFPMeterBandDscpRemark(OFPMeterBandHeader):
    """Raise the drop precedence of packets above the band's rate."""

    _TYPE_ID = ofproto.OFPMBT_DSCP_REMARK
    _FMT = "IIB3x"
    _FIELDS = "rate burst_size prec_level"


@METER_BANDS.register
class OFPMeterBandExperimenter(OFPMeterBandHeader):
    """Vendor defined meter band."""

    _TYPE_ID = ofproto.OFPMBT_EXPERIMENTER
    _FMT = "III"
    _FIELDS = "rate burst_size experimenter"
    _DEFAULTS = {"experimenter": None}


@_message
class OFPMeterMod(MsgBase):
    """Add, change or delete a meter."""

    cls_msg_type = ofproto.OFPT_METER_MOD
    _FMT = "HHI"
    _FIELDS = "command flags meter_id"
    _DEFAULTS = {
        "command": ofproto.OFPMC_ADD,
        "flags": ofproto.OFPMF_KBPS,
        "meter_id": 1,
    }
    _EXTRA = "bands"

    def _init_hook(self):
        if not self.bands:
            self.bands = []

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        bands = []
        while offset < msg_len:
            band = OFPMeterBandHeader.parser(buf, offset)
            bands.append(band)
            offset += band.len
        return {"bands": bands}

    def _serialize_tail(self):
        offset = len(self.buf)
        for band in self.bands:
            offset += band.serialize(self.buf, offset)


# -- barriers ---------------------------------------------------------------


@_message
class OFPBarrierRequest(MsgBase):
    """Ask the switch to complete everything sent so far."""

    cls_msg_type = ofproto.OFPT_BARRIER_REQUEST


@_message
class OFPBarrierReply(_SwitchMsg):
    """Everything sent before the barrier is done."""

    cls_msg_type = ofproto.OFPT_BARRIER_REPLY


# -- queues -----------------------------------------------------------------


class OFPQueuePropHeader(Codec):
    """A queue property: 16 bit property, 16 bit length, four pad bytes."""

    _LEAD = "property len"

    def serialize(self, buf, offset):
        """Write this property into ``buf``, returning its length."""
        body = self.pack_fixed() if self._STRUCT is not None else b""
        body += self.pack_tail()
        self.len = _TLV_HDR.size + len(body)
        msg_pack_into("!HH%ds" % len(body), buf, offset, self.property, self.len, body)
        return self.len

    def pack_tail(self):
        """Bytes following the fixed part. An override point."""
        return b""


class OFPQueueProp(OFPQueuePropHeader):
    """Base for the defined queue properties.

    The four pad bytes of the header belong to each subclass's ``_FMT``, so
    the body a subclass declares starts at the header's type and length.
    """

    _ABSTRACT = True
    _LEAD = ""
    _EXTRA = "property len"
    _TYPE_ID = None
    #: Fixed total length of the property, or None if it is variable.
    _CLS_LEN = None

    def _init_hook(self):
        self.property = self._TYPE_ID
        self.len = self._CLS_LEN

    @classmethod
    def parser(cls, buf, offset):
        """Read one queue property, or None if its type is unknown."""
        property_, len_ = _TLV_HDR.unpack_from(buf, offset)
        subcls = QUEUE_PROPS.lookup(property_)
        if subcls is None:
            return None
        prop = subcls.from_fields(subcls.unpack_fixed(buf, offset + _TLV_HDR.size))
        prop.property = property_
        prop.len = len_
        if property_ == ofproto.OFPQT_EXPERIMENTER:
            prop.parse_experimenter_data(
                bytes(buf)[
                    offset + ofproto.OFP_QUEUE_PROP_EXPERIMENTER_SIZE : offset + len_
                ]
            )
        return prop


@QUEUE_PROPS.register
class OFPQueuePropMinRate(OFPQueueProp):
    """Guaranteed minimum rate, in tenths of a percent."""

    _TYPE_ID = ofproto.OFPQT_MIN_RATE
    _CLS_LEN = ofproto.OFP_QUEUE_PROP_MIN_RATE_SIZE
    _FMT = "4xH6x"
    _FIELDS = "rate"
    _DEFAULTS = _required(_FIELDS)


@QUEUE_PROPS.register
class OFPQueuePropMaxRate(OFPQueueProp):
    """Ceiling rate, in tenths of a percent."""

    _TYPE_ID = ofproto.OFPQT_MAX_RATE
    _CLS_LEN = ofproto.OFP_QUEUE_PROP_MAX_RATE_SIZE
    _FMT = "4xH6x"
    _FIELDS = "rate"
    _DEFAULTS = _required(_FIELDS)


@QUEUE_PROPS.register
class OFPQueuePropExperimenter(OFPQueueProp):
    """Vendor defined queue property, with a tail of opaque bytes."""

    _TYPE_ID = ofproto.OFPQT_EXPERIMENTER
    _FMT = "4xI4x"
    _FIELDS = "experimenter"
    _DEFAULTS = _required(_FIELDS)
    _EXTRA = "data property len"

    def parse_experimenter_data(self, rest):
        """Record the trailing vendor data as a list of octets."""
        self.data = list(rest)

    def pack_tail(self):
        return bytes(self.data) if self.data else b""


class OFPPacketQueue(Codec):
    """One queue attached to a port."""

    _EXTRA = "queue_id port properties len"
    _DEFAULTS = dict(_required("queue_id port properties"), len=None)

    @classmethod
    def parser(cls, buf, offset):
        """Read one queue and its properties from ``buf`` at ``offset``."""
        queue_id, port, len_ = struct.unpack_from(
            ofproto.OFP_PACKET_QUEUE_PACK_STR, buf, offset
        )
        end = offset + len_
        offset += ofproto.OFP_PACKET_QUEUE_SIZE
        properties = []
        while offset < end:
            # An unrecognised property is skipped by its own length rather
            # than stalling the loop, which is what os-ken would do.
            prop_len = _TLV_HDR.unpack_from(buf, offset)[1]
            prop = OFPQueueProp.parser(buf, offset)
            if prop is not None:
                properties.append(prop)
            offset += prop_len
        queue = cls(queue_id, port, properties)
        queue.len = len_
        return queue


@_message
class OFPQueueGetConfigRequest(MsgBase):
    """Ask for the queues configured on a port."""

    cls_msg_type = ofproto.OFPT_QUEUE_GET_CONFIG_REQUEST
    _FMT = "I4x"
    _FIELDS = "port"
    _DEFAULTS = _required(_FIELDS)


@_message
class OFPQueueGetConfigReply(_SwitchMsg):
    """The queues configured on a port."""

    cls_msg_type = ofproto.OFPT_QUEUE_GET_CONFIG_REPLY
    _EXTRA = "queues port"

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        (port,) = struct.unpack_from(
            ofproto.OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR, buf, offset
        )
        offset = ofproto.OFP_QUEUE_GET_CONFIG_REPLY_SIZE
        queues = []
        while offset < msg_len:
            queue = OFPPacketQueue.parser(bytes(buf), offset)
            queues.append(queue)
            offset += queue.len
        return {"port": port, "queues": queues}


# -- role and asynchronous configuration ------------------------------------


class _RoleMsg(MsgBase):
    """A controller role and the generation id that orders role changes."""

    _ABSTRACT = True
    _FMT = "I4xQ"
    _FIELDS = "role generation_id"
    _DEFAULTS = _none(_FIELDS)


@_message
class OFPRoleRequest(_RoleMsg):
    """Ask for, or change, this controller's role."""

    cls_msg_type = ofproto.OFPT_ROLE_REQUEST


@_message
class OFPRoleReply(_RoleMsg, _SwitchMsg):
    """This controller's role."""

    cls_msg_type = ofproto.OFPT_ROLE_REPLY


class _AsyncConfig(MsgBase):
    """The three pairs of asynchronous message masks, master then slave."""

    _ABSTRACT = True
    _EXTRA = "packet_in_mask port_status_mask flow_removed_mask"
    _MASKS = ("packet_in_mask", "port_status_mask", "flow_removed_mask")

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):
        values = struct.unpack_from(ofproto.OFP_ASYNC_CONFIG_PACK_STR, buf, offset)
        return {
            name: list(values[i * 2 : i * 2 + 2]) for i, name in enumerate(cls._MASKS)
        }

    def _serialize_tail(self):
        self.buf += struct.pack(
            ofproto.OFP_ASYNC_CONFIG_PACK_STR,
            *(value for name in self._MASKS for value in getattr(self, name))
        )


@_message
class OFPGetAsyncRequest(MsgBase):
    """Ask which asynchronous messages the switch will send."""

    cls_msg_type = ofproto.OFPT_GET_ASYNC_REQUEST


@_message
class OFPGetAsyncReply(_AsyncConfig, _SwitchMsg):
    """Which asynchronous messages the switch will send."""

    cls_msg_type = ofproto.OFPT_GET_ASYNC_REPLY


@_message
class OFPSetAsync(_AsyncConfig):
    """Choose which asynchronous messages the switch will send."""

    cls_msg_type = ofproto.OFPT_SET_ASYNC
    _DEFAULTS = _required(_AsyncConfig._EXTRA)

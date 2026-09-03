"""OpenFlow 1.3 messages, actions, instructions and match.

Every structure declares its wire layout and lets :mod:`c65of.codec` compile
the constructor, the packer and the JSON dict form. Only structures with a
variable length tail -- a match, a list of actions, a multipart body -- write
any code, and then only for the tail.
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

import logging
import struct

from c65of.codec import REGISTRY, REQUIRED, Codec, TLVRegistry, msg_pack_into
from c65of.lib.type_desc import MacAddr as _MAC
from c65of.ofproto import consts as ofproto
from c65of.ofproto import oxm

LOG = logging.getLogger(__name__)

_MSG_TYPES = TLVRegistry("message")
ACTIONS = TLVRegistry("action")
INSTRUCTIONS = TLVRegistry("instruction")
METER_BANDS = TLVRegistry("meter band")
QUEUE_PROPS = TLVRegistry("queue property")

_TLV_HDR = struct.Struct("!HH")
_HDR = ofproto.OFP_HEADER_SIZE


def round_up(length, align):
    """Smallest multiple of ``align`` that is at least ``length``."""
    return (length + align - 1) // align * align


def header(buf):
    """Unpack an OpenFlow header: ``(version, msg_type, msg_len, xid)``."""
    return struct.unpack_from(ofproto.OFP_HEADER_PACK_STR, bytes(buf))


class OFPUnknownVersion(Exception):
    """A message arrived for a protocol version this library does not speak."""


class OFPTruncatedMessage(Exception):
    """A message was shorter than its own declared length."""


# -- messages ---------------------------------------------------------------


class MsgBase(Codec):
    """An OpenFlow message.

    ``datapath``, ``version``, ``msg_type``, ``msg_len``, ``xid`` and ``buf``
    are message plumbing rather than message content, so they stay out of the
    JSON dict form; only the declared fields appear there.
    """

    _ABSTRACT = True
    _LEAD = "datapath"
    _HIDDEN = "datapath"
    # The structures a message carries -- actions, buckets, matches -- take no
    # datapath, so it is not passed down into their from_jsondict.
    _PASS_ARGS = False

    cls_msg_type = None
    version = None
    msg_type = None
    msg_len = None
    xid = None
    buf = None

    def set_headers(self, version, msg_type, msg_len, xid):
        """Record the header fields of a message read off the wire."""
        assert msg_type == self.cls_msg_type
        self.version = version
        self.msg_type = msg_type
        self.msg_len = msg_len
        self.xid = xid

    def set_xid(self, xid):
        """Assign the transaction id, once."""
        assert self.xid is None
        self.xid = xid

    def set_buf(self, buf):
        """Record the raw bytes this message was parsed from."""
        self.buf = bytes(buf)

    def __str__(self):
        def hexify(value):
            return hex(value) if isinstance(value, int) else value

        return "version=%s,msg_type=%s,msg_len=%s,xid=%s,%s" % (
            hexify(self.version),
            hexify(self.msg_type),
            hexify(self.msg_len),
            hexify(self.xid),
            Codec.__str__(self),
        )

    __repr__ = __str__

    @classmethod
    def parser(cls, datapath, version, msg_type, msg_len, xid, buf):
        """Build a message from the bytes of a whole OpenFlow message."""
        fields = cls.unpack_fixed(buf, _HDR) if cls._STRUCT is not None else {}
        fields.update(cls._parse_tail(buf, _HDR + cls._SIZE, msg_len))
        message = cls.from_fields(fields, datapath=datapath)
        message.set_headers(version, msg_type, msg_len, xid)
        message.set_buf(buf)
        return message

    @classmethod
    def _parse_tail(cls, buf, offset, msg_len):  # pylint: disable=unused-argument
        """Fields following the fixed part. An override point."""
        return {}

    def serialize(self):
        """Encode this message into ``self.buf``."""
        self.version = ofproto.OFP_VERSION
        self.msg_type = self.cls_msg_type
        self.buf = bytearray(_HDR)
        self._serialize_body()
        self.msg_len = len(self.buf)
        if self.xid is None:
            self.xid = 0
        struct.pack_into(
            ofproto.OFP_HEADER_PACK_STR,
            self.buf,
            0,
            self.version,
            self.msg_type,
            self.msg_len,
            self.xid,
        )

    def _serialize_body(self):
        if self._STRUCT is not None:
            self.buf += self.pack_fixed()
        self._serialize_tail()

    def _serialize_tail(self):
        """Bytes following the fixed part. An override point."""


def _message(cls):
    """Register a message class under its OpenFlow message type."""
    cls._TYPE_ID = cls.cls_msg_type
    return _MSG_TYPES.register(cls)


def msg(datapath, version, msg_type, msg_len, xid, buf):
    """Parse one whole OpenFlow message.

    A hello is readable whatever version it announces: it carries the version
    negotiation itself, and a switch that speaks a later protocol opens with
    that version and expects to be negotiated down. Every other message has to
    match the version this library speaks.
    """
    if version != ofproto.OFP_VERSION and msg_type != ofproto.OFPT_HELLO:
        raise OFPUnknownVersion("unsupported OpenFlow version 0x%02x" % version)
    if len(buf) < msg_len:
        raise OFPTruncatedMessage("message truncated: %d of %d" % (len(buf), msg_len))
    cls = _MSG_TYPES.lookup(msg_type)
    if cls is None:
        return None
    try:
        return cls.parser(datapath, version, msg_type, msg_len, xid, buf)
    except Exception:  # pylint: disable=broad-except
        # A switch that sends one malformed message keeps its channel: the
        # frame length was already validated, so the stream is still in sync
        # and the next message parses. Dropping the channel here would turn a
        # single bad message into a reconnect.
        LOG.exception(
            "malformed OpenFlow message from the switch: "
            "version 0x%02x msg_type %d msg_len %d xid %d",
            version,
            msg_type,
            msg_len,
            xid,
        )
        return None


def ofp_msg_from_jsondict(datapath, jsondict):
    """Instantiate a message class from ``{"OFPSetConfig": {...}}``.

    Resolved through the codec registry, so a message defined in any module
    is reachable, not just those in this one.
    """
    if len(jsondict) != 1:
        raise ValueError("expected a single class name, got %r" % (list(jsondict),))
    name, params = next(iter(jsondict.items()))
    cls = REGISTRY.get(name)
    if cls is None or not issubclass(cls, MsgBase):
        raise ValueError("%s is not an OpenFlow message class" % name)
    return cls.from_jsondict(params, datapath=datapath)


# -- match ------------------------------------------------------------------


class OFPMatch(Codec):
    """An OXM flow match.

    Fields are given as keyword arguments and held in OXM type order, which is
    what the prerequisite rules require (eth_type before ipv4_src, and so on).
    """

    _ABSTRACT = True

    def __init__(self, type_=None, length=None, _ordered_fields=None, **kwargs):
        self.type = ofproto.OFPMT_OXM if type_ is None else type_
        self.length = length
        if _ordered_fields is not None:
            assert not kwargs
            self._fields2 = _ordered_fields
            return
        normalized = dict(oxm.oxm_normalize_user(k, v) for k, v in kwargs.items())
        fields = [oxm.oxm_from_user(k, v) for k, v in normalized.items()]
        fields.sort(key=lambda f: f[0][0] if isinstance(f[0], tuple) else f[0])
        self._fields2 = [oxm.oxm_to_user(n, v, m) for n, v, m in fields]

    def __getitem__(self, key):
        return dict(self._fields2)[key]

    def __contains__(self, key):
        return key in dict(self._fields2)

    def items(self):
        """The match fields, in wire order, as ``(name, user_value)`` pairs."""
        return self._fields2

    def iteritems(self):
        """The match fields as an iterator over ``(name, user_value)``."""
        return iter(dict(self._fields2).items())

    def get(self, key, default=None):
        """The value of one match field, or ``default``."""
        return dict(self._fields2).get(key, default)

    def iter_attrs(self):
        yield "oxm_fields", dict(self._fields2)

    def to_jsondict(self, encode_string=None):
        return {
            "OFPMatch": {
                "oxm_fields": [oxm.oxm_to_jsondict(k, uv) for k, uv in self._fields2],
                "length": self.length,
                "type": self.type,
            }
        }

    @classmethod
    def from_jsondict(cls, params, decode_string=None, **extra):
        fields = [oxm.oxm_from_jsondict(f) for f in params["oxm_fields"]]
        match = cls(_ordered_fields=fields)
        # Round trip to fill in length exactly as the wire form would.
        buf = bytearray()
        match.serialize(buf, 0)
        return cls.parser(bytes(buf), 0)

    def serialize(self, buf, offset):
        """Write the match into ``buf``, returning its padded length."""
        field_offset = offset + 4
        for name, user_value in self._fields2:
            num, value, mask = oxm.oxm_from_user(name, user_value)
            field_offset += oxm.oxm_serialize(num, value, mask, buf, field_offset)
        length = field_offset - offset
        msg_pack_into("!HH", buf, offset, self.type, length)
        self.length = length
        pad_len = round_up(length, 8) - length
        if pad_len:
            msg_pack_into("!%dx" % pad_len, buf, field_offset)
        return length + pad_len

    @classmethod
    def parser(cls, buf, offset):
        """Read a match from ``buf`` at ``offset``."""
        type_, length = _TLV_HDR.unpack_from(buf, offset)
        offset += 4
        remaining = length - 4
        fields = []
        while remaining > 0:
            num, value, mask, field_len = oxm.oxm_parse(buf, offset)
            fields.append(oxm.oxm_to_user(num, value, mask))
            offset += field_len
            remaining -= field_len
        match = cls(_ordered_fields=fields)
        match.type = type_
        match.length = length
        return match


# -- actions ----------------------------------------------------------------


class _Tagged(Codec):
    """A structure introduced by a 16 bit type and a 16 bit length.

    Actions, instructions, meter bands and queue properties all share this
    shape, so they share the parse and serialize code and differ only in which
    registry they dispatch through.
    """

    _ABSTRACT = True
    _EXTRA = "type len"
    _REGISTRY = None
    _TYPE_ID = None
    #: True when the structure carries a tail beyond its fixed part.
    _VARIABLE = False

    def _init_hook(self):
        if isinstance(self._TYPE_ID, int):
            self.type = self._TYPE_ID
        if not self._VARIABLE:
            self.len = 4 + self._SIZE

    @classmethod
    def parser(cls, buf, offset):
        """Dispatch on the type field and parse one structure."""
        type_, len_ = _TLV_HDR.unpack_from(buf, offset)
        subcls = cls._REGISTRY.lookup(type_)
        if subcls is None:
            raise ValueError("unknown %s type %d" % (cls._REGISTRY.name, type_))
        return subcls.parse_body(buf, offset, type_, len_)

    @classmethod
    def parse_body(cls, buf, offset, type_, len_):
        """Build one structure from its body. An override point."""
        fields = cls.unpack_fixed(buf, offset + 4) if cls._STRUCT is not None else {}
        obj = (
            cls.from_fields(fields, type_=type_)
            if cls._LEAD
            else cls.from_fields(fields)
        )
        obj.type = type_
        obj.len = len_
        return obj

    def serialize(self, buf, offset):
        """Write this structure into ``buf``, returning its length."""
        body = self.pack_fixed() if self._STRUCT is not None else b""
        body += self.pack_tail()
        self.len = 4 + len(body)
        msg_pack_into("!HH%ds" % len(body), buf, offset, self.type, self.len, body)
        return self.len

    def pack_tail(self):
        """Bytes following the fixed part. An override point."""
        return b""


class OFPAction(_Tagged):
    """Base for OpenFlow actions."""

    _ABSTRACT = True
    _REGISTRY = ACTIONS


def _action(cls):
    return ACTIONS.register(cls)


@_action
class OFPActionOutput(OFPAction):
    """Output to a port."""

    _TYPE_ID = ofproto.OFPAT_OUTPUT
    _FMT = "IH6x"
    _FIELDS = "port max_len"
    _DEFAULTS = {"port": REQUIRED, "max_len": ofproto.OFPCML_MAX}


@_action
class OFPActionCopyTtlOut(OFPAction):
    """Copy the TTL outwards."""

    _TYPE_ID = ofproto.OFPAT_COPY_TTL_OUT
    _FMT = "4x"
    _FIELDS = ""


@_action
class OFPActionCopyTtlIn(OFPAction):
    """Copy the TTL inwards."""

    _TYPE_ID = ofproto.OFPAT_COPY_TTL_IN
    _FMT = "4x"
    _FIELDS = ""


@_action
class OFPActionSetMplsTtl(OFPAction):
    """Set the MPLS TTL."""

    _TYPE_ID = ofproto.OFPAT_SET_MPLS_TTL
    _FMT = "B3x"
    _FIELDS = "mpls_ttl"
    _DEFAULTS = {"mpls_ttl": REQUIRED}


@_action
class OFPActionDecMplsTtl(OFPAction):
    """Decrement the MPLS TTL."""

    _TYPE_ID = ofproto.OFPAT_DEC_MPLS_TTL
    _FMT = "4x"
    _FIELDS = ""


@_action
class OFPActionPushVlan(OFPAction):
    """Push a VLAN tag."""

    _TYPE_ID = ofproto.OFPAT_PUSH_VLAN
    _FMT = "H2x"
    _FIELDS = "ethertype"
    _DEFAULTS = {"ethertype": 33024}


@_action
class OFPActionPopVlan(OFPAction):
    """Pop the outer VLAN tag."""

    _TYPE_ID = ofproto.OFPAT_POP_VLAN
    _FMT = "4x"
    _FIELDS = ""


@_action
class OFPActionPushMpls(OFPAction):
    """Push an MPLS label."""

    _TYPE_ID = ofproto.OFPAT_PUSH_MPLS
    _FMT = "H2x"
    _FIELDS = "ethertype"
    _DEFAULTS = {"ethertype": 34887}


@_action
class OFPActionPopMpls(OFPAction):
    """Pop the outer MPLS label."""

    _TYPE_ID = ofproto.OFPAT_POP_MPLS
    _FMT = "H2x"
    _FIELDS = "ethertype"
    _DEFAULTS = {"ethertype": 2048}


@_action
class OFPActionSetQueue(OFPAction):
    """Set the queue id."""

    _TYPE_ID = ofproto.OFPAT_SET_QUEUE
    _FMT = "I"
    _FIELDS = "queue_id"
    _DEFAULTS = {"queue_id": REQUIRED}


@_action
class OFPActionGroup(OFPAction):
    """Send to a group."""

    _TYPE_ID = ofproto.OFPAT_GROUP
    _FMT = "I"
    _FIELDS = "group_id"


@_action
class OFPActionSetNwTtl(OFPAction):
    """Set the IP TTL."""

    _TYPE_ID = ofproto.OFPAT_SET_NW_TTL
    _FMT = "B3x"
    _FIELDS = "nw_ttl"
    _DEFAULTS = {"nw_ttl": REQUIRED}


@_action
class OFPActionDecNwTtl(OFPAction):
    """Decrement the IP TTL."""

    _TYPE_ID = ofproto.OFPAT_DEC_NW_TTL
    _FMT = "4x"
    _FIELDS = ""


@_action
class OFPActionPushPbb(OFPAction):
    """Push a PBB service tag."""

    _TYPE_ID = ofproto.OFPAT_PUSH_PBB
    _FMT = "H2x"
    _FIELDS = "ethertype"
    _DEFAULTS = {"ethertype": REQUIRED}


@_action
class OFPActionPopPbb(OFPAction):
    """Pop the outer PBB service tag."""

    _TYPE_ID = ofproto.OFPAT_POP_PBB
    _FMT = "4x"
    _FIELDS = ""


@_action
class OFPActionSetField(OFPAction):
    """Set one header field, carried as a single OXM TLV."""

    _TYPE_ID = ofproto.OFPAT_SET_FIELD
    _EXTRA = "field type len"
    _VARIABLE = True

    def __init__(self, field=None, **kwargs):
        self.type = self._TYPE_ID
        self.len = ofproto.OFP_ACTION_SET_FIELD_SIZE
        if field is None:
            if len(kwargs) != 1:
                raise TypeError("OFPActionSetField takes exactly one field")
            key, value = next(iter(kwargs.items()))
            self.field = oxm.oxm_from_user(key, value)
        else:
            self.field = field
        self.key, self.value = oxm.oxm_to_user(*self.field)

    def iter_attrs(self):
        # str() names the field being set, as the field= form reads poorly.
        yield self.key, self.value

    def to_jsondict(self, encode_string=None):
        return {
            "OFPActionSetField": {
                "field": oxm.oxm_to_jsondict(self.key, self.value),
                "len": self.len,
                "type": self.type,
            }
        }

    @classmethod
    def from_jsondict(cls, params, decode_string=None, **extra):
        key, value = oxm.oxm_from_jsondict(params["field"])
        action = cls(**{key: value})
        # Round trip so len reflects the padded wire form.
        buf = bytearray()
        action.serialize(buf, 0)
        return cls.parser(bytes(buf), 0)

    @classmethod
    def parse_body(cls, buf, offset, type_, len_):
        num, value, mask, _ = oxm.oxm_parse(buf, offset + 4)
        action = cls(field=(num, value, mask))
        action.len = len_
        return action

    def serialize(self, buf, offset):
        num, value, mask = self.field
        # The OXM TLV is padded out to an 8 byte boundary.
        payload = 4 + (len(value) * (2 if mask else 1))
        self.len = round_up(4 + payload, 8)
        pad_len = self.len - 4 - payload
        msg_pack_into("!HH", buf, offset, self.type, self.len)
        oxm.oxm_serialize(num, value, mask, buf, offset + 4)
        if pad_len:
            msg_pack_into("!%dx" % pad_len, buf, offset + 4 + payload)
        return self.len


@_action
class OFPActionExperimenter(OFPAction):
    """Vendor defined action."""

    _TYPE_ID = ofproto.OFPAT_EXPERIMENTER
    _FMT = "I"
    _FIELDS = "experimenter"
    _DEFAULTS = {"experimenter": REQUIRED}


# -- instructions -----------------------------------------------------------


class OFPInstruction(_Tagged):
    """Base for OpenFlow instructions."""

    _ABSTRACT = True
    _REGISTRY = INSTRUCTIONS


def _instruction(cls):
    return INSTRUCTIONS.register(cls)


@_instruction
class OFPInstructionGotoTable(OFPInstruction):
    """Continue processing in a later table."""

    _TYPE_ID = ofproto.OFPIT_GOTO_TABLE
    _FMT = "B3x"
    _FIELDS = "table_id"
    _DEFAULTS = {"table_id": REQUIRED}


@_instruction
class OFPInstructionWriteMetadata(OFPInstruction):
    """Write masked metadata for later tables."""

    _TYPE_ID = ofproto.OFPIT_WRITE_METADATA
    _FMT = "4xQQ"
    _FIELDS = "metadata metadata_mask"
    _DEFAULTS = {"metadata": REQUIRED, "metadata_mask": REQUIRED}


@_instruction
class OFPInstructionMeter(OFPInstruction):
    """Meter the packet."""

    _TYPE_ID = ofproto.OFPIT_METER
    _FMT = "I"
    _FIELDS = "meter_id"
    _DEFAULTS = {"meter_id": 1}


class OFPInstructionActions(OFPInstruction):
    """Apply, write or clear an action set.

    One class covers three instruction types, so the type is a constructor
    argument rather than a class constant.
    """

    _LEAD = "type"
    _EXTRA = "actions len"
    _FMT = "4x"
    _FIELDS = ""
    _VARIABLE = True

    def _init_hook(self):
        if self.actions is None:
            self.actions = []
        # os-ken accepts len_ and never assigns it: the length is whatever
        # serialization works out, so a value passed in is not believed.
        self.len = None

    def iter_attrs(self):
        # len only exists once serialized, as in os-ken.
        yield "actions", self.actions
        if self.len is not None:
            yield "len", self.len
        yield "type", self.type

    @classmethod
    def parse_body(cls, buf, offset, type_, len_):
        actions = []
        pos = offset + 8
        end = offset + len_
        while pos < end:
            action = OFPAction.parser(buf, pos)
            actions.append(action)
            pos += action.len
        inst = cls(type_, actions)
        inst.len = len_
        return inst

    def serialize(self, buf, offset):
        body = bytearray()
        for action in self.actions:
            action.serialize(body, len(body))
        self.len = 8 + len(body)
        msg_pack_into(
            "!HH4x%ds" % len(body), buf, offset, self.type, self.len, bytes(body)
        )
        return self.len


for _type in (
    ofproto.OFPIT_WRITE_ACTIONS,
    ofproto.OFPIT_APPLY_ACTIONS,
    ofproto.OFPIT_CLEAR_ACTIONS,
):
    INSTRUCTIONS.classes[_type] = OFPInstructionActions


# -- shared structures ------------------------------------------------------


class _NulString:
    """A fixed width, NUL padded name.

    Kept as bytes, as os-ken does; the ``utf-8`` coercion in ``_TYPE`` decodes
    it for the JSON dict form.
    """

    @staticmethod
    def to_user(value):
        """The name with its NUL padding removed."""
        return value.rstrip(b"\0")

    @staticmethod
    def from_user(value):
        """Bytes; the struct format re-applies the NUL padding."""
        return value.encode("utf-8") if isinstance(value, str) else value


class OFPPort(Codec):
    """Description of a switch port."""

    _FMT = "I4x6s2x16sIIIIIIII"
    _FIELDS = (
        "port_no hw_addr name config state curr advertised supported peer "
        "curr_speed max_speed"
    )
    _CODERS = {"hw_addr": _MAC, "name": _NulString}
    _TYPE = {"ascii": ("hw_addr",), "utf-8": ("name",)}
    # os-ken's OFPPort is a namedtuple, so its attribute order is field order.
    _ATTRS = (
        "port_no",
        "hw_addr",
        "name",
        "config",
        "state",
        "curr",
        "advertised",
        "supported",
        "peer",
        "curr_speed",
        "max_speed",
    )

    @classmethod
    def parser(cls, buf, offset):
        """Read a port description from ``buf`` at ``offset``."""
        return cls.from_fields(cls.unpack_fixed(buf, offset))

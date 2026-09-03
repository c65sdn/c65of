"""Link Layer Discovery Protocol (LLDP, IEEE 802.1AB).

An LLDPDU is a sequence of TLVs, each prefixed by a 16 bit header packing a
7 bit type and a 9 bit information string length. Chassis ID, Port ID, TTL and
End are mandatory; the optional TLVs may appear in any order between them.
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

# pylint: disable=attribute-defined-outside-init

import struct

from c65of.codec import Codec
from c65of.packet import ether_types as ether
from c65of.packet.ethernet import ethernet
from c65of.packet.packet_base import PacketBase

# LLDP destination MAC addresses.
LLDP_MAC_NEAREST_BRIDGE = "01:80:c2:00:00:0e"
LLDP_MAC_NEAREST_NON_TPMR_BRIDGE = "01:80:c2:00:00:03"
LLDP_MAC_NEAREST_CUSTOMER_BRIDGE = "01:80:c2:00:00:00"

LLDP_TLV_TYPELEN_STR = "!H"
LLDP_TLV_SIZE = 2
LLDP_TLV_TYPE_MASK = 0xFE00
LLDP_TLV_TYPE_SHIFT = 9
LLDP_TLV_LENGTH_MASK = 0x01FF

# LLDP TLV type.
LLDP_TLV_END = 0
LLDP_TLV_CHASSIS_ID = 1
LLDP_TLV_PORT_ID = 2
LLDP_TLV_TTL = 3
LLDP_TLV_PORT_DESCRIPTION = 4
LLDP_TLV_SYSTEM_NAME = 5
LLDP_TLV_SYSTEM_DESCRIPTION = 6
LLDP_TLV_SYSTEM_CAPABILITIES = 7
LLDP_TLV_MANAGEMENT_ADDRESS = 8
LLDP_TLV_ORGANIZATIONALLY_SPECIFIC = 127

#: Attributes common to every TLV; a constructed TLV has no ``tlv_info``.
_TLV_ATTRS = "typelen len tlv_info"


class LLDPBasicTLV(Codec):
    """One TLV of an LLDPDU.

    Constructed with ``buf`` it decodes, :meth:`_parse` splitting the
    information string into the subclass attributes; constructed with keyword
    arguments it encodes, :meth:`_build` setting them and :meth:`_info`
    packing them back.
    """

    _LEN_MIN = 0
    _LEN_MAX = 511
    _EXTRA = _TLV_ATTRS
    tlv_type = None

    def __init__(self, buf=None, **kwargs):
        if buf:
            (self.typelen,) = struct.unpack_from(LLDP_TLV_TYPELEN_STR, buf)
            assert self.tlv_type == self.get_type(buf)
            self.len = self.typelen & LLDP_TLV_LENGTH_MASK
            assert len(buf) >= self.len + LLDP_TLV_SIZE
            self.tlv_info = buf[LLDP_TLV_SIZE : LLDP_TLV_SIZE + self.len]
            self._parse()
        else:
            self.len = self._build(**kwargs)
            assert self._len_valid()
            self.typelen = (self.tlv_type << LLDP_TLV_TYPE_SHIFT) | self.len

    def __init_subclass__(cls, **kwargs):
        # A subclass declares _EXTRA for the JSON dict form only; every TLV
        # shares the constructor above rather than a generated one.
        cls._ABSTRACT = True
        super().__init_subclass__(**kwargs)

    @staticmethod
    def get_type(buf):
        """TLV type of the TLV at the head of ``buf``."""
        (typelen,) = struct.unpack_from(LLDP_TLV_TYPELEN_STR, buf)
        return (typelen & LLDP_TLV_TYPE_MASK) >> LLDP_TLV_TYPE_SHIFT

    @staticmethod
    def set_tlv_type(subcls, tlv_type):
        """Record ``tlv_type`` as the type ``subcls`` decodes."""
        assert issubclass(subcls, LLDPBasicTLV)
        subcls.tlv_type = tlv_type

    def _len_valid(self):
        return self._LEN_MIN <= self.len <= self._LEN_MAX

    def iter_attrs(self):
        """Yield the attributes this instance actually has.

        Only a decoded TLV keeps ``tlv_info``, and only some subclasses split
        further fields out of it.
        """
        for name in self._ATTRS:
            if hasattr(self, name):
                yield name, getattr(self, name)

    def _parse(self):
        """Split ``tlv_info`` into the subclass attributes."""

    def _build(self, **kwargs):
        """Set the subclass attributes; return the information string length."""
        raise NotImplementedError

    def _info(self):
        """The information string of this TLV."""
        return self.tlv_info

    def serialize(self):
        """Encode this TLV."""
        return struct.pack(LLDP_TLV_TYPELEN_STR, self.typelen) + self._info()


class lldp(PacketBase):  # pylint: disable=invalid-name
    """LLDPDU: the ordered list of TLVs an LLDP frame carries."""

    _EXTRA = "tlvs"
    _tlv_parsers = {}

    def __init__(self, tlvs):
        self.tlvs = tlvs

    def __len__(self):
        return sum(LLDP_TLV_SIZE + tlv.len for tlv in self.tlvs)

    def _tlvs_len_valid(self):
        # Chassis id, port id, ttl and end at least.
        return len(self.tlvs) >= 4

    def _tlvs_valid(self):
        return (
            self.tlvs[0].tlv_type == LLDP_TLV_CHASSIS_ID
            and self.tlvs[1].tlv_type == LLDP_TLV_PORT_ID
            and self.tlvs[2].tlv_type == LLDP_TLV_TTL
            and self.tlvs[-1].tlv_type == LLDP_TLV_END
        )

    @classmethod
    def _parser(cls, buf):
        tlvs = []
        while buf:
            tlv = cls._tlv_parsers[LLDPBasicTLV.get_type(buf)](buf)
            tlvs.append(tlv)
            buf = buf[LLDP_TLV_SIZE + tlv.len :]
            if tlv.tlv_type == LLDP_TLV_END:
                break
            assert len(buf) > 0
        lldp_pkt = cls(tlvs)
        assert lldp_pkt._tlvs_len_valid()
        assert lldp_pkt._tlvs_valid()
        return lldp_pkt, None, buf

    @classmethod
    def parser(cls, buf):
        """Decode an LLDPDU, or ``(None, None, buf)`` if ``buf`` is not one."""
        try:
            return cls._parser(buf)
        except (AssertionError, KeyError, struct.error):
            return None, None, buf

    def serialize(self, payload, prev):
        data = bytearray()
        for tlv in self.tlvs:
            data += tlv.serialize()
        return data

    @classmethod
    def set_type(cls, tlv_cls):
        """Record ``tlv_cls`` as the parser for the type it declares."""
        cls._tlv_parsers[tlv_cls.tlv_type] = tlv_cls

    @classmethod
    def get_type(cls, tlv_type):
        """Class decoding ``tlv_type``."""
        return cls._tlv_parsers[tlv_type]

    @classmethod
    def set_tlv_type(cls, tlv_type):
        """Class decorator registering a TLV class under ``tlv_type``."""

        def _set_type(tlv_cls):
            tlv_cls.set_tlv_type(tlv_cls, tlv_type)
            cls.set_type(tlv_cls)
            return tlv_cls

        return _set_type


@lldp.set_tlv_type(LLDP_TLV_END)
class End(LLDPBasicTLV):
    """End of LLDPDU TLV, with no information string."""

    def _build(self, **kwargs):
        return 0

    def _info(self):
        return b""


@lldp.set_tlv_type(LLDP_TLV_CHASSIS_ID)
class ChassisID(LLDPBasicTLV):
    """Chassis ID TLV: a subtype and the chassis id it selects."""

    _PACK_STR = "!B"
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    # Subtype id (1 octet) + chassis id (1 - 255 octets).
    _LEN_MIN = 2
    _LEN_MAX = 256
    _EXTRA = _TLV_ATTRS + " subtype chassis_id"

    # Chassis ID subtype.
    SUB_CHASSIS_COMPONENT = 1
    SUB_INTERFACE_ALIAS = 2
    SUB_PORT_COMPONENT = 3
    SUB_MAC_ADDRESS = 4
    SUB_NETWORK_ADDRESS = 5
    SUB_INTERFACE_NAME = 6
    SUB_LOCALLY_ASSIGNED = 7

    def _parse(self):
        (self.subtype,) = struct.unpack_from(self._PACK_STR, self.tlv_info)
        self.chassis_id = self.tlv_info[self._PACK_SIZE :]

    def _build(self, **kwargs):
        self.subtype = kwargs["subtype"]
        self.chassis_id = kwargs["chassis_id"]
        return self._PACK_SIZE + len(self.chassis_id)

    def _info(self):
        return struct.pack(self._PACK_STR, self.subtype) + self.chassis_id


@lldp.set_tlv_type(LLDP_TLV_PORT_ID)
class PortID(LLDPBasicTLV):
    """Port ID TLV: a subtype and the port id it selects."""

    _PACK_STR = "!B"
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    # Subtype id (1 octet) + port id (1 - 255 octets).
    _LEN_MIN = 2
    _LEN_MAX = 256
    _EXTRA = _TLV_ATTRS + " subtype port_id"

    # Port ID subtype.
    SUB_INTERFACE_ALIAS = 1
    SUB_PORT_COMPONENT = 2
    SUB_MAC_ADDRESS = 3
    SUB_NETWORK_ADDRESS = 4
    SUB_INTERFACE_NAME = 5
    SUB_AGENT_CIRCUIT_ID = 6
    SUB_LOCALLY_ASSIGNED = 7

    def _parse(self):
        (self.subtype,) = struct.unpack_from(self._PACK_STR, self.tlv_info)
        self.port_id = self.tlv_info[self._PACK_SIZE :]

    def _build(self, **kwargs):
        self.subtype = kwargs["subtype"]
        self.port_id = kwargs["port_id"]
        return self._PACK_SIZE + len(self.port_id)

    def _info(self):
        return struct.pack(self._PACK_STR, self.subtype) + self.port_id


@lldp.set_tlv_type(LLDP_TLV_TTL)
class TTL(LLDPBasicTLV):
    """Time To Live TLV: seconds this information stays valid."""

    _PACK_STR = "!H"
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    _LEN_MIN = _PACK_SIZE
    _LEN_MAX = _PACK_SIZE
    _EXTRA = _TLV_ATTRS + " ttl"

    def _parse(self):
        (self.ttl,) = struct.unpack_from(self._PACK_STR, self.tlv_info)

    def _build(self, **kwargs):
        self.ttl = kwargs["ttl"]
        return self._PACK_SIZE

    def _info(self):
        return struct.pack(self._PACK_STR, self.ttl)


class _TextTLV(LLDPBasicTLV):
    """A TLV whose whole information string is one text field.

    The named field is a property over ``tlv_info``, so the JSON dict form
    carries ``tlv_info`` alone.
    """

    _LEN_MAX = 255
    #: Constructor keyword naming the text.
    _FIELD = None

    def _build(self, **kwargs):
        self.tlv_info = kwargs[self._FIELD]
        return len(self.tlv_info)


@lldp.set_tlv_type(LLDP_TLV_PORT_DESCRIPTION)
class PortDescription(_TextTLV):
    """Port description TLV."""

    _FIELD = "port_description"

    @property
    def port_description(self):
        """The port description."""
        return self.tlv_info

    @port_description.setter
    def port_description(self, value):
        self.tlv_info = value


@lldp.set_tlv_type(LLDP_TLV_SYSTEM_NAME)
class SystemName(_TextTLV):
    """System name TLV."""

    _FIELD = "system_name"

    @property
    def system_name(self):
        """The system name."""
        return self.tlv_info

    @system_name.setter
    def system_name(self, value):
        self.tlv_info = value


@lldp.set_tlv_type(LLDP_TLV_SYSTEM_DESCRIPTION)
class SystemDescription(_TextTLV):
    """System description TLV."""

    _FIELD = "system_description"

    @property
    def system_description(self):
        """The system description."""
        return self.tlv_info

    @system_description.setter
    def system_description(self, value):
        self.tlv_info = value


@lldp.set_tlv_type(LLDP_TLV_SYSTEM_CAPABILITIES)
class SystemCapabilities(LLDPBasicTLV):
    """System capabilities TLV: those implemented and those enabled."""

    _PACK_STR = "!HH"
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    _LEN_MIN = _PACK_SIZE
    _LEN_MAX = _PACK_SIZE
    _EXTRA = _TLV_ATTRS + " system_cap enabled_cap"

    # System capabilities.
    CAP_REPEATER = 1 << 1
    CAP_MAC_BRIDGE = 1 << 2
    CAP_WLAN_ACCESS_POINT = 1 << 3
    CAP_ROUTER = 1 << 4
    CAP_TELEPHONE = 1 << 5
    CAP_DOCSIS = 1 << 6
    CAP_STATION_ONLY = 1 << 7
    CAP_CVLAN = 1 << 8
    CAP_SVLAN = 1 << 9
    CAP_TPMR = 1 << 10

    def _parse(self):
        self.system_cap, self.enabled_cap = struct.unpack_from(
            self._PACK_STR, self.tlv_info
        )

    def _build(self, **kwargs):
        self.system_cap = kwargs["system_cap"]
        self.enabled_cap = kwargs["enabled_cap"]
        return self._PACK_SIZE

    def _info(self):
        return struct.pack(self._PACK_STR, self.system_cap, self.enabled_cap)


@lldp.set_tlv_type(LLDP_TLV_MANAGEMENT_ADDRESS)
class ManagementAddress(LLDPBasicTLV):
    """Management address TLV: an address, an interface and an object id."""

    _LEN_MIN = 9
    _LEN_MAX = 167

    _ADDR_PACK_STR = "!BB"
    _ADDR_PACK_SIZE = struct.calcsize(_ADDR_PACK_STR)
    _ADDR_LEN_MIN = 1
    _ADDR_LEN_MAX = 31

    _INTF_PACK_STR = "!BIB"
    _INTF_PACK_SIZE = struct.calcsize(_INTF_PACK_STR)
    _OID_LEN_MIN = 0
    _OID_LEN_MAX = 128

    _EXTRA = (
        _TLV_ATTRS + " addr_len addr_subtype addr intf_subtype intf_num oid_len oid"
    )

    def _parse(self):
        self.addr_len, self.addr_subtype = struct.unpack_from(
            self._ADDR_PACK_STR, self.tlv_info
        )
        assert self._addr_len_valid()
        # addr_len covers the subtype octet as well as the address.
        offset = self._ADDR_PACK_SIZE + self.addr_len - 1
        self.addr = self.tlv_info[self._ADDR_PACK_SIZE : offset]
        self.intf_subtype, self.intf_num, self.oid_len = struct.unpack_from(
            self._INTF_PACK_STR, self.tlv_info, offset
        )
        assert self._oid_len_valid()
        self.oid = self.tlv_info[offset + self._INTF_PACK_SIZE :]

    def _build(self, **kwargs):
        self.addr_subtype = kwargs["addr_subtype"]
        self.addr = kwargs["addr"]
        self.addr_len = len(self.addr) + 1
        assert self._addr_len_valid()
        self.intf_subtype = kwargs["intf_subtype"]
        self.intf_num = kwargs["intf_num"]
        self.oid = kwargs["oid"]
        self.oid_len = len(self.oid)
        assert self._oid_len_valid()
        return (
            self._ADDR_PACK_SIZE
            + self.addr_len
            - 1
            + self._INTF_PACK_SIZE
            + self.oid_len
        )

    def _info(self):
        return (
            struct.pack(self._ADDR_PACK_STR, self.addr_len, self.addr_subtype)
            + self.addr
            + struct.pack(
                self._INTF_PACK_STR, self.intf_subtype, self.intf_num, self.oid_len
            )
            + self.oid
        )

    def _addr_len_valid(self):
        # The two bounds are OR'd, as in os-ken.
        return (
            self._ADDR_LEN_MIN <= self.addr_len or self.addr_len <= self._ADDR_LEN_MAX
        )

    def _oid_len_valid(self):
        return self._OID_LEN_MIN <= self.oid_len <= self._OID_LEN_MAX


@lldp.set_tlv_type(LLDP_TLV_ORGANIZATIONALLY_SPECIFIC)
class OrganizationallySpecific(LLDPBasicTLV):
    """Organizationally specific TLV: an OUI, a subtype and opaque bytes."""

    _PACK_STR = "!3sB"
    _PACK_SIZE = struct.calcsize(_PACK_STR)
    _LEN_MIN = _PACK_SIZE
    _LEN_MAX = 511
    _EXTRA = _TLV_ATTRS + " oui subtype info"

    def _parse(self):
        self.oui, self.subtype = struct.unpack_from(self._PACK_STR, self.tlv_info)
        self.info = self.tlv_info[self._PACK_SIZE :]

    def _build(self, **kwargs):
        self.oui = kwargs["oui"]
        self.subtype = kwargs["subtype"]
        self.info = kwargs["info"]
        return self._PACK_SIZE + len(self.info)

    def _info(self):
        return struct.pack(self._PACK_STR, self.oui, self.subtype) + self.info


ethernet.register_packet_type(lldp, ether.ETH_TYPE_LLDP)

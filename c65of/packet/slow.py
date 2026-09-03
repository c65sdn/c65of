"""Slow Protocols (IEEE 802.3 clause 43B), of which LACP is the one decoded.

A slow protocol frame starts with a one octet subtype selecting the protocol;
only LACP (IEEE 802.1AX) has a parser here, as in os-ken. A LACPDU is a fixed
110 octet frame of four TLVs: actor, partner, collector and terminator.
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

import struct

from c65of.lib import addrconv
from c65of.packet import ether_types as ether
from c65of.packet.ethernet import ethernet
from c65of.packet.packet_base import PacketBase

# Slow Protocol Multicast destination.
SLOW_PROTOCOL_MULTICAST = "01:80:c2:00:00:02"

# Slow Protocol SubType.
SLOW_SUBTYPE_LACP = 0x01
SLOW_SUBTYPE_MARKER = 0x02
SLOW_SUBTYPE_OAM = 0x03
SLOW_SUBTYPE_OSSP = 0x0A

#: The actor/partner state octet, least significant bit first.
_STATE_FLAGS = (
    "activity",
    "timeout",
    "aggregation",
    "synchronization",
    "collecting",
    "distributing",
    "defaulted",
    "expired",
)

#: Actor and partner information fields, in wire order.
_ROLE_FIELDS = ("system_priority", "system", "key", "port_priority", "port")

_LACP_ATTRS = " ".join(
    ["version"]
    + [
        "%s_%s" % (role, field)
        for role in ("actor", "partner")
        for field in _ROLE_FIELDS + tuple("state_" + flag for flag in _STATE_FLAGS)
    ]
    + ["collector_max_delay"]
)


class lacp(PacketBase):  # pylint: disable=invalid-name
    """Link Aggregation Control Protocol PDU (LACP, IEEE 802.1AX).

    Each of the actor and partner contributes a system id and priority, a key,
    a port and its priority, and eight state bits packed into one octet; the
    collector contributes its maximum delay.
    """

    LACP_VERSION_NUMBER = 1

    # LACP TLV type.
    LACP_TLV_TYPE_ACTOR = 1
    LACP_TLV_TYPE_PARTNER = 2
    LACP_TLV_TYPE_COLLECTOR = 3
    LACP_TLV_TYPE_TERMINATOR = 0

    # LACP state(LACP_Activity).
    LACP_STATE_ACTIVE = 1
    LACP_STATE_PASSIVE = 0
    # LACP state(LACP_Timeout).
    LACP_STATE_SHORT_TIMEOUT = 1
    LACP_STATE_LONG_TIMEOUT = 0
    # LACP state(Aggregation).
    LACP_STATE_AGGREGATEABLE = 1
    LACP_STATE_INDIVIDUAL = 0
    # LACP state(Synchronization).
    LACP_STATE_IN_SYNC = 1
    LACP_STATE_OUT_OF_SYNC = 0
    # LACP state(Collecting).
    LACP_STATE_COLLECTING_ENABLED = 1
    LACP_STATE_COLELCTING_DISABLED = 0
    # LACP state(Distributing).
    LACP_STATE_DISTRIBUTING_ENABLED = 1
    LACP_STATE_DISTRIBUTING_DISABLED = 0
    # LACP state(Defaulted).
    LACP_STATE_DEFAULED_PARTNER = 1
    LACP_STATE_OPERATIONAL_PARTNER = 0
    # LACP state(Expired).
    LACP_STATE_EXPIRED = 1
    LACP_STATE_NOT_EXPIRED = 0

    # Seconds between periodic transmissions, by timeout control value.
    FAST_PERIODIC_TIME = 1
    SLOW_PERIODIC_TIME = 30
    # Seconds before received LACPDU information is invalidated.
    SHORT_TIMEOUT_TIME = 3 * FAST_PERIODIC_TIME
    LONG_TIMEOUT_TIME = 3 * SLOW_PERIODIC_TIME

    _HLEN_PACK_STR = "!BB"
    _HLEN_PACK_LEN = struct.calcsize(_HLEN_PACK_STR)
    _ACTPRT_INFO_PACK_STR = "!BBH6sHHHB3x"
    _ACTPRT_INFO_PACK_LEN = struct.calcsize(_ACTPRT_INFO_PACK_STR)
    _COL_INFO_PACK_STR = "!BBH12x"
    _COL_INFO_PACK_LEN = struct.calcsize(_COL_INFO_PACK_STR)
    _TRM_PACK_STR = "!BB50x"
    _TRM_PACK_LEN = struct.calcsize(_TRM_PACK_STR)
    _ALL_PACK_LEN = (
        _HLEN_PACK_LEN
        + _ACTPRT_INFO_PACK_LEN * 2
        + _COL_INFO_PACK_LEN
        + _TRM_PACK_LEN
    )

    _MIN_LEN = _ALL_PACK_LEN
    _EXTRA = _LACP_ATTRS
    _TYPE = {"ascii": ("actor_system", "partner_system")}

    def __init__(
        self,
        version=LACP_VERSION_NUMBER,
        actor_system_priority=0,
        actor_system="00:00:00:00:00:00",
        actor_key=0,
        actor_port_priority=0,
        actor_port=0,
        actor_state_activity=0,
        actor_state_timeout=0,
        actor_state_aggregation=0,
        actor_state_synchronization=0,
        actor_state_collecting=0,
        actor_state_distributing=0,
        actor_state_defaulted=0,
        actor_state_expired=0,
        partner_system_priority=0,
        partner_system="00:00:00:00:00:00",
        partner_key=0,
        partner_port_priority=0,
        partner_port=0,
        partner_state_activity=0,
        partner_state_timeout=0,
        partner_state_aggregation=0,
        partner_state_synchronization=0,
        partner_state_collecting=0,
        partner_state_distributing=0,
        partner_state_defaulted=0,
        partner_state_expired=0,
        collector_max_delay=0,
    ):
        self.version = version
        self.actor_system_priority = actor_system_priority
        self.actor_system = actor_system
        self.actor_key = actor_key
        self.actor_port_priority = actor_port_priority
        self.actor_port = actor_port
        self.actor_state_activity = actor_state_activity
        self.actor_state_timeout = actor_state_timeout
        self.actor_state_aggregation = actor_state_aggregation
        self.actor_state_synchronization = actor_state_synchronization
        self.actor_state_collecting = actor_state_collecting
        self.actor_state_distributing = actor_state_distributing
        self.actor_state_defaulted = actor_state_defaulted
        self.actor_state_expired = actor_state_expired
        self.partner_system_priority = partner_system_priority
        self.partner_system = partner_system
        self.partner_key = partner_key
        self.partner_port_priority = partner_port_priority
        self.partner_port = partner_port
        self.partner_state_activity = partner_state_activity
        self.partner_state_timeout = partner_state_timeout
        self.partner_state_aggregation = partner_state_aggregation
        self.partner_state_synchronization = partner_state_synchronization
        self.partner_state_collecting = partner_state_collecting
        self.partner_state_distributing = partner_state_distributing
        self.partner_state_defaulted = partner_state_defaulted
        self.partner_state_expired = partner_state_expired
        self.collector_max_delay = collector_max_delay
        for name in self._ATTRS:
            assert "_state_" not in name or getattr(self, name) in (0, 1)
        self._subtype = SLOW_SUBTYPE_LACP
        self._actor_tag = self.LACP_TLV_TYPE_ACTOR
        self._actor_length = self._ACTPRT_INFO_PACK_LEN
        self._actor_state = self._pack_state("actor")
        self._partner_tag = self.LACP_TLV_TYPE_PARTNER
        self._partner_length = self._ACTPRT_INFO_PACK_LEN
        self._partner_state = self._pack_state("partner")
        self._collector_tag = self.LACP_TLV_TYPE_COLLECTOR
        self._collector_length = self._COL_INFO_PACK_LEN
        self._terminator_tag = self.LACP_TLV_TYPE_TERMINATOR
        self._terminator_length = 0

    def _pack_state(self, role):
        return sum(
            getattr(self, "%s_state_%s" % (role, flag)) << bit
            for bit, flag in enumerate(_STATE_FLAGS)
        )

    @classmethod
    def parser(cls, buf):
        """Decode a LACPDU, which is always exactly ``_ALL_PACK_LEN`` octets."""
        assert cls._ALL_PACK_LEN == len(buf)
        (subtype, version) = struct.unpack_from(cls._HLEN_PACK_STR, buf)
        assert SLOW_SUBTYPE_LACP == subtype
        assert cls.LACP_VERSION_NUMBER == version
        fields = {"version": version}
        offset = cls._HLEN_PACK_LEN
        for role, tag in (
            ("actor", cls.LACP_TLV_TYPE_ACTOR),
            ("partner", cls.LACP_TLV_TYPE_PARTNER),
        ):
            values = struct.unpack_from(cls._ACTPRT_INFO_PACK_STR, buf, offset)
            assert (tag, cls._ACTPRT_INFO_PACK_LEN) == values[:2]
            offset += cls._ACTPRT_INFO_PACK_LEN
            fields.update(
                ("%s_%s" % (role, name), value)
                for name, value in zip(_ROLE_FIELDS, values[2:7])
            )
            fields["%s_system" % role] = addrconv.mac.bin_to_text(values[3])
            fields.update(
                ("%s_state_%s" % (role, flag), (values[7] >> bit) & 1)
                for bit, flag in enumerate(_STATE_FLAGS)
            )
        (collector_tag, collector_length, max_delay) = struct.unpack_from(
            cls._COL_INFO_PACK_STR, buf, offset
        )
        assert cls.LACP_TLV_TYPE_COLLECTOR == collector_tag
        assert cls._COL_INFO_PACK_LEN == collector_length
        offset += cls._COL_INFO_PACK_LEN
        (terminator_tag, terminator_length) = struct.unpack_from(
            cls._TRM_PACK_STR, buf, offset
        )
        assert cls.LACP_TLV_TYPE_TERMINATOR == terminator_tag
        assert terminator_length == 0
        pkt = cls(collector_max_delay=max_delay, **fields)
        return pkt, None, buf[cls._ALL_PACK_LEN :]

    def serialize(self, payload, prev):
        data = struct.pack(self._HLEN_PACK_STR, self._subtype, self.version)
        for role, tag, length, state in (
            ("actor", self._actor_tag, self._actor_length, self._actor_state),
            ("partner", self._partner_tag, self._partner_length, self._partner_state),
        ):
            priority, system, key, port_priority, port = (
                getattr(self, "%s_%s" % (role, name)) for name in _ROLE_FIELDS
            )
            data += struct.pack(
                self._ACTPRT_INFO_PACK_STR,
                tag,
                length,
                priority,
                addrconv.mac.text_to_bin(system),
                key,
                port_priority,
                port,
                state,
            )
        data += struct.pack(
            self._COL_INFO_PACK_STR,
            self._collector_tag,
            self._collector_length,
            self.collector_max_delay,
        )
        return data + struct.pack(
            self._TRM_PACK_STR, self._terminator_tag, self._terminator_length
        )


class slow(PacketBase):  # pylint: disable=invalid-name
    """Slow protocol subtype dispatcher, with only a parser."""

    _PACK_STR = "!B"
    #: Subtype -> parser class. Marker, OAM and OSSP are not implemented.
    _SUBTYPES = {SLOW_SUBTYPE_LACP: lacp}

    @classmethod
    def parser(cls, buf):
        """Hand ``buf`` to the parser for its subtype, if there is one."""
        (subtype,) = struct.unpack_from(cls._PACK_STR, buf)
        cls_ = cls._SUBTYPES.get(subtype)
        if cls_ is None:
            return None, None, buf
        return cls_.parser(buf)


ethernet.register_packet_type(slow, ether.ETH_TYPE_SLOW)

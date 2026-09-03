"""Conversions between user supplied match/meter config and wire values.

The subset of os-ken's ofctl helpers a controller needs to turn YAML or REST
configuration into OpenFlow structures. Values arrive as ints or as strings
in any of the forms an operator would write: decimal, hex, ``addr/masklen``,
``addr/mask``, or a reserved port name such as ``CONTROLLER``.
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

import ipaddress
import logging

LOG = logging.getLogger(__name__)


def str_to_int(value):
    """Integer from a decimal, hex or octal string, or from an int."""
    return int(str(value), 0)


def to_match_eth(value):
    """A MAC match: ``addr`` or an ``addr/mask`` pair."""
    if "/" in value:
        addr, mask = value.split("/")
        return addr, mask
    return value


def to_match_ip(value):
    """An IP match: ``addr``, or an ``addr/mask`` pair.

    A prefix length is expanded to a full mask, so ``10.0.0.0/8`` and
    ``10.0.0.0/255.0.0.0`` give the same pair.
    """
    if "/" not in value:
        return value
    addr, mask = value.split("/")
    if mask.isdigit():
        # The prefix length gives the mask; the address keeps the bits it was
        # written with, as the addr/mask form already does.
        family = ipaddress.ip_address(addr)
        any_addr = "0.0.0.0" if family.version == 4 else "::"
        return addr, str(ipaddress.ip_network("%s/%s" % (any_addr, mask)).netmask)
    return addr, mask


def to_match_vid(value, ofpvid_present):
    """A VLAN match, applying OFPVID_PRESENT where the spec says to.

    A decimal value is a VLAN tag, so OFPVID_PRESENT is added. A hexadecimal
    string is a raw oxm_value that already carries the bit, so it is not.
    """
    if isinstance(value, int):
        return value | ofpvid_present
    if "/" in value:
        vid, mask = value.split("/")
        return str_to_int(vid), str_to_int(mask)
    if value.isdigit():
        return int(value, 10) | ofpvid_present
    return str_to_int(value)


def to_match_masked_int(value):
    """An integer match: a value, or a ``value/mask`` pair."""
    if isinstance(value, str) and "/" in value:
        number, mask = value.split("/")
        return str_to_int(number), str_to_int(mask)
    return str_to_int(value)


def to_match_packet_type(value):
    """A packet type match, given as a pair or as a packed integer."""
    if isinstance(value, (list, tuple)):
        return str_to_int(value[0]) << 16 | str_to_int(value[1])
    return str_to_int(value)


class OFCtlUtil:
    """Resolves reserved names such as ``CONTROLLER`` against a protocol module."""

    def __init__(self, ofproto):
        self.ofproto = ofproto

    def _reserved_num_from_user(self, num, prefix):
        try:
            return str_to_int(num)
        except ValueError:
            pass
        name = num if num.startswith(prefix) else prefix + num
        try:
            return getattr(self.ofproto, name.upper())
        except AttributeError:
            LOG.warning("cannot convert to a reserved number: %s", num)
            return num

    def ofp_port_from_user(self, port):
        """A port number, or the value of an ``OFPP_`` name."""
        return self._reserved_num_from_user(port, "OFPP_")

    def ofp_table_from_user(self, table):
        """A table id, or the value of an ``OFPTT_`` name."""
        return self._reserved_num_from_user(table, "OFPTT_")

    def ofp_group_from_user(self, group):
        """A group id, or the value of an ``OFPG_`` name."""
        return self._reserved_num_from_user(group, "OFPG_")

    def ofp_meter_from_user(self, meter):
        """A meter id, or the value of an ``OFPM_`` name."""
        return self._reserved_num_from_user(meter, "OFPM_")

    def ofp_buffer_from_user(self, buffer_id):
        """A buffer id, with ``NO_BUFFER`` resolved."""
        if buffer_id in ("OFP_NO_BUFFER", "NO_BUFFER"):
            return self.ofproto.OFP_NO_BUFFER
        return str_to_int(buffer_id)


def meter_mod_from_conf(datapath, meter, command):
    """Build an OFPMeterMod from a meter configuration mapping.

    ``datapath`` supplies the protocol and parser modules, so this works
    against a real datapath or a stand-in that only records the message.
    """
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    util = OFCtlUtil(ofproto)

    flag_values = {
        "KBPS": ofproto.OFPMF_KBPS,
        "PKTPS": ofproto.OFPMF_PKTPS,
        "BURST": ofproto.OFPMF_BURST,
        "STATS": ofproto.OFPMF_STATS,
    }
    flags = 0
    meter_flags = meter.get("flags", [])
    if not isinstance(meter_flags, list):
        meter_flags = [meter_flags]
    for flag in meter_flags:
        if flag not in flag_values:
            LOG.error("unknown meter flag: %s", flag)
            continue
        flags |= flag_values[flag]

    bands = []
    for band in meter.get("bands", []):
        band_type = band.get("type")
        rate = str_to_int(band.get("rate", 0))
        burst_size = str_to_int(band.get("burst_size", 0))
        if band_type == "DROP":
            bands.append(parser.OFPMeterBandDrop(rate, burst_size))
        elif band_type == "DSCP_REMARK":
            prec_level = str_to_int(band.get("prec_level", 0))
            bands.append(parser.OFPMeterBandDscpRemark(rate, burst_size, prec_level))
        elif band_type == "EXPERIMENTER":
            experimenter = str_to_int(band.get("experimenter", 0))
            bands.append(
                parser.OFPMeterBandExperimenter(rate, burst_size, experimenter)
            )
        else:
            LOG.error("unknown meter band type: %s", band_type)

    meter_id = util.ofp_meter_from_user(meter.get("meter_id", 0))
    return parser.OFPMeterMod(datapath, command, flags, meter_id, bands)


def mod_meter_entry(datapath, meter, command):
    """Build an OFPMeterMod from configuration and send it.

    os-ken's equivalent only sends; this returns the message too, so a caller
    that wants the message does not need a datapath stand-in to capture it.
    """
    meter_mod = meter_mod_from_conf(datapath, meter, command)
    if meter_mod.xid is None:
        datapath.set_xid(meter_mod)
    datapath.send_msg(meter_mod)
    return meter_mod

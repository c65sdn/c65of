"""Differential tests: config value conversion vs os-ken's ofctl helpers."""

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

import os_ken.lib.ofctl_utils as reference
import os_ken.ofproto.ofproto_v1_3 as ref_ofp
import pytest

from c65of import ofctl
from c65of.ofproto import consts


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.1",
        "10.0.0.0/8",
        "192.168.0.0/255.255.0.0",
        "fe80::1",
        "2001:db8::/32",
        # Host bits set: kept, not masked away.
        "10.0.0.1/8",
        "192.168.1.5/24",
        "2001:db8::5/32",
        "0.0.0.0/0",
        "::/0",
    ],
)
def test_to_match_ip(value):
    """An address, a prefix length and a dotted mask all agree with os-ken."""
    assert ofctl.to_match_ip(value) == reference.to_match_ip(value)


@pytest.mark.parametrize(
    "value", ["0e:00:00:00:00:01", "0e:00:00:00:00:00/ff:ff:ff:00:00:00"]
)
def test_to_match_eth(value):
    """A MAC with and without a mask agrees with os-ken."""
    assert ofctl.to_match_eth(value) == reference.to_match_eth(value)


@pytest.mark.parametrize("value", [100, "100", "0x1064", "0x1000/0x1000", "0"])
def test_to_match_vid(value):
    """OFPVID_PRESENT is applied for decimal forms only, as os-ken does."""
    assert ofctl.to_match_vid(value, consts.OFPVID_PRESENT) == reference.to_match_vid(
        value, ref_ofp.OFPVID_PRESENT
    )


@pytest.mark.parametrize("value", [5, "5", "0xff", "0xff/0xff", "0o17"])
def test_to_match_masked_int(value):
    """Decimal, hex, octal and masked integers agree with os-ken."""
    assert ofctl.to_match_masked_int(value) == reference.to_match_masked_int(value)


@pytest.mark.parametrize("value", ["1", "0x10", "0o17", "0b101", 7])
def test_str_to_int(value):
    """Base detection agrees with os-ken."""
    assert ofctl.str_to_int(value) == reference.str_to_int(value)


def test_leading_zero_is_rejected_like_the_reference():
    """int(x, 0) rejects a leading zero, and both sides raise the same way."""
    with pytest.raises(ValueError):
        ofctl.str_to_int("010")
    with pytest.raises(ValueError):
        reference.str_to_int("010")


@pytest.mark.parametrize("value", [(1, 2), [1, 2], "0x10000"])
def test_to_match_packet_type(value):
    """A packet type given as a pair or packed integer agrees with os-ken."""
    assert ofctl.to_match_packet_type(value) == reference.to_match_packet_type(value)


@pytest.mark.parametrize(
    "port", ["CONTROLLER", "OFPP_CONTROLLER", "LOCAL", "IN_PORT", "1", "0xfffffffd"]
)
def test_ofp_port_from_user(port):
    """Reserved port names and numbers resolve as os-ken resolves them."""
    assert ofctl.OFCtlUtil(consts).ofp_port_from_user(port) == reference.OFCtlUtil(
        ref_ofp
    ).ofp_port_from_user(port)


def test_unknown_reserved_name_is_returned_unchanged(caplog):
    """An unresolvable name is logged and passed through, as os-ken does."""
    util = ofctl.OFCtlUtil(consts)
    assert util.ofp_port_from_user("bogus") == "bogus"
    assert "cannot convert" in caplog.text.lower()


@pytest.mark.parametrize(
    "resolver, value",
    [
        ("ofp_table_from_user", "ALL"),
        ("ofp_group_from_user", "ANY"),
        ("ofp_meter_from_user", "CONTROLLER"),
        ("ofp_meter_from_user", "SLOWPATH"),
    ],
)
def test_other_reserved_resolvers(resolver, value):
    """The table, group and meter name spaces resolve as os-ken's do."""
    ours = getattr(ofctl.OFCtlUtil(consts), resolver)(value)
    theirs = getattr(reference.OFCtlUtil(ref_ofp), resolver)(value)
    assert ours == theirs


@pytest.mark.parametrize(
    "buffer_id, expected", [("NO_BUFFER", consts.OFP_NO_BUFFER), ("7", 7)]
)
def test_ofp_buffer_from_user(buffer_id, expected):
    """A buffer id resolves the NO_BUFFER name or parses as a number."""
    assert ofctl.OFCtlUtil(consts).ofp_buffer_from_user(buffer_id) == expected

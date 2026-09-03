"""Differential tests for address, MAC and type conversion, plus hub."""

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

import os_ken.lib.addrconv as ref_addrconv
import os_ken.lib.mac as ref_mac
import os_ken.lib.type_desc as ref_type_desc
import pytest

from c65of.lib import addrconv, mac, type_desc

MACS = ["00:00:00:00:00:00", "0e:00:00:00:00:01", "ff:ff:ff:ff:ff:ff"]
IPV4 = ["0.0.0.0", "10.0.0.1", "255.255.255.255"]
IPV6 = ["::", "fe80::1", "2001:db8::ff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]


@pytest.mark.parametrize("text", MACS)
def test_mac_conversion(text):
    """MAC text and packed forms agree with os-ken in both directions."""
    packed = addrconv.mac.text_to_bin(text)
    assert packed == ref_addrconv.mac.text_to_bin(text)
    assert addrconv.mac.bin_to_text(packed) == ref_addrconv.mac.bin_to_text(packed)


@pytest.mark.parametrize("text", IPV4)
def test_ipv4_conversion(text):
    """IPv4 text and packed forms agree with os-ken in both directions."""
    packed = addrconv.ipv4.text_to_bin(text)
    assert packed == ref_addrconv.ipv4.text_to_bin(text)
    assert addrconv.ipv4.bin_to_text(packed) == ref_addrconv.ipv4.bin_to_text(packed)


@pytest.mark.parametrize("text", IPV6)
def test_ipv6_conversion(text):
    """IPv6 text and packed forms agree with os-ken in both directions."""
    packed = addrconv.ipv6.text_to_bin(text)
    assert packed == ref_addrconv.ipv6.text_to_bin(text)
    assert addrconv.ipv6.bin_to_text(packed) == ref_addrconv.ipv6.bin_to_text(packed)


@pytest.mark.parametrize(
    "text", ["10.0.0.0/8", "192.168.1.0/255.255.255.0", "2001:db8::/32"]
)
def test_prefix_returns_addr_and_netmask(text):
    """A prefix converts to the (addr, netmask) pair a masked match wants."""
    converter = addrconv.ipv6 if ":" in text else addrconv.ipv4
    reference = ref_addrconv.ipv6 if ":" in text else ref_addrconv.ipv4
    assert converter.text_to_bin(text) == reference.text_to_bin(text)


def test_text_to_int():
    """An address converts to its integer value."""
    assert addrconv.ipv4.text_to_int("10.0.0.1") == 0x0A000001
    assert addrconv.ipv6.text_to_int("::1") == 1


@pytest.mark.parametrize("text", ["not:a:mac", "00:00:00:00:00", ""])
def test_bad_mac_text_rejected(text):
    """Text that is not six octets is an error."""
    with pytest.raises(ValueError):
        addrconv.mac.text_to_bin(text)


def test_bad_mac_binary_rejected():
    """Packed input of the wrong width is an error."""
    with pytest.raises(ValueError):
        addrconv.mac.bin_to_text(b"\x00\x01")


def test_mac_constants_match_reference():
    """The well known addresses agree with os-ken."""
    assert mac.DONTCARE == ref_mac.DONTCARE
    assert mac.BROADCAST == ref_mac.BROADCAST
    assert mac.DONTCARE_STR == ref_mac.DONTCARE_STR
    assert mac.BROADCAST_STR == ref_mac.BROADCAST_STR
    assert mac.MULTICAST == ref_mac.MULTICAST
    assert mac.UNICAST == ref_mac.UNICAST
    assert mac.HADDR_PATTERN == ref_mac.HADDR_PATTERN


@pytest.mark.parametrize(
    "text, multicast",
    [
        ("01:00:5e:00:00:01", True),
        ("0e:00:00:00:00:01", False),
        ("ff:ff:ff:ff:ff:ff", True),
    ],
)
def test_is_multicast(text, multicast):
    """The group bit is read as os-ken reads it."""
    packed = mac.haddr_to_bin(text)
    assert mac.is_multicast(packed) is multicast
    assert bool(ref_mac.is_multicast(packed)) is multicast


@pytest.mark.parametrize("text", MACS)
def test_mac_helpers_match_reference(text):
    """The haddr helpers agree with os-ken."""
    assert mac.haddr_to_bin(text) == ref_mac.haddr_to_bin(text)
    assert mac.haddr_to_int(text) == ref_mac.haddr_to_int(text)
    packed = mac.haddr_to_bin(text)
    assert mac.haddr_to_str(packed) == ref_mac.haddr_to_str(packed)


def test_haddr_to_str_of_none():
    """A missing address stringifies rather than raising."""
    assert mac.haddr_to_str(None) == ref_mac.haddr_to_str(None) == "None"


def test_haddr_bitand():
    """Masking a packed address agrees with os-ken."""
    addr = mac.haddr_to_bin("0e:11:22:33:44:55")
    mask = mac.haddr_to_bin("ff:ff:ff:00:00:00")
    assert mac.haddr_bitand(addr, mask) == ref_mac.haddr_bitand(addr, mask)


@pytest.mark.parametrize("width", [1, 2, 3, 4, 8, 9, 16])
def test_int_descriptors_match_reference(width):
    """Each integer width round trips exactly as os-ken's does."""
    ours = getattr(type_desc, "Int%d" % width)
    theirs = getattr(ref_type_desc, "Int%d" % width)
    value = (1 << (width * 8)) - 1
    assert ours.from_user(value) == theirs.from_user(value)
    packed = ours.from_user(value)
    assert ours.to_user(packed) == theirs.to_user(packed) == value


def test_int_descr_multiple():
    """The paired integer descriptor agrees with os-ken."""
    values = (1, 2)
    assert type_desc.Int4Double.from_user(values) == ref_type_desc.Int4Double.from_user(
        values
    )
    packed = type_desc.Int4Double.from_user(values)
    assert type_desc.Int4Double.to_user(packed) == values


def test_int_descr_multiple_rejects_wrong_count():
    """A tuple of the wrong length is an error."""
    with pytest.raises(ValueError, match="expected 2 values"):
        type_desc.Int4Double.from_user((1,))


@pytest.mark.parametrize(
    "descr, value",
    [
        ("MacAddr", "0e:00:00:00:00:01"),
        ("IPv4Addr", "10.0.0.1"),
        ("IPv6Addr", "fe80::1"),
    ],
)
def test_address_descriptors_match_reference(descr, value):
    """Address descriptors round trip exactly as os-ken's do."""
    ours = getattr(type_desc, descr)
    theirs = getattr(ref_type_desc, descr)
    assert ours.from_user(value) == theirs.from_user(value)
    packed = ours.from_user(value)
    assert ours.to_user(packed) == theirs.to_user(packed) == value


def test_unknown_type_is_base64():
    """Opaque field bytes carry as base64, as os-ken carries them."""
    data = b"\x00\xff\x10"
    assert type_desc.UnknownType.to_user(data) == ref_type_desc.UnknownType.to_user(
        data
    )
    encoded = type_desc.UnknownType.to_user(data)
    assert type_desc.UnknownType.from_user(encoded) == data


@pytest.mark.parametrize(
    "value",
    [
        ipaddress.IPv4Address("10.0.0.1"),
        ipaddress.ip_address("fe80::1"),
        "0e:00:00:00:00:01",
    ],
)
def test_non_string_addresses_are_accepted(value):
    """An ipaddress object converts, as it did through netaddr.

    faucet passes ipaddress objects straight into these converters.
    """
    if isinstance(value, str):
        assert addrconv.mac.text_to_bin(value) == ref_addrconv.mac.text_to_bin(value)
        return
    converter = addrconv.ipv6 if value.version == 6 else addrconv.ipv4
    reference = ref_addrconv.ipv6 if value.version == 6 else ref_addrconv.ipv4
    assert converter.text_to_bin(value) == reference.text_to_bin(value)
    assert converter.text_to_bin(value) == converter.text_to_bin(str(value))

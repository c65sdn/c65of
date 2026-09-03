"""MAC address constants and predicates."""

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

from c65of.lib import addrconv

HADDR_PATTERN = r"([0-9a-f]{2}:){5}[0-9a-f]{2}"

DONTCARE = b"\x00" * 6
BROADCAST = b"\xff" * 6
DONTCARE_STR = "00:00:00:00:00:00"
BROADCAST_STR = "ff:ff:ff:ff:ff:ff"
MULTICAST = "fe:ff:ff:ff:ff:ff"
UNICAST = "01:00:00:00:00:00"


def is_multicast(addr):
    """True if the group bit of a packed address is set."""
    return bool(addr[0] & 0x01)


def haddr_to_str(addr):
    """Human readable form of a packed address."""
    if addr is None:
        return "None"
    return addrconv.mac.bin_to_text(addr)


def haddr_to_int(addr):
    """Integer value of a human readable address."""
    return int(addr.replace(":", ""), 16)


def haddr_to_bin(string):
    """Packed form of a human readable address."""
    return addrconv.mac.text_to_bin(string)


def haddr_bitand(addr, mask):
    """Bitwise AND of two packed addresses."""
    return bytes(a & m for a, m in zip(addr, mask))

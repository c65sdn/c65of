"""Type descriptors converting between OXM wire bytes and user values."""

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

import base64

from c65of.lib import addrconv


class IntDescr:
    """Big-endian unsigned integer of a fixed byte width."""

    __slots__ = ("size",)

    def __init__(self, size):
        self.size = size

    def to_user(self, binary):
        """Integer value of ``binary``."""
        return int.from_bytes(binary, "big")

    def from_user(self, value):
        """Packed form of integer ``value``."""
        return int(value).to_bytes(self.size, "big")


class IntDescrMlt:
    """Fixed length tuple of big-endian unsigned integers."""

    __slots__ = ("length", "num", "size")

    def __init__(self, length, num):
        self.length = length
        self.num = num
        self.size = length * num

    def to_user(self, binary):
        """Tuple of integers from ``binary``."""
        step = self.length
        return tuple(
            int.from_bytes(binary[i : i + step], "big")
            for i in range(0, self.size, step)
        )

    def from_user(self, values):
        """Packed form of a tuple of integers."""
        if len(values) != self.num:
            raise ValueError("expected %d values, got %d" % (self.num, len(values)))
        return b"".join(int(v).to_bytes(self.length, "big") for v in values)


# Descriptor singletons, named for the field widths they decode.
# pylint: disable=invalid-name
Int1 = IntDescr(1)
Int2 = IntDescr(2)
Int3 = IntDescr(3)
Int4 = IntDescr(4)
Int8 = IntDescr(8)
Int9 = IntDescr(9)
Int16 = IntDescr(16)
Int4Double = IntDescrMlt(4, 2)


class MacAddr:
    """48 bit MAC address."""

    size = 6
    to_user = staticmethod(addrconv.mac.bin_to_text)
    from_user = staticmethod(addrconv.mac.text_to_bin)


class IPv4Addr:
    """32 bit IPv4 address."""

    size = 4
    to_user = staticmethod(addrconv.ipv4.bin_to_text)
    from_user = staticmethod(addrconv.ipv4.text_to_bin)


class IPv6Addr:
    """128 bit IPv6 address."""

    size = 16
    to_user = staticmethod(addrconv.ipv6.bin_to_text)
    from_user = staticmethod(addrconv.ipv6.text_to_bin)


class UnknownType:
    """Opaque bytes, carried as base64 text."""

    to_user = staticmethod(lambda data: base64.b64encode(data).decode("ascii"))
    from_user = staticmethod(base64.b64decode)

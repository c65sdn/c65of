"""Base class for protocol headers."""

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

from c65of.codec import Codec

#: ethertype -> class, shared by the ethernet header and the VLAN tags.
ETHERTYPES = {}

#: IP protocol number -> class, shared by the IPv4 and IPv6 headers.
IP_PROTOS = {}


class PacketBase(Codec):
    """A protocol (ethernet, ipv4, ...) header.

    ``_TYPES`` maps a next-protocol selector in this header to the class that
    parses what follows. Headers sharing a number space share one registry:
    :data:`ETHERTYPES` for ethernet and the VLAN tags, :data:`IP_PROTOS` for
    IPv4 and IPv6.
    """

    _TYPES = {}
    _MIN_LEN = 0
    _ABSTRACT = True
    #: Attribute whose value selects the class parsing what follows, if any.
    _NEXT_FIELD = None

    @classmethod
    def get_packet_type(cls, type_):
        """Class registered for next-protocol selector ``type_``, or None."""
        return cls._TYPES.get(type_)

    @classmethod
    def register_packet_type(cls, cls_, type_):
        """Register ``cls_`` as the parser for selector ``type_``."""
        cls._TYPES[type_] = cls_

    def __len__(self):
        return self._MIN_LEN

    @property
    def protocol_name(self):
        """Name used in the JSON dict form."""
        return type(self).__name__

    @classmethod
    def parser(cls, buf):
        """Decode a header at offset 0 of ``buf``.

        Returns ``(header, next_cls, rest)``, where ``next_cls`` is None when
        the rest of the packet is raw payload. The default suits a header that
        is exactly its declared struct; override for options or a payload
        length that is not "the rest".
        """
        fields = cls.unpack_fixed(buf)
        header = cls.from_fields(fields)
        next_cls = None
        if cls._NEXT_FIELD is not None:
            next_cls = cls.get_packet_type(fields[cls._NEXT_FIELD])
        return header, next_cls, buf[cls._SIZE :]

    def serialize(self, payload, prev):  # pylint: disable=unused-argument
        """Encode this header.

        ``payload`` is what immediately follows this header, ``prev`` the
        enclosing header (None when outermost); both are needed by protocols
        whose checksum covers a pseudo header.
        """
        return self.pack_fixed()

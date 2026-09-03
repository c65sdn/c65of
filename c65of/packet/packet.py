"""Packet decoder/encoder: an ordered stack of protocol headers."""

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
import struct

from c65of.codec import Codec, REGISTRY
from c65of.packet import ethernet
from c65of.packet.packet_base import PacketBase


class Packet(Codec):
    """A single packet, decoded or being encoded.

    Constructed with ``data`` it decodes; iterating yields the protocol
    headers and then the payload, in on-wire order. Constructed empty it
    encodes: add headers outermost first, then call :meth:`serialize`.
    """

    _ABSTRACT = True
    _ATTRS = ("protocols",)

    def __init__(self, data=None, protocols=None, parse_cls=ethernet.ethernet):
        self.data = data
        self.protocols = [] if protocols is None else protocols
        if self.data:
            self._parse(parse_cls)

    def _parse(self, cls):
        rest = self.data
        while cls:
            # A buffer of nothing but padding ends the walk.
            if not bytes(rest).strip(b"\x00"):
                return
            try:
                proto, cls, rest = cls.parser(rest)
            except struct.error:
                break
            if proto:
                self.protocols.append(proto)
        if rest and bytes(rest).strip(b"\x00"):
            self.protocols.append(rest)

    def serialize(self):
        """Encode the registered headers into ``self.data``.

        Headers serialize innermost first so that a header covering a payload
        checksum sees the bytes it covers.
        """
        self.data = bytearray()
        reversed_protocols = self.protocols[::-1]
        last = len(reversed_protocols) - 1
        for i, proto in enumerate(reversed_protocols):
            if isinstance(proto, PacketBase):
                prev = None if i == last else reversed_protocols[i + 1]
                data = proto.serialize(self.data, prev)
            else:
                data = bytes(proto)
            self.data = bytearray(data + self.data)

    @classmethod
    def from_jsondict(cls, params, decode_string=base64.b64decode, **extra):
        protocols = []
        for proto in params["protocols"]:
            for key, value in proto.items():
                proto_cls = REGISTRY.get(key)
                if proto_cls is None or not issubclass(proto_cls, PacketBase):
                    raise ValueError("unknown protocol name %s" % key)
                protocols.append(proto_cls.from_jsondict(value))
        return cls(protocols=protocols)

    def add_protocol(self, proto):
        """Append a header. Headers must be added in on-wire order."""
        self.protocols.append(proto)

    def get_protocols(self, protocol):
        """Every header that is an instance of ``protocol``."""
        if isinstance(protocol, PacketBase):
            protocol = type(protocol)
        return [p for p in self.protocols if isinstance(p, protocol)]

    def get_protocol(self, protocol):
        """The outermost header that is an instance of ``protocol``, or None."""
        for proto in self.protocols:
            if isinstance(proto, protocol):
                return proto
        return None

    def __truediv__(self, trailer):
        self.add_protocol(trailer)
        return self

    def __iter__(self):
        return iter(self.protocols)

    def __getitem__(self, idx):
        return self.protocols[idx]

    def __setitem__(self, idx, item):
        self.protocols[idx] = item

    def __delitem__(self, idx):
        del self.protocols[idx]

    def __len__(self):
        return len(self.protocols)

    def __contains__(self, protocol):
        if isinstance(protocol, type) and issubclass(protocol, PacketBase):
            return any(isinstance(p, protocol) for p in self.protocols)
        return protocol in self.protocols

    def __str__(self):
        return ", ".join(repr(protocol) for protocol in self.protocols)

    __repr__ = __str__

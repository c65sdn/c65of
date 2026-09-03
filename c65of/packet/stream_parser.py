"""Streaming message extraction from a byte stream."""

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

import abc


class StreamParser(metaclass=abc.ABCMeta):
    """Extracts whole messages from a transport with no message boundaries."""

    class TooSmallException(Exception):
        """Not enough bytes yet for a complete message."""

    def __init__(self):
        self._q = bytearray()

    def parse(self, data):
        """Append ``data`` and return every complete message now available."""
        self._q.extend(data)
        msgs = []
        while True:
            try:
                msg, self._q = self.try_parse(self._q)
            except self.TooSmallException:
                break
            msgs.append(msg)
        return msgs

    @abc.abstractmethod
    def try_parse(self, q):
        """Return ``(msg, rest)`` or raise :class:`TooSmallException`."""

"""Events carrying OpenFlow messages.

Every message class gets an event class named after it -- ``OFPPacketIn``
becomes ``EventOFPPacketIn`` -- generated from the message registry rather
than written out, so a new message needs no entry here.
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

import sys

from c65of.app import EventBase
from c65of.ofproto import base as _base
from c65of.ofproto import parser as _parser  # noqa: F401  (registers every message)


class EventOFPMsgBase(EventBase):
    """An OpenFlow message that arrived on a datapath's channel."""

    def __init__(self, msg):
        self.msg = msg


class EventOFPStateChange(EventBase):
    """A datapath moved to a different negotiation phase."""

    def __init__(self, dp):
        self.datapath = dp


class EventOFPPortStateChange(EventBase):
    """A port on a datapath changed state."""

    def __init__(self, dp, reason, port_no):
        self.datapath = dp
        self.reason = reason
        self.port_no = port_no


_EVENT_CLASSES = {}


def event_name(msg_cls_name):
    """Event class name for a message class name."""
    return "Event" + msg_cls_name


def ofp_msg_to_ev_cls(msg_cls):
    """The event class carrying ``msg_cls``."""
    return _EVENT_CLASSES[msg_cls]


def ofp_msg_to_ev(msg):
    """Wrap a parsed message in its event."""
    return ofp_msg_to_ev_cls(type(msg))(msg)


def generate():
    """Create an event class for every registered message class.

    Idempotent, so a module registering more messages can call it again.
    """
    module = sys.modules[__name__]
    for msg_cls in _message_classes():
        if msg_cls in _EVENT_CLASSES:
            continue
        name = event_name(msg_cls.__name__)
        ev_cls = type(name, (EventOFPMsgBase,), {"__doc__": "%s event." % name})
        ev_cls.__module__ = __name__
        _EVENT_CLASSES[msg_cls] = ev_cls
        setattr(module, name, ev_cls)


def _message_classes():
    """Every message class currently registered, including subclasses."""
    seen = set()
    pending = [_base.MsgBase]
    while pending:
        cls = pending.pop()
        for sub in cls.__subclasses__():
            if sub not in seen:
                seen.add(sub)
                pending.append(sub)
    return seen


generate()

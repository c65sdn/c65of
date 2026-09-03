"""Tracks the datapaths connected to this controller.

An application observes :class:`EventDP` for connects and disconnects,
:class:`EventDPReconnected` when a switch reconnects before we noticed the
old connection drop, and the port events for topology changes. All of them
are delivered on the ``dpset`` dispatcher.
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

import logging

from c65of import ofp_event
from c65of.app import (
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    EventBase,
    OFApp,
    set_ev_cls,
)

LOG = logging.getLogger(__name__)

DPSET_EV_DISPATCHER = "dpset"


class EventDPBase(EventBase):
    """Base of the events about a datapath."""

    def __init__(self, dp):
        self.dp = dp


class EventDP(EventDPBase):
    """A switch connected (``enter`` true) or disconnected (``enter`` false).

    ``ports`` is the port list at the moment of the change.
    """

    def __init__(self, dp, enter_leave):
        super().__init__(dp)
        self.enter = enter_leave
        self.ports = []


class EventDPReconnected(EventDPBase):
    """A registered switch connected again; ``ports`` survives the reconnect."""

    def __init__(self, dp):
        super().__init__(dp)
        self.ports = []


class EventPortBase(EventDPBase):
    """Base of the events about one port of a datapath."""

    def __init__(self, dp, port):
        super().__init__(dp)
        self.port = port


class EventPortAdd(EventPortBase):
    """A port was added to a switch."""


class EventPortDelete(EventPortBase):
    """A port was removed from a switch."""


class EventPortModify(EventPortBase):
    """An attribute of a port changed."""


class PortState(dict):
    """The ports of one datapath, keyed by port number."""

    def add(self, port_no, port):
        """Record a new port."""
        self[port_no] = port

    def remove(self, port_no):
        """Forget a port."""
        del self[port_no]

    def modify(self, port_no, port):
        """Replace a port's description."""
        self[port_no] = port


class DPSet(OFApp):
    """The set of switches connected to this controller.

    Used as a context by another application::

        class MyApp(OFApp):
            _CONTEXTS = {"dpset": dpset.DPSet}
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "dpset"
        #: datapath id -> :class:`c65of.controller.Datapath`.
        self.dps = {}
        #: datapath id -> :class:`PortState`.
        self.port_state = {}

    def get(self, dp_id):
        """The datapath with this id, or None."""
        return self.dps.get(dp_id)

    def get_all(self):
        """Every ``(dpid, datapath)`` pair currently connected."""
        return list(self.dps.items())

    def get_port(self, dpid, port_no):
        """One port of a datapath. Raises ``KeyError`` if there is no such port."""
        return self.port_state[dpid][port_no]

    def get_ports(self, dpid):
        """Every port of a datapath. Raises ``KeyError`` if it is not connected."""
        return list(self.port_state[dpid].values())

    def _register(self, dp):
        assert dp.id is not None
        # A switch can reconnect before we notice the old connection drop, so
        # forget the older one, keep its PortState, and report a reconnect
        # rather than a leave followed by an enter.
        reconnected = dp.id in self.dps
        if reconnected:
            self.logger.warning("multiple connections from %016x", dp.id)
            self.dps[dp.id].close()
        self.dps[dp.id] = dp
        if dp.id not in self.port_state:
            self.port_state[dp.id] = PortState()
            ev = EventDP(dp, True)
            for port in dp.ports.values():
                self._port_added(dp, port)
                ev.ports.append(port)
            self.send_event_to_observers(ev)
        if reconnected:
            ev = EventDPReconnected(dp)
            ev.ports = list(self.port_state.get(dp.id, {}).values())
            self.send_event_to_observers(ev)

    def _unregister(self, dp):
        if dp not in self.dps.values():
            return
        ev = EventDP(dp, False)
        for port in list(self.port_state.get(dp.id, {}).values()):
            self._port_deleted(dp, port)
            ev.ports.append(port)
        self.send_event_to_observers(ev)
        del self.dps[dp.id]
        del self.port_state[dp.id]

    def _port_added(self, datapath, port):
        self.port_state[datapath.id].add(port.port_no, port)

    def _port_deleted(self, datapath, port):
        self.port_state[datapath.id].remove(port.port_no)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def dispatcher_change(self, ev):
        """Register a datapath reaching MAIN, unregister one going DEAD."""
        datapath = ev.datapath
        assert datapath is not None
        if ev.state == MAIN_DISPATCHER:
            self._register(datapath)
        elif ev.state == DEAD_DISPATCHER:
            self._unregister(datapath)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        """Track a port change and republish it as a port event."""
        msg = ev.msg
        datapath = msg.datapath
        port = msg.desc
        ofproto = datapath.ofproto
        if msg.reason == ofproto.OFPPR_ADD:
            self._port_added(datapath, port)
            event = EventPortAdd(datapath, port)
        elif msg.reason == ofproto.OFPPR_DELETE:
            self._port_deleted(datapath, port)
            event = EventPortDelete(datapath, port)
        elif msg.reason == ofproto.OFPPR_MODIFY:
            self.port_state[datapath.id].modify(port.port_no, port)
            event = EventPortModify(datapath, port)
        else:
            return
        LOG.debug(
            "DPSET: port %s of %016x reason %s", port.port_no, datapath.id, msg.reason
        )
        self.send_event_to_observers(event)

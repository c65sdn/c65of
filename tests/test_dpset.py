"""Tracking connected datapaths: register, unregister, reconnect and ports."""

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

import threading

import pytest

from c65of import ofp_event
from c65of import ofproto as ofp
from c65of.app import (
    APPS,
    DEAD_DISPATCHER,
    HANDSHAKE_DISPATCHER,
    MAIN_DISPATCHER,
    OFApp,
    set_ev_cls,
)
from c65of.dpset import (
    DPSET_EV_DISPATCHER,
    DPSet,
    EventDP,
    EventDPReconnected,
    EventPortAdd,
    EventPortDelete,
    EventPortModify,
    PortState,
)
from c65of.ofproto import parser

TIMEOUT = 15.0
DPID = 0x00000000000000FF


def port(port_no, state=0):
    """A port description."""
    return parser.OFPPort(
        port_no=port_no,
        hw_addr="00:0e:0c:00:00:%02x" % port_no,
        name="port%d" % port_no,
        config=0,
        state=state,
        curr=0,
        advertised=0,
        supported=0,
        peer=0,
        curr_speed=1000,
        max_speed=10000,
    )


class FakeDatapath:
    """Enough of a datapath for DPSet: an id, its ports and a close()."""

    def __init__(self, dpid=DPID, port_nos=(1, 2)):
        self.id = dpid
        self.ports = {port_no: port(port_no) for port_no in port_nos}
        self.ofproto = ofp
        self.state = None
        self.closed = False

    def close(self):
        """Record that DPSet dropped this connection."""
        self.closed = True


class Driver(OFApp):
    """Publishes the events the channel would publish."""

    def state_change(self, datapath, state):
        """Announce a phase transition."""
        ev = ofp_event.EventOFPStateChange(datapath)
        ev.state = state
        datapath.state = state
        self.send_event_to_observers(ev, state)

    def port_status(self, datapath, reason, desc):
        """Announce a port status change."""
        msg = parser.OFPPortStatus(datapath, reason=reason, desc=desc)
        self.send_event_to_observers(ofp_event.EventOFPPortStatus(msg), MAIN_DISPATCHER)


class Observer(OFApp):
    """Records the datapath events DPSet publishes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seen = []
        self._cond = threading.Condition()

    def _record(self, ev):
        with self._cond:
            self.seen.append(ev)
            self._cond.notify_all()

    def of_kind(self, cls):
        """Every recorded event of a class."""
        return [ev for ev in self.seen if isinstance(ev, cls)]

    def wait_for(self, cls, count):
        """Block until ``count`` events of class ``cls`` have arrived."""
        with self._cond:
            arrived = self._cond.wait_for(
                lambda: len(self.of_kind(cls)) >= count, TIMEOUT
            )
        assert arrived, "timed out waiting for %d %s" % (count, cls.__name__)

    @set_ev_cls([EventDP, EventDPReconnected], DPSET_EV_DISPATCHER)
    def datapath_change(self, ev):
        """Record a connect, disconnect or reconnect."""
        self._record(ev)

    @set_ev_cls([EventPortAdd, EventPortDelete, EventPortModify], DPSET_EV_DISPATCHER)
    def port_change(self, ev):
        """Record a port event."""
        self._record(ev)


PORT_EVENTS = {
    ofp.OFPPR_ADD: EventPortAdd,
    ofp.OFPPR_DELETE: EventPortDelete,
    ofp.OFPPR_MODIFY: EventPortModify,
}


class Fixture:
    """A started DPSet with a driver and an observer around it."""

    def __init__(self):
        self.dpset = DPSet()
        self.driver = Driver()
        self.observer = Observer()
        self.apps = (self.dpset, self.driver, self.observer)
        for app in self.apps:
            APPS[app.name] = app
            app.start()

    def publish(self, action, cls):
        """Run ``action`` and wait for the next event of class ``cls``."""
        expected = len(self.observer.of_kind(cls)) + 1
        action()
        self.observer.wait_for(cls, expected)

    def connect(self, datapath):
        """Take a new datapath to MAIN and wait for the enter event."""
        self.publish(
            lambda: self.driver.state_change(datapath, MAIN_DISPATCHER), EventDP
        )
        return datapath

    def reconnect(self, datapath):
        """Take a known dpid to MAIN again and wait for the reconnect event."""
        self.publish(
            lambda: self.driver.state_change(datapath, MAIN_DISPATCHER),
            EventDPReconnected,
        )
        return datapath

    def disconnect(self, datapath):
        """Take a datapath to DEAD and wait for the leave event."""
        self.publish(
            lambda: self.driver.state_change(datapath, DEAD_DISPATCHER), EventDP
        )

    def port_status(self, datapath, reason, desc):
        """Publish a port status and wait for the port event it becomes."""
        self.publish(
            lambda: self.driver.port_status(datapath, reason, desc),
            PORT_EVENTS[reason],
        )

    def close(self):
        """Stop every application."""
        for app in self.apps:
            app.stop()
            APPS.pop(app.name, None)


@pytest.fixture(name="net")
def _net():
    fixture = Fixture()
    yield fixture
    fixture.close()


def test_connect_registers_the_datapath_and_its_ports(net):
    """A datapath reaching MAIN is registered with its ports."""
    datapath = net.connect(FakeDatapath())
    assert net.dpset.get(DPID) is datapath
    assert net.dpset.get_all() == [(DPID, datapath)]
    assert sorted(net.dpset.port_state[DPID]) == [1, 2]
    (ev,) = net.observer.of_kind(EventDP)
    assert ev.enter is True
    assert sorted(p.port_no for p in ev.ports) == [1, 2]


def test_disconnect_unregisters_and_reports_the_ports(net):
    """A datapath going DEAD is forgotten and its ports reported."""
    datapath = net.connect(FakeDatapath())
    net.disconnect(datapath)
    assert net.dpset.get(DPID) is None
    assert net.dpset.get_all() == []
    assert net.dpset.port_state == {}
    leave = net.observer.of_kind(EventDP)[-1]
    assert leave.enter is False
    assert sorted(p.port_no for p in leave.ports) == [1, 2]


def test_disconnect_of_an_unknown_datapath_is_ignored(net):
    """A leave for a datapath we never registered is ignored."""
    net.driver.state_change(FakeDatapath(), DEAD_DISPATCHER)
    other = net.connect(FakeDatapath(dpid=DPID + 1))
    assert [ev.dp for ev in net.observer.of_kind(EventDP)] == [other]


def test_reconnect_replaces_the_datapath_and_keeps_the_ports(net):
    """A reconnecting dpid replaces its connection and keeps its ports."""
    first = net.connect(FakeDatapath())
    second = net.reconnect(FakeDatapath())
    assert first.closed
    assert net.dpset.get(DPID) is second
    assert len(net.observer.of_kind(EventDP)) == 1
    (ev,) = net.observer.of_kind(EventDPReconnected)
    assert ev.dp is second
    assert sorted(p.port_no for p in ev.ports) == [1, 2]


def test_a_second_dpid_connects_independently(net):
    """Two dpids are tracked separately."""
    first = net.connect(FakeDatapath())
    second = net.connect(FakeDatapath(dpid=DPID + 1, port_nos=(9,)))
    assert dict(net.dpset.get_all()) == {DPID: first, DPID + 1: second}
    assert net.dpset.get_ports(DPID + 1) == [second.ports[9]]


def test_port_add(net):
    """An added port is tracked and republished."""
    datapath = net.connect(FakeDatapath())
    net.port_status(datapath, ofp.OFPPR_ADD, port(3))
    assert sorted(net.dpset.port_state[DPID]) == [1, 2, 3]
    (ev,) = net.observer.of_kind(EventPortAdd)
    assert ev.dp is datapath and ev.port.port_no == 3


def test_port_delete(net):
    """A deleted port is forgotten and republished."""
    datapath = net.connect(FakeDatapath())
    net.port_status(datapath, ofp.OFPPR_DELETE, port(2))
    assert sorted(net.dpset.port_state[DPID]) == [1]
    (ev,) = net.observer.of_kind(EventPortDelete)
    assert ev.port.port_no == 2


def test_port_modify(net):
    """A modified port replaces the one held for it."""
    datapath = net.connect(FakeDatapath())
    net.port_status(datapath, ofp.OFPPR_MODIFY, port(1, state=ofp.OFPPS_LINK_DOWN))
    assert net.dpset.get_port(DPID, 1).state == ofp.OFPPS_LINK_DOWN
    (ev,) = net.observer.of_kind(EventPortModify)
    assert ev.port.state == ofp.OFPPS_LINK_DOWN


def test_unknown_port_status_reason_is_ignored(net):
    """A port status with an unknown reason changes nothing."""
    datapath = net.connect(FakeDatapath())
    net.driver.port_status(datapath, 0xFE, port(3))
    net.port_status(datapath, ofp.OFPPR_MODIFY, port(1, state=ofp.OFPPS_LINK_DOWN))
    assert sorted(net.dpset.port_state[DPID]) == [1, 2]
    assert net.observer.of_kind(EventPortAdd) == []


def test_state_change_to_another_phase_is_ignored(net):
    """A phase other than MAIN or DEAD does not register anything."""
    net.driver.state_change(FakeDatapath(), HANDSHAKE_DISPATCHER)
    net.connect(FakeDatapath(dpid=DPID + 1))
    assert net.dpset.get(DPID) is None


def test_get_port_of_an_unknown_datapath_raises(net):
    """Asking for the ports of an unknown datapath raises KeyError."""
    with pytest.raises(KeyError):
        net.dpset.get_port(DPID, 1)
    with pytest.raises(KeyError):
        net.dpset.get_ports(DPID)


def test_port_state_is_a_dict_with_named_operations():
    """PortState is a dict with add, modify and remove."""
    state = PortState()
    state.add(1, port(1))
    assert list(state) == [1]
    state.modify(1, port(1, state=ofp.OFPPS_LINK_DOWN))
    assert state[1].state == ofp.OFPPS_LINK_DOWN
    state.remove(1)
    assert not state


def test_dpset_is_named_for_the_context_key():
    """A fresh DPSet is empty and named for its context key."""
    dpset = DPSet()
    assert dpset.name == "dpset"
    assert not dpset.dps
    assert not dpset.port_state

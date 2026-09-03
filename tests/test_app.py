"""The application framework: handler registration, dispatch and lifecycle."""

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

import queue
import sys
import threading

import pytest

from c65of import hub
from c65of.app import (
    APPS,
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    AppManager,
    EventBase,
    OFApp,
    set_ev_cls,
)


class Ping(EventBase):
    """Test event."""

    def __init__(self, value):
        self.value = value


class Pong(EventBase):
    """Test event no app handles."""


class Recorder(OFApp):
    """Records the events it is sent."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seen = []
        self.main_only = []
        self.arrived = threading.Event()

    @set_ev_cls(Ping)
    def any_phase(self, ev):
        """Handler with no dispatcher restriction."""
        self.seen.append(ev.value)
        self.arrived.set()

    @set_ev_cls(Ping, MAIN_DISPATCHER)
    def main_phase(self, ev):
        """Handler restricted to the main phase."""
        self.main_only.append(ev.value)


class Exploder(OFApp):
    """Raises from its handler."""

    @set_ev_cls(Ping)
    def boom(self, ev):
        """Always raises."""
        raise RuntimeError("boom")


@pytest.fixture(name="app")
def _app():
    instance = Recorder()
    APPS[instance.name] = instance
    instance.start()
    yield instance
    instance.stop()
    APPS.pop(instance.name, None)


def test_handlers_registered_from_decorator():
    """Decorated methods are registered without an explicit call."""
    app = Recorder()
    assert app.handles(Ping)
    assert not app.handles(Pong)


def test_dispatcher_filters_delivery():
    """A phase-restricted handler only fires in that phase."""
    app = Recorder()
    assert len(app.get_handlers(Ping(1), MAIN_DISPATCHER)) == 2
    assert len(app.get_handlers(Ping(1), CONFIG_DISPATCHER)) == 1
    assert len(app.get_handlers(Ping(1))) == 2


def test_send_event_reaches_the_handler(app):
    """An event sent by name is delivered on the app's own thread."""
    app.send_event(app.name, Ping(7), MAIN_DISPATCHER)
    assert app.arrived.wait(5)
    assert app.seen == [7]
    assert app.main_only == [7]


def test_send_event_to_observers(app):
    """Broadcast reaches every app handling the class, and no others."""
    app.send_event_to_observers(Ping(9))
    assert app.arrived.wait(5)
    assert app.seen == [9]


def test_send_event_to_unknown_app_is_ignored(app):
    """Naming an app that is not running is not an error."""
    app.send_event("NoSuchApp", Ping(1))
    assert app.seen == []


def test_handler_exception_does_not_kill_the_loop():
    """A raising handler is logged and the dispatch thread survives."""
    app = Exploder()
    APPS[app.name] = app
    app.start()
    try:
        app.send_event(app.name, Ping(1))
        app.send_event(app.name, Ping(2))
        hub.sleep(0.2)
        assert app.main_thread.is_alive()
    finally:
        app.stop()
        APPS.pop(app.name, None)


def test_unregister_handler():
    """A removed handler stops matching."""
    app = Recorder()
    app.unregister_handler(Ping, app.any_phase)
    assert len(app.get_handlers(Ping(1))) == 1
    app.unregister_handler(Ping, app.any_phase)


def test_stop_drains_queued_events():
    """Events already queued are handled before the loop exits."""
    app = Recorder()
    APPS[app.name] = app
    app.start()
    for value in range(20):
        app.send_event(app.name, Ping(value))
    app.stop()
    APPS.pop(app.name, None)
    assert app.seen == list(range(20))


def test_app_manager_runs_an_app():
    """The manager loads, starts and stops an application by module name."""
    manager = AppManager()
    manager.applications_cls["recorder"] = Recorder
    services = manager.instantiate_apps()
    try:
        assert len(services) == 1
        app = manager.applications["Recorder"]
        app.send_event(app.name, Ping(3))
        assert app.arrived.wait(5)
    finally:
        manager.close()
    assert not APPS


def test_app_manager_rejects_a_module_with_no_app():
    """Loading a module that defines no application is an error."""
    with pytest.raises(ImportError, match="no OFApp subclass"):
        AppManager().load_apps(["c65of.hub"])


def test_hub_spawn_is_a_daemon():
    """Background threads never keep the process alive at exit."""
    done = threading.Event()
    thread = hub.spawn(done.set)
    assert thread.daemon
    assert done.wait(5)
    hub.joinall([thread])
    hub.kill(thread)


def test_ofp_events_are_generated_for_every_message():
    """Importing the messages and regenerating gives each one an event class."""
    # pylint: disable=import-outside-toplevel
    from c65of import ofp_event
    from c65of.ofproto.messages import OFPFlowMod

    ofp_event.generate()
    assert ofp_event.event_name("OFPPacketIn") == "EventOFPPacketIn"
    ev_cls = ofp_event.ofp_msg_to_ev_cls(OFPFlowMod)
    assert ev_cls is ofp_event.EventOFPFlowMod
    assert ev_cls.__module__ == "c65of.ofp_event"

    msg = OFPFlowMod(None, table_id=1)
    ev = ofp_event.ofp_msg_to_ev(msg)
    assert isinstance(ev, ofp_event.EventOFPFlowMod)
    assert ev.msg is msg

    # Idempotent: a second pass reuses the classes it already made.
    ofp_event.generate()
    assert ofp_event.ofp_msg_to_ev_cls(OFPFlowMod) is ev_cls


def test_ofp_state_change_events():
    """The datapath phase and port state events carry what they are given."""
    # pylint: disable=import-outside-toplevel
    from c65of import ofp_event

    assert ofp_event.EventOFPStateChange("dp").datapath == "dp"
    port = ofp_event.EventOFPPortStateChange("dp", 1, 3)
    assert (port.datapath, port.reason, port.port_no) == ("dp", 1, 3)


@pytest.mark.parametrize("unix", [False, True])
def test_stream_server_accepts_connections(tmp_path, unix):
    """A connection reaches the handler on its own thread, TCP or unix socket."""
    # pylint: disable=import-outside-toplevel
    import socket

    from c65of.hub import StreamServer

    got = queue.Queue()

    def handle(sock, _addr):
        got.put(sock.recv(16))
        sock.close()

    listen = (str(tmp_path / "sock"), None) if unix else ("127.0.0.1", 0)
    server = StreamServer(listen, handle)
    try:
        hub.spawn(server.serve_forever)
        family = socket.AF_UNIX if unix else socket.AF_INET
        client = socket.socket(family, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(server.address if not unix else listen[0])
        client.sendall(b"hello")
        assert got.get(timeout=5) == b"hello"
        client.close()
    finally:
        server.close()


def test_stream_server_stops_when_closed():
    """serve_forever returns once the listening socket is closed."""
    # pylint: disable=import-outside-toplevel
    from c65of.hub import StreamServer

    server = StreamServer(("127.0.0.1", 0), lambda sock, addr: None)
    done = threading.Event()

    def serve():
        server.serve_forever()
        done.set()

    hub.spawn(serve)
    server.close()
    assert done.wait(5)


def test_undecorated_handler_is_dispatched():
    """register_handler accepts a plain callable, not only a decorated method.

    Without this the dispatch loop raises looking up a callers mapping that is
    not there, outside the per-handler guard, and the app's thread dies
    silently.
    """
    app = Recorder()
    seen = []
    app.register_handler(Pong, seen.append)
    APPS[app.name] = app
    app.start()
    try:
        app.send_event(app.name, Pong(), MAIN_DISPATCHER)
        app.send_event(app.name, Ping(1))
        assert app.arrived.wait(5)
        assert len(seen) == 1
        assert app.main_thread.is_alive()
    finally:
        app.stop()
        APPS.pop(app.name, None)


def test_load_app_from_a_file_path(tmp_path):
    """An application can be given as a path, not only a dotted module name.

    --ryu-app-lists is given a path for an application that ships beside the
    controller rather than inside it, and such an application may import
    sibling files, so its own directory has to resolve.
    """
    (tmp_path / "helper.py").write_text("VALUE = 7\n", encoding="utf-8")
    (tmp_path / "sideapp.py").write_text(
        "from c65of.app import OFApp\n"
        "from helper import VALUE\n"
        "class SideApp(OFApp):\n"
        '    """An app loaded from a path."""\n'
        "    MARKER = VALUE\n",
        encoding="utf-8",
    )
    cls = AppManager().load_app(str(tmp_path / "sideapp.py"))
    assert cls is not None
    assert cls.__name__ == "SideApp"
    assert cls.MARKER == 7
    # The directory is not left on the path afterwards.
    assert str(tmp_path) not in sys.path


def test_load_app_from_a_missing_path():
    """A path that is not a module is an error naming the path."""
    with pytest.raises((ImportError, FileNotFoundError)):
        AppManager().load_app("/nonexistent/nope.py")


def test_ofp_events_carry_a_timestamp():
    """A message event records when the channel produced it.

    Consumers age what the message reports against this, and the handler may
    run well after the event was queued, so it cannot be read at handling
    time.
    """
    # pylint: disable=import-outside-toplevel
    import time

    from c65of import ofp_event
    from c65of.ofproto.messages import OFPPacketIn

    ofp_event.generate()
    before = time.time()
    ev = ofp_event.ofp_msg_to_ev(OFPPacketIn(None))
    after = time.time()
    assert before <= ev.timestamp <= after

"""The OpenFlow channel: framing, handshake, phases, echoes and teardown.

Every test drives a real listener over loopback with a plain client socket.
The bytes the controller writes are compared with what os-ken serializes for
the same message, and the switch's bytes are decoded with os-ken before they
are sent, so both directions are checked against an independent
implementation of the wire format.
"""

# A protocol channel has a lot of surface: handshake, framing, TLS, echo,
# shutdown. Splitting the file would only scatter one subject.
# pylint: disable=too-many-lines

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

import contextlib
import datetime
import logging
import socket
import ssl
import struct
import threading

import pytest
from os_ken.ofproto import ofproto_parser as oken_parser
from os_ken.ofproto import ofproto_protocol as oken_protocol
from os_ken.ofproto import ofproto_v1_3 as oken_ofp
from os_ken.ofproto import ofproto_v1_3_parser as oken_msgs

from c65of import hub, ofp_event
from c65of import ofproto as ofp
from c65of.app import (
    APPS,
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    HANDSHAKE_DISPATCHER,
    MAIN_DISPATCHER,
    OFApp,
    set_ev_cls,
)
from c65of.controller import Datapath, OFPHandler, OFPStreamParser, OpenFlowController
from c65of.ofproto import parser

TIMEOUT = 15.0
SOCKET_TIMEOUT = 0.05
DPID = 0x0000000000ABCDEF
MAC = b"\x00\x0e\x0c\x00\x00\x01"
OKEN_DP = oken_protocol.ProtocolDesc(version=oken_ofp.OFP_VERSION)


def oken_decode(data):
    """Decode a whole OpenFlow message with os-ken."""
    version, msg_type, msg_len, xid = oken_parser.header(data)
    return oken_parser.msg(OKEN_DP, version, msg_type, msg_len, xid, data)


def oken_bytes(msg, xid):
    """Serialize an os-ken message with a given xid."""
    msg.set_xid(xid)
    msg.serialize()
    return bytes(msg.buf)


def assert_is_oken(raw, msg):
    """The controller's bytes are exactly what os-ken emits for ``msg``."""
    assert raw == oken_bytes(msg, oken_parser.header(raw)[3])


def frame(msg_type, xid=0, body=b"", version=ofp.OFP_VERSION):
    """An OpenFlow message as a switch would put it on the wire."""
    header = struct.pack(
        "!BBHI", version, msg_type, ofp.OFP_HEADER_SIZE + len(body), xid
    )
    return header + body


def hello_frame(xid=0, version=ofp.OFP_VERSION, versions=None):
    """A hello, optionally carrying a version bitmap element."""
    body = b""
    if versions is not None:
        bitmap = 0
        for offered in versions:
            bitmap |= 1 << offered
        body = struct.pack("!HHI", ofp.OFPHET_VERSIONBITMAP, 8, bitmap)
    data = frame(ofp.OFPT_HELLO, xid, body, version=version)
    if versions is not None:
        assert oken_decode(data).elements[0].versions == sorted(versions)
    return data


def features_frame(xid, dpid=DPID):
    """A features reply."""
    data = frame(
        ofp.OFPT_FEATURES_REPLY, xid, struct.pack("!QIBB2xI4x", dpid, 256, 254, 0, 0x4F)
    )
    assert oken_decode(data).datapath_id == dpid
    return data


def port_body(port_no, name=None, config=0, state=0):
    """One ``struct ofp_port``."""
    return struct.pack(
        "!I4x6s2x16sIIIIIIII",
        port_no,
        MAC,
        (name or "port%d" % port_no).encode(),
        config,
        state,
        0,
        0,
        0,
        0,
        1000,
        10000,
    )


def port_desc_frame(xid, port_nos, flags=0):
    """A port description multipart reply."""
    body = struct.pack("!HH4x", ofp.OFPMP_PORT_DESC, flags)
    body += b"".join(port_body(port_no) for port_no in port_nos)
    data = frame(ofp.OFPT_MULTIPART_REPLY, xid, body)
    assert [port.port_no for port in oken_decode(data).body] == list(port_nos)
    return data


def port_status_frame(reason, port_no, xid=0, **kwargs):
    """A port status notification."""
    body = struct.pack("!B7x", reason) + port_body(port_no, **kwargs)
    data = frame(ofp.OFPT_PORT_STATUS, xid, body)
    assert oken_decode(data).desc.port_no == port_no
    return data


def error_frame(type_, code, data=b"", xid=0):
    """An error report from the switch, serialized by os-ken."""
    return oken_bytes(
        oken_msgs.OFPErrorMsg(OKEN_DP, type_=type_, code=code, data=data), xid
    )


def echo_frame(msg_type, xid, data=b""):
    """An echo request or reply, serialized by os-ken."""
    cls = (
        oken_msgs.OFPEchoRequest
        if msg_type == ofp.OFPT_ECHO_REQUEST
        else oken_msgs.OFPEchoReply
    )
    return oken_bytes(cls(OKEN_DP, data=data), xid)


def tcp_pair():
    """A connected pair of loopback TCP sockets."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.create_connection(listener.getsockname(), timeout=TIMEOUT)
    server, _ = listener.accept()
    listener.close()
    client.settimeout(TIMEOUT)
    return server, client


class Switch:
    """A test switch: a plain socket that speaks OpenFlow 1.3."""

    def __init__(self, sock):
        self.sock = sock
        self.sock.settimeout(TIMEOUT)

    @classmethod
    def connect(cls, address):
        """Open a plain TCP connection to the controller."""
        return cls(socket.create_connection(address, timeout=TIMEOUT))

    def close(self):
        """Drop the connection."""
        self.sock.close()

    def send(self, data):
        """Write raw bytes."""
        self.sock.sendall(data)

    def recv_exactly(self, size):
        """Read exactly ``size`` bytes or raise."""
        buf = b""
        while len(buf) < size:
            chunk = self.sock.recv(size - len(buf))
            if not chunk:
                raise EOFError("connection closed after %d of %d" % (len(buf), size))
            buf += chunk
        return buf

    def read_raw(self):
        """Read the bytes of exactly one message."""
        head = self.recv_exactly(ofp.OFP_HEADER_SIZE)
        _, _, msg_len, _ = oken_parser.header(head)
        return head + self.recv_exactly(msg_len - ofp.OFP_HEADER_SIZE)

    def read_msg(self):
        """Read one message; os-ken parses only what a controller receives."""
        raw = self.read_raw()
        return parser.msg(None, *oken_parser.header(raw), raw)

    def read_eof(self):
        """True once the controller has closed its side."""
        while True:
            if not self.sock.recv(4096):
                return True


class Observer(OFApp):
    """Records the events the channel emits."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.states = []
        self.port_changes = []
        self.errors = []
        self._flags = {}
        self._lock = threading.Lock()

    def flag(self, key):
        """The event marking ``key`` as seen."""
        with self._lock:
            return self._flags.setdefault(key, threading.Event())

    def wait(self, key):
        """Block until ``key`` has been seen."""
        assert self.flag(key).wait(TIMEOUT), "timed out waiting for %s" % (key,)

    @set_ev_cls(ofp_event.EventOFPStateChange)
    def state_change(self, ev):
        """Record a phase transition."""
        self.states.append(ev.state)
        self.flag(("state", ev.state)).set()

    @set_ev_cls(ofp_event.EventOFPPortStateChange)
    def port_state_change(self, ev):
        """Record a port change."""
        self.port_changes.append((ev.reason, ev.port_no))
        self.flag(("port", ev.reason, ev.port_no)).set()

    @set_ev_cls(ofp_event.EventOFPErrorMsg)
    def error_msg(self, ev):
        """Record an error report."""
        self.errors.append(ev.msg)
        self.flag("error").set()


class Channel:
    """A running controller, its handler, an observer and the test switches."""

    def __init__(self, **kwargs):
        self.handler = OFPHandler()
        self.observer = Observer()
        self.datapaths = hub.Queue()
        self.switches = []
        self.controller = OpenFlowController(
            listen_host="127.0.0.1",
            tcp_port=0,
            socket_timeout=SOCKET_TIMEOUT,
            **kwargs,
        )
        build = self.controller.datapath

        def record(sock, address):
            datapath = build(sock, address)
            self.datapaths.put(datapath)
            return datapath

        self.controller.datapath = record
        self.handler.controller = self.controller
        for app in (self.handler, self.observer):
            APPS[app.name] = app
        self.handler.start()
        self.observer.start()

    def connect(self):
        """Connect a switch and return it with the controller's datapath."""
        switch = Switch.connect(self.controller.tcp_address)
        self.switches.append(switch)
        return switch, self.datapaths.get(timeout=TIMEOUT)

    def handshake(self, port_nos=(1,)):
        """Drive one switch from hello to MAIN and return it with its datapath."""
        switch, datapath = self.connect()
        assert_is_oken(switch.read_raw(), oken_msgs.OFPHello(OKEN_DP))
        switch.send(hello_frame())
        raw = switch.read_raw()
        assert_is_oken(raw, oken_msgs.OFPFeaturesRequest(OKEN_DP))
        switch.send(features_frame(oken_parser.header(raw)[3]))
        assert_is_oken(
            switch.read_raw(),
            oken_msgs.OFPSetConfig(OKEN_DP, ofp.OFPC_FRAG_NORMAL, ofp.OFPCML_NO_BUFFER),
        )
        raw = switch.read_raw()
        assert_is_oken(raw, oken_msgs.OFPPortDescStatsRequest(OKEN_DP, 0))
        switch.send(port_desc_frame(oken_parser.header(raw)[3], port_nos))
        self.observer.wait(("state", MAIN_DISPATCHER))
        return switch, datapath

    def close(self):
        """Tear everything down."""
        for switch in self.switches:
            switch.close()
        self.controller.stop()
        self.handler.stop()
        self.observer.stop()
        for app in (self.handler, self.observer):
            APPS.pop(app.name, None)


@pytest.fixture(name="channel")
def _channel():
    net = Channel()
    yield net
    net.close()


@pytest.fixture(name="pair")
def _pair():
    server, client = tcp_pair()
    datapath = Datapath(server, ("127.0.0.1", 1), socket_timeout=SOCKET_TIMEOUT)
    yield datapath, client
    datapath.close()
    server.close()
    client.close()


@pytest.fixture(name="tls_certs", scope="module")
def _tls_certs(tmp_path_factory):
    """A throwaway self signed certificate and its key, as file paths."""
    x509 = pytest.importorskip("cryptography.x509")
    hashes = pytest.importorskip("cryptography.hazmat.primitives.hashes")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("tls")
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


# -- framing ----------------------------------------------------------------


def test_stream_parser_frames_two_messages_from_one_read():
    """Two messages arriving in one read come back as two messages."""
    stream = OFPStreamParser()
    msgs = stream.parse(hello_frame(1) + echo_frame(ofp.OFPT_ECHO_REQUEST, 2, b"hi"))
    assert [type(m).__name__ for m in msgs] == ["OFPHello", "OFPEchoRequest"]
    assert [m.xid for m in msgs] == [1, 2]


def test_stream_parser_waits_for_the_rest_of_a_message():
    """A message split across reads is held until it is complete."""
    stream = OFPStreamParser()
    data = echo_frame(ofp.OFPT_ECHO_REQUEST, 3, b"payload")
    assert not stream.parse(data[:5])
    assert not stream.parse(data[5:-1])
    msgs = stream.parse(data[-1:])
    assert [m.data for m in msgs] == [b"payload"]


def test_stream_parser_skips_a_message_shorter_than_its_header():
    """A length that cannot cover the header resynchronises the stream."""
    stream = OFPStreamParser()
    bogus = struct.pack("!BBHI", ofp.OFP_VERSION, ofp.OFPT_HELLO, 4, 0)
    msgs = stream.parse(bogus + hello_frame(9))
    assert msgs[0] is None
    assert msgs[1].xid == 9


def test_stream_parser_yields_none_for_an_unknown_message_type():
    """An unknown message type parses to None rather than raising."""
    stream = OFPStreamParser()
    assert stream.parse(frame(99, 1)) == [None]


# -- handshake --------------------------------------------------------------


def test_controller_sends_hello_on_connect(channel):
    """A new connection is greeted with a hello and starts in HANDSHAKE."""
    switch, datapath = channel.connect()
    assert_is_oken(switch.read_raw(), oken_msgs.OFPHello(OKEN_DP))
    assert datapath.state == HANDSHAKE_DISPATCHER
    assert datapath.is_active


def test_hello_moves_to_config_and_requests_features(channel):
    """A usable hello moves to CONFIG and asks for the switch's features."""
    switch, datapath = channel.connect()
    switch.read_raw()
    switch.send(hello_frame())
    assert_is_oken(switch.read_raw(), oken_msgs.OFPFeaturesRequest(OKEN_DP))
    channel.observer.wait(("state", CONFIG_DISPATCHER))
    assert datapath.state == CONFIG_DISPATCHER


def test_hello_version_bitmap_offering_our_version_is_accepted(channel):
    """A version bitmap that includes 1.3 negotiates successfully."""
    switch, _datapath = channel.connect()
    switch.read_raw()
    switch.send(hello_frame(versions=[1, ofp.OFP_VERSION]))
    assert_is_oken(switch.read_raw(), oken_msgs.OFPFeaturesRequest(OKEN_DP))


def test_hello_version_bitmap_without_our_version_fails(channel):
    """A version bitmap without 1.3 gets an error and a closed channel."""
    switch, _datapath = channel.connect()
    switch.read_raw()
    switch.send(hello_frame(versions=[1]))
    error = oken_decode(switch.read_raw())
    assert (error.type, error.code) == (ofp.OFPET_HELLO_FAILED, ofp.OFPHFC_INCOMPATIBLE)
    assert switch.read_eof()


def test_hello_with_an_unsupported_version_fails(channel):
    """A hello offering only versions we do not speak is rejected.

    An earlier version with no bitmap leaves nothing in common: the spec's
    rule is min(sent, received), and 1.0 is below what this library speaks.
    """
    switch, _datapath = channel.connect()
    switch.read_raw()
    switch.send(hello_frame(version=0x01))
    error = oken_decode(switch.read_raw())
    assert (error.type, error.code) == (ofp.OFPET_HELLO_FAILED, ofp.OFPHFC_INCOMPATIBLE)
    assert switch.read_eof()


def test_full_handshake_reaches_main(channel):
    """The whole handshake names the datapath, fills its ports and reaches MAIN."""
    _switch, datapath = channel.handshake(port_nos=(1, 2))
    assert datapath.id == DPID
    assert sorted(datapath.ports) == [1, 2]
    assert datapath.ports[2].name == b"port2"
    assert channel.observer.states == [
        HANDSHAKE_DISPATCHER,
        CONFIG_DISPATCHER,
        MAIN_DISPATCHER,
    ]


def test_multipart_port_desc_reply_more_defers_main(channel):
    """MAIN is deferred until the last part of the port description arrives."""
    switch, datapath = channel.connect()
    switch.read_raw()
    switch.send(hello_frame())
    switch.send(features_frame(oken_parser.header(switch.read_raw())[3]))
    switch.read_raw()
    xid = oken_parser.header(switch.read_raw())[3]
    switch.send(port_desc_frame(xid, (1,), flags=ofp.OFPMPF_REPLY_MORE))
    switch.send(port_desc_frame(xid, (2,)))
    channel.observer.wait(("state", MAIN_DISPATCHER))
    assert sorted(datapath.ports) == [1, 2]


# -- echoes, ports and errors ----------------------------------------------


def test_echo_request_is_answered_with_the_same_xid_and_data(channel):
    """An echo request comes back as an echo reply with the same xid and data."""
    switch, _datapath = channel.handshake()
    switch.send(echo_frame(ofp.OFPT_ECHO_REQUEST, 4242, b"ping"))
    raw = switch.read_raw()
    assert oken_parser.header(raw)[3] == 4242
    assert_is_oken(raw, oken_msgs.OFPEchoReply(OKEN_DP, data=b"ping"))


def test_echo_reply_clears_an_outstanding_request(channel):
    """An echo reply clears the matching outstanding echo request."""
    switch, datapath = channel.handshake()
    datapath.unreplied_echo_requests.append(1234)
    switch.send(echo_frame(ofp.OFPT_ECHO_REPLY, 1234))
    switch.send(echo_frame(ofp.OFPT_ECHO_REQUEST, 5, b"after"))
    assert switch.read_msg().data == b"after"
    assert datapath.unreplied_echo_requests == []


def test_unanswered_echo_requests_close_the_datapath():
    """Too many unanswered echo requests take the datapath to DEAD."""
    net = Channel(echo_request_interval=0.01, max_unreplied_echo_requests=1)
    try:
        switch, datapath = net.connect()
        assert isinstance(switch.read_msg(), parser.OFPHello)
        assert isinstance(switch.read_msg(), parser.OFPEchoRequest)
        assert isinstance(switch.read_msg(), parser.OFPEchoRequest)
        net.observer.wait(("state", DEAD_DISPATCHER))
        assert datapath.state == DEAD_DISPATCHER
    finally:
        net.close()


@pytest.mark.parametrize(
    "reason,expected",
    [
        (ofp.OFPPR_ADD, [1, 3]),
        (ofp.OFPPR_MODIFY, [1]),
        (ofp.OFPPR_DELETE, []),
    ],
)
def test_port_status_updates_the_ports_and_is_republished(channel, reason, expected):
    """A port status updates the datapath's ports and becomes a port state event."""
    switch, datapath = channel.handshake()
    port_no = 3 if reason == ofp.OFPPR_ADD else 1
    switch.send(port_status_frame(reason, port_no, state=ofp.OFPPS_LINK_DOWN))
    channel.observer.wait(("port", reason, port_no))
    assert sorted(datapath.ports) == expected
    assert channel.observer.port_changes == [(reason, port_no)]


def test_unknown_port_status_reason_is_ignored(channel):
    """A port status with an unknown reason changes nothing."""
    switch, datapath = channel.handshake()
    switch.send(port_status_frame(0xFE, 7))
    switch.send(echo_frame(ofp.OFPT_ECHO_REQUEST, 6, b"sync"))
    assert switch.read_msg().data == b"sync"
    assert sorted(datapath.ports) == [1]
    assert channel.observer.port_changes == []


def test_error_message_from_the_switch_is_delivered(channel):
    """An error report reaches the applications observing it."""
    switch, _datapath = channel.handshake()
    switch.send(error_frame(ofp.OFPET_BAD_REQUEST, ofp.OFPBRC_BAD_TYPE, b"\x04" * 64))
    channel.observer.wait("error")
    (error,) = channel.observer.errors
    assert (error.type, error.code) == (ofp.OFPET_BAD_REQUEST, ofp.OFPBRC_BAD_TYPE)


def test_short_error_message_is_logged_as_a_warning(channel, caplog):
    """An error carrying too little of the failed request is called out."""
    switch, _datapath = channel.handshake()
    switch.send(error_frame(ofp.OFPET_BAD_REQUEST, ofp.OFPBRC_BAD_TYPE, b"ab"))
    channel.observer.wait("error")
    switch.send(echo_frame(ofp.OFPT_ECHO_REQUEST, 8, b"sync"))
    assert switch.read_msg().data == b"sync"
    assert "at least 64" in caplog.text


def test_experimenter_error_message_is_delivered(channel):
    """An experimenter error keeps its experimenter id and type."""
    switch, _datapath = channel.handshake()
    switch.send(
        oken_bytes(
            oken_msgs.OFPErrorExperimenterMsg(
                OKEN_DP, exp_type=3, experimenter=0x2320, data=b"x"
            ),
            11,
        )
    )
    channel.observer.wait("error")
    (error,) = channel.observer.errors
    assert (error.experimenter, error.exp_type) == (0x2320, 3)


# -- teardown ---------------------------------------------------------------


def test_peer_disconnect_moves_the_datapath_to_dead(channel):
    """A switch dropping the connection takes its datapath to DEAD."""
    switch, datapath = channel.handshake()
    switch.close()
    channel.observer.wait(("state", DEAD_DISPATCHER))
    assert datapath.state == DEAD_DISPATCHER
    assert not datapath.is_active


def test_close_moves_the_datapath_to_dead_and_shuts_the_socket(channel):
    """Closing a datapath ends the connection the switch sees."""
    switch, datapath = channel.handshake()
    datapath.close()
    channel.observer.wait(("state", DEAD_DISPATCHER))
    assert switch.read_eof()


def test_controller_stop_closes_the_listener(channel):
    """Stopping the controller frees the listening port."""
    address = channel.controller.tcp_address
    channel.controller.stop()
    assert channel.controller.listeners == []
    with pytest.raises(OSError):
        socket.create_connection(address, timeout=TIMEOUT).close()


def _sabotage(datapath):
    """Make ``serve`` raise, standing in for a switch that breaks the parser."""

    def explode():
        raise RuntimeError("boom")

    datapath.serve = explode
    return datapath


def test_serve_connection_survives_a_broken_datapath(channel, caplog):
    """One connection raising does not take the listener down."""
    server, client = tcp_pair()
    build = channel.controller.datapath
    channel.controller.datapath = lambda sock, address: _sabotage(build(sock, address))
    channel.controller.serve_connection(server, ("127.0.0.1", 2))
    client.close()
    server.close()
    assert "error in the datapath" in caplog.text


# -- datapath internals -----------------------------------------------------


def test_set_xid_assigns_before_the_message_is_queued(pair):
    """The xid is on the message before anything is queued."""
    datapath, _client = pair
    msg = parser.OFPBarrierRequest(datapath)
    seen = []

    def spy(buf, close_socket=False):
        """Record the xid the message carries at the moment it is queued."""
        del buf, close_socket
        seen.append(msg.xid)
        return True

    datapath.send = spy
    datapath.send_msg(msg)
    assert msg.xid is not None
    assert seen == [msg.xid]


def test_set_xid_increments_and_wraps(pair):
    """Transaction ids increment and wrap at the protocol maximum."""
    datapath, _client = pair
    datapath.xid = ofp.MAX_XID - 1
    assert datapath.set_xid(parser.OFPBarrierRequest(datapath)) == ofp.MAX_XID
    assert datapath.set_xid(parser.OFPBarrierRequest(datapath)) == 0


def test_send_msg_preserves_order(pair):
    """Messages reach the wire in the order they were queued."""
    datapath, client = pair
    writer = hub.spawn(datapath._send_loop)  # pylint: disable=protected-access
    xids = [datapath.send_barrier() and datapath.xid for _ in range(5)]
    switch = Switch(client)
    assert [switch.read_msg().xid for _ in range(5)] == xids
    datapath.close()
    hub.joinall([writer])


def test_send_after_close_is_refused(pair):
    """Sending on a closed datapath is refused rather than queued."""
    datapath, _client = pair
    writer = hub.spawn(datapath._send_loop)  # pylint: disable=protected-access
    datapath.close()
    hub.joinall([writer])
    assert datapath.send_q is None
    assert datapath.send(b"ignored") is False


def test_datapath_str_shows_the_dpid(pair):
    """A datapath prints its dpid once it has one."""
    datapath, _client = pair
    assert "id=None" in str(datapath)
    datapath.id = DPID
    assert "%016x" % DPID in repr(datapath)


def test_acknowledge_unknown_echo_reply_is_a_no_op(pair):
    """Acknowledging an xid we never sent does nothing."""
    datapath, _client = pair
    datapath.acknowledge_echo_reply(99)
    assert datapath.unreplied_echo_requests == []


def test_datapath_without_a_brick_drops_events(pair):
    """A datapath with no handshake application still changes phase."""
    datapath, _client = pair
    datapath.ofp_brick = None
    datapath.set_state(MAIN_DISPATCHER)
    assert datapath.state == MAIN_DISPATCHER


def test_a_frame_shorter_than_its_header_is_skipped():
    """An impossible length is stepped over rather than trusted.

    Trusting it would either desynchronise the stream or wait forever for a
    frame that cannot arrive, so the parser skips one header and resumes.
    """
    parser_ = OFPStreamParser()
    bad = struct.pack("!BBHI", ofp.OFP_VERSION, ofp.OFPT_ECHO_REQUEST, 2, 1)
    good = struct.pack("!BBHI", ofp.OFP_VERSION, ofp.OFPT_ECHO_REPLY, 8, 7)
    msgs = parser_.parse(bad + good)
    assert [m for m in msgs if m is not None][0].xid == 7


# -- listeners --------------------------------------------------------------


def test_default_ports_come_from_the_protocol():
    """With no ports configured the protocol's defaults are used."""
    controller = OpenFlowController()
    assert (controller.tcp_port, controller.ssl_port) == (
        ofp.OFP_TCP_PORT,
        ofp.OFP_SSL_PORT,
    )
    assert not controller.use_ssl


def test_tls_listener_completes_a_handshake(tls_certs):
    """A TLS client gets the same hello as a plain one."""
    cert, key = tls_certs
    controller = OpenFlowController(
        listen_host="127.0.0.1",
        tcp_port=0,
        ssl_port=0,
        ctl_cert=cert,
        ctl_privkey=key,
        ciphers="ECDHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384",
        socket_timeout=SOCKET_TIMEOUT,
    )
    handler = OFPHandler(controller=controller)
    APPS[handler.name] = handler
    handler.start()
    try:
        assert controller.use_ssl
        assert len(controller.listeners) == 2
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(controller.ssl_address, timeout=TIMEOUT)
        with context.wrap_socket(raw) as tls:
            assert_is_oken(Switch(tls).read_raw(), oken_msgs.OFPHello(OKEN_DP))
    finally:
        handler.stop()
        handler.close()
        APPS.pop(handler.name, None)


def test_tls_listener_rejects_a_plain_connection(tls_certs, caplog):
    """A plain connection to the TLS port is dropped."""
    caplog.set_level(logging.DEBUG)
    cert, key = tls_certs
    controller = OpenFlowController(
        listen_host="127.0.0.1",
        tcp_port=0,
        ssl_port=0,
        ctl_cert=cert,
        ctl_privkey=key,
        socket_timeout=SOCKET_TIMEOUT,
    )
    controller.start()
    try:
        plain = socket.create_connection(controller.ssl_address, timeout=TIMEOUT)
        plain.sendall(b"not tls at all\n")
        with contextlib.suppress(ConnectionResetError):
            assert plain.recv(4096) == b""
        plain.close()
    finally:
        controller.stop()
    assert "TLS handshake" in caplog.text


def test_ca_certs_require_a_client_certificate(tls_certs):
    """Configured CA certificates make a client certificate mandatory."""
    cert, key = tls_certs
    controller = OpenFlowController(ctl_cert=cert, ctl_privkey=key, ca_certs=cert)
    context = controller.ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_send_loop_survives_a_socket_error(pair):
    """A write to a dead socket ends the writer instead of raising."""
    datapath, client = pair
    client.close()
    datapath.socket.close()
    writer = hub.spawn(datapath._send_loop)  # pylint: disable=protected-access
    datapath.send_barrier()
    hub.joinall([writer])
    assert datapath.send_q is None


def test_recv_loop_survives_a_socket_error(pair):
    """A read from a dead socket ends the reader instead of raising."""
    datapath, _client = pair
    datapath.socket.close()
    datapath._recv_loop()  # pylint: disable=protected-access


def test_echo_loop_stops_when_the_datapath_closes(pair):
    """Closing a datapath ends its echo loop without waiting out the interval."""
    datapath, client = pair
    datapath.max_unreplied_echo_requests = 5
    datapath.echo_request_interval = 300.0
    writer = hub.spawn(datapath._send_loop)  # pylint: disable=protected-access
    echo = hub.spawn(datapath._echo_request_loop)  # pylint: disable=protected-access
    assert isinstance(Switch(client).read_msg(), parser.OFPEchoRequest)
    datapath.close()
    hub.joinall([echo, writer])
    assert datapath.state == DEAD_DISPATCHER


def test_calling_the_controller_serves_until_stopped():
    """Calling the controller listens, then blocks until it is stopped."""
    controller = OpenFlowController(
        listen_host="127.0.0.1", tcp_port=0, socket_timeout=SOCKET_TIMEOUT
    )
    listening = threading.Event()
    start = controller.start

    def announce():
        threads = start()
        listening.set()
        return threads

    controller.start = announce
    serving = hub.spawn(controller)
    assert listening.wait(TIMEOUT)
    socket.create_connection(controller.tcp_address, timeout=TIMEOUT).close()
    controller.stop()
    hub.joinall([serving])


def test_handler_creates_a_controller_when_given_none(monkeypatch):
    """A handler with no controller of its own builds the default one."""

    class FakeController:
        """Records that it was started and stopped."""

        def __init__(self):
            self.stopped = False

        def start(self):
            """Pretend to bind a listener."""
            return []

        def stop(self):
            """Record the shutdown."""
            self.stopped = True

    monkeypatch.setattr("c65of.controller.OpenFlowController", FakeController)
    handler = OFPHandler()
    handler.start()
    try:
        assert isinstance(handler.controller, FakeController)
    finally:
        handler.stop()
        handler.close()
    assert handler.controller.stopped


def test_datapath_id_is_set_before_observers_see_the_features_reply(channel):
    """Every observer of the features reply sees the datapath already named.

    os-ken sets the id inside its own handler and gets away with it because it
    runs that handler inline on the read thread. Here every observer runs
    concurrently on its own thread, so an application looking the datapath up
    by id -- as faucet does -- would race the handshake application and see
    None. Setting it in the channel removes the race.
    """
    seen = []
    ready = threading.Event()

    class NamingObserver(OFApp):
        """Records the datapath id at the moment the event is delivered."""

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def features(self, ev):
            """Note what the datapath was called when this arrived."""
            seen.append(ev.msg.datapath.id)
            ready.set()

    observer = NamingObserver()
    APPS[observer.name] = observer
    observer.start()
    try:
        switch, _datapath = channel.connect()
        switch.read_raw()
        switch.send(hello_frame())
        raw = switch.read_raw()
        switch.send(features_frame(oken_parser.header(raw)[3]))
        assert ready.wait(SOCKET_TIMEOUT)
        assert seen == [DPID]
    finally:
        observer.stop()
        APPS.pop(observer.name, None)


def test_queued_message_is_sent_even_though_close_races_it(pair):
    """A message queued before close() still reaches the switch.

    close() flips the state and then queues its sentinel, so a send loop that
    tested the state before dequeuing would drop whatever was already in
    flight. hello_failed depends on this: it queues an error and closes, and
    the switch has to see the error rather than a bare disconnect.
    """
    datapath, client = pair
    datapath.set_state(HANDSHAKE_DISPATCHER)
    # Queue first, then flip the state as close() does, and only then let the
    # send loop run: with the state tested before the dequeue, this is exactly
    # the interleaving that dropped the message.
    datapath.hello_failed("no compatible version found")
    datapath.set_state(DEAD_DISPATCHER)
    hub.spawn(datapath._send_loop)  # pylint: disable=protected-access
    client.settimeout(SOCKET_TIMEOUT)
    raw = b""
    while len(raw) < 8:
        chunk = client.recv(8 - len(raw))
        assert chunk, "closed before the error was sent"
        raw += chunk
    version, msg_type, length, _xid = struct.unpack("!BBHI", raw)
    assert (version, msg_type) == (ofp.OFP_VERSION, ofp.OFPT_ERROR)
    body = b""
    while len(body) < length - 8:
        body += client.recv(length - 8 - len(body))
    err_type, err_code = struct.unpack_from("!HH", body)
    assert (err_type, err_code) == (ofp.OFPET_HELLO_FAILED, ofp.OFPHFC_INCOMPATIBLE)


@pytest.mark.parametrize(
    "version, versions",
    [
        # What Open vSwitch actually sends: it opens at its own highest
        # version and offers a bitmap covering everything it speaks.
        (0x06, [1, 2, 3, 4, 5, 6]),
        (0x06, [4]),
        # A later version with no bitmap: the spec's rule is min(sent, received).
        (0x06, None),
        (0x05, None),
    ],
)
def test_a_switch_speaking_a_later_version_negotiates_down(channel, version, versions):
    """A hello announcing a later protocol is negotiated down, not rejected.

    A hello carries the version negotiation itself, so it has to be read
    whatever version it announces. Rejecting it outright left every real
    switch unable to connect while every test using a 1.3 hello passed.
    """
    switch, datapath = channel.connect()
    assert_is_oken(switch.read_raw(), oken_msgs.OFPHello(OKEN_DP))
    switch.send(hello_frame(version=version, versions=versions))
    assert_is_oken(switch.read_raw(), oken_msgs.OFPFeaturesRequest(OKEN_DP))
    assert datapath.state == CONFIG_DISPATCHER


@pytest.mark.parametrize(
    "version, versions",
    [
        # Offers a bitmap that does not include 1.3.
        (0x06, [1, 5, 6]),
        # Announces a version below ours and offers no bitmap.
        (0x01, None),
    ],
)
def test_a_switch_with_no_version_in_common_is_told_so(channel, version, versions):
    """No usable version still gets an error rather than a silent drop."""
    switch, datapath = channel.connect()
    assert_is_oken(switch.read_raw(), oken_msgs.OFPHello(OKEN_DP))
    switch.send(hello_frame(version=version, versions=versions))
    raw = switch.read_raw()
    parsed = oken_decode(raw)
    assert parsed.type == ofp.OFPET_HELLO_FAILED
    assert parsed.code == ofp.OFPHFC_INCOMPATIBLE
    channel.observer.wait(("state", DEAD_DISPATCHER))
    assert datapath.state == DEAD_DISPATCHER


def test_a_malformed_message_does_not_drop_the_channel(channel, caplog):
    """One bad message is logged and skipped; the switch keeps its channel.

    The frame length is validated before the body is parsed, so the stream is
    still in sync and the next message parses. Dropping the channel would turn
    a single malformed message into a reconnect -- which is what a control
    plane fuzz test measures.
    """
    switch, datapath = channel.handshake()
    # A port status claiming a length its body cannot fill.
    switch.send(frame(ofp.OFPT_PORT_STATUS, 1, b"\x00" * 4))
    # The channel survives and still answers.
    switch.send(frame(ofp.OFPT_ECHO_REQUEST, 2, b"ping"))
    reply = oken_decode(switch.read_raw())
    assert reply.msg_type == ofp.OFPT_ECHO_REPLY
    assert reply.data == b"ping"
    assert datapath.state == MAIN_DISPATCHER
    assert "malformed OpenFlow message" in caplog.text

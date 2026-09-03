"""The OpenFlow channel: listeners, per switch connections and the handshake.

:class:`OpenFlowController` accepts connections and hands each to a
:class:`Datapath`, which reads and writes its socket on two daemon threads.
:class:`OFPHandler` negotiates the version and walks the datapath from
HANDSHAKE through CONFIG to MAIN, and finally to DEAD.
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

import contextlib
import logging
import random
import socket
import ssl
import threading

from c65of import hub, ofp_event
from c65of import ofproto as ofp
from c65of.app import (
    APPS,
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    HANDSHAKE_DISPATCHER,
    MAIN_DISPATCHER,
    OFApp,
    set_ev_handler,
)
from c65of.ofproto import parser as ofproto_parser
from c65of.ofproto.base import OFPUnknownVersion
from c65of.packet.stream_parser import StreamParser

LOG = logging.getLogger(__name__)

DEFAULT_OFP_HOST = "0.0.0.0"
#: Seconds a socket operation blocks before its loop rechecks the state.
DEFAULT_SOCKET_TIMEOUT = 5.0
#: Seconds between echo requests.
DEFAULT_ECHO_REQUEST_INTERVAL = 15.0
#: Unreplied echo requests tolerated; 0 disables the echo loop entirely.
DEFAULT_MAX_UNREPLIED_ECHO_REQUESTS = 0
LISTEN_BACKLOG = 128
RECV_SIZE = 65536
#: Name the handshake application registers under in :data:`c65of.app.APPS`.
OFP_BRICK_NAME = "OFPHandler"


class OFPStreamParser(StreamParser):
    """Frames whole OpenFlow messages out of a TCP byte stream."""

    def __init__(self, datapath=None):
        super().__init__()
        self.datapath = datapath

    def try_parse(self, q):
        """Return ``(msg, rest)``; ``msg`` is None for a message we cannot build."""
        if len(q) < ofp.OFP_HEADER_SIZE:
            raise self.TooSmallException()
        version, msg_type, msg_len, xid = ofproto_parser.header(q)
        if msg_len < ofp.OFP_HEADER_SIZE:
            # Too short to cover its own header: resynchronise past it.
            LOG.debug("invalid message length %s from %s", msg_len, self.datapath)
            return None, q[ofp.OFP_HEADER_SIZE :]
        if len(q) < msg_len:
            raise self.TooSmallException()
        return (
            ofproto_parser.msg(
                self.datapath, version, msg_type, msg_len, xid, q[:msg_len]
            ),
            q[msg_len:],
        )


class Datapath:
    """One OpenFlow switch connected to this controller.

    ``ofproto`` and ``ofproto_parser`` are the constant and structure modules
    for the negotiated version, so an application can build messages for a
    switch without importing either itself.
    """

    #: OpenFlow versions this controller speaks.
    supported_ofp_version = (ofp.OFP_VERSION,)

    def __init__(
        self,
        sock,
        address,
        ofp_brick=None,
        socket_timeout=DEFAULT_SOCKET_TIMEOUT,
        echo_request_interval=DEFAULT_ECHO_REQUEST_INTERVAL,
        max_unreplied_echo_requests=DEFAULT_MAX_UNREPLIED_ECHO_REQUESTS,
    ):
        self.socket = sock
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.settimeout(socket_timeout)
        self.address = address
        self.is_active = True
        self.ofproto = ofp
        self.ofproto_parser = ofproto_parser
        # Unbounded on purpose: a bounded queue blocks whoever calls send_msg
        # once full, and that is usually an event dispatch thread -- the same
        # thread that must run the handler waking a sender blocked on a reply.
        self.send_q = hub.Queue()
        self.echo_request_interval = echo_request_interval
        self.max_unreplied_echo_requests = max_unreplied_echo_requests
        self.unreplied_echo_requests = []
        self.xid = random.randint(0, ofp.MAX_XID)
        self.id = None
        self.ports = {}
        self.ofp_brick = (
            ofp_brick if ofp_brick is not None else APPS.get(OFP_BRICK_NAME)
        )
        self.state = None
        self._stopped = threading.Event()
        self.set_state(HANDSHAKE_DISPATCHER)

    def __str__(self):
        return "Datapath<id=%s,address=%s,state=%s>" % (
            self.id if self.id is None else "%016x" % self.id,
            self.address,
            self.state,
        )

    __repr__ = __str__

    def set_state(self, state):
        """Move to negotiation phase ``state`` and tell every observer."""
        if self.state == state:
            return
        self.state = state
        ev = ofp_event.EventOFPStateChange(self)
        ev.state = state
        if self.ofp_brick is not None:
            self.ofp_brick.send_event_to_observers(ev, state)

    def close(self):
        """Mark the datapath dead and stop its threads."""
        self._stopped.set()
        self.set_state(DEAD_DISPATCHER)
        q = self.send_q
        if q is not None:
            # Wakes _send_loop, parked on a blocking get().
            q.put((None, False))

    def set_xid(self, msg):
        """Assign ``msg`` the next transaction id and return it.

        Returned before the message is queued, so a caller can register a
        waiter for the reply while the request is still in the queue.
        """
        self.xid = (self.xid + 1) & ofp.MAX_XID
        msg.set_xid(self.xid)
        return self.xid

    def send(self, buf, close_socket=False):
        """Queue raw bytes for the writer thread. False if the channel is gone."""
        q = self.send_q
        if q is None:
            LOG.debug("datapath %s terminating; send discarded", self.address)
            return False
        q.put((bytes(buf), close_socket))
        return True

    def send_msg(self, msg, close_socket=False):
        """Serialize and queue an OpenFlow message."""
        assert isinstance(msg, self.ofproto_parser.MsgBase)
        if msg.xid is None:
            self.set_xid(msg)
        msg.serialize()
        return self.send(msg.buf, close_socket=close_socket)

    def send_barrier(self):
        """Queue a barrier request."""
        return self.send_msg(self.ofproto_parser.OFPBarrierRequest(self))

    def hello_failed(self, error_desc):
        """Report an unusable version to the switch and drop the connection."""
        LOG.error("%s on datapath %s", error_desc, self.address)
        self.send_msg(
            self.ofproto_parser.OFPErrorMsg(
                datapath=self,
                type_=ofp.OFPET_HELLO_FAILED,
                code=ofp.OFPHFC_INCOMPATIBLE,
                data=error_desc,
            ),
            close_socket=True,
        )
        # Queued first, so the send loop drains the error before the sentinel
        # close() puts behind it.
        self.close()

    def _close_write(self):
        # Half close, so the switch sees the last bytes and closes its end.
        with contextlib.suppress(OSError, ValueError):
            self.socket.shutdown(socket.SHUT_WR)

    def _send_loop(self):
        # Loop on the queue rather than on the state: close() flips the state
        # and then queues the sentinel, so testing the state first would drop
        # whatever was already queued -- including the error message
        # hello_failed sends immediately before closing.
        try:
            while True:
                buf, close_socket = self.send_q.get()
                if buf is None:
                    break
                self.socket.sendall(buf)
                if close_socket:
                    break
        except OSError as exc:
            LOG.debug("send to switch at %s failed: %s", self.address, exc)
        finally:
            self.send_q = None
            self._close_write()

    def _recv_loop(self):
        stream = OFPStreamParser(self)
        while self.state != DEAD_DISPATCHER:
            try:
                data = self.socket.recv(RECV_SIZE)
            except socket.timeout:
                continue
            except OSError as exc:
                LOG.debug("recv from switch at %s failed: %s", self.address, exc)
                break
            if not data:
                break
            try:
                msgs = stream.parse(data)
            except OFPUnknownVersion as exc:
                self.hello_failed(str(exc))
                break
            except Exception:  # pylint: disable=broad-except
                LOG.exception("malformed message from switch at %s", self.address)
                break
            for msg in msgs:
                if msg is not None:
                    self._dispatch(msg)

    def _absorb(self, msg):
        """Record what the message says about the channel itself.

        The datapath id has to be set before the event reaches any observer:
        os-ken gets away with setting it in a handler because it runs its own
        handlers inline on this thread, but here every observer -- including
        the handshake application -- runs concurrently, and an application
        that looks the datapath up by id would see None.
        """
        if isinstance(msg, self.ofproto_parser.OFPSwitchFeatures):
            self.id = msg.datapath_id
            # OpenFlow 1.3 moved the port list out of the features reply.
            self.ports = {}

    def _dispatch(self, msg):
        self._absorb(msg)
        # Queue and return: handlers run on their own application's thread, so
        # parsing the next message never waits on one of them.
        if self.ofp_brick is not None:
            self.ofp_brick.send_event_to_observers(
                ofp_event.ofp_msg_to_ev(msg), self.state
            )

    def _echo_request_loop(self):
        if not self.max_unreplied_echo_requests:
            return
        while (
            self.send_q is not None
            and len(self.unreplied_echo_requests) <= self.max_unreplied_echo_requests
        ):
            echo_req = self.ofproto_parser.OFPEchoRequest(self)
            self.unreplied_echo_requests.append(self.set_xid(echo_req))
            self.send_msg(echo_req)
            if self._stopped.wait(self.echo_request_interval):
                return
        self.close()

    def acknowledge_echo_reply(self, xid):
        """Forget an outstanding echo request."""
        with contextlib.suppress(ValueError):
            self.unreplied_echo_requests.remove(xid)

    def serve(self):
        """Run the channel until the connection ends."""
        send_thr = hub.spawn(self._send_loop)
        self.send_msg(self.ofproto_parser.OFPHello(self))
        echo_thr = hub.spawn(self._echo_request_loop)
        try:
            self._recv_loop()
        finally:
            self.is_active = False
            self.close()
            hub.joinall([send_thr, echo_thr])
            with contextlib.suppress(OSError):
                self.socket.close()


class OpenFlowController:
    """Listens for switch connections and gives each one a :class:`Datapath`.

    Every setting is a constructor argument: nothing here reads a process
    wide configuration object.
    """

    def __init__(
        self,
        listen_host=DEFAULT_OFP_HOST,
        tcp_port=None,
        ssl_port=None,
        ctl_cert=None,
        ctl_privkey=None,
        ca_certs=None,
        ciphers=None,
        socket_timeout=DEFAULT_SOCKET_TIMEOUT,
        echo_request_interval=DEFAULT_ECHO_REQUEST_INTERVAL,
        max_unreplied_echo_requests=DEFAULT_MAX_UNREPLIED_ECHO_REQUESTS,
    ):
        self.listen_host = listen_host
        self.tcp_port = ofp.OFP_TCP_PORT if tcp_port is None else tcp_port
        self.ssl_port = ofp.OFP_SSL_PORT if ssl_port is None else ssl_port
        self.ctl_cert = ctl_cert
        self.ctl_privkey = ctl_privkey
        self.ca_certs = ca_certs
        self.ciphers = ciphers
        self.socket_timeout = socket_timeout
        self.echo_request_interval = echo_request_interval
        self.max_unreplied_echo_requests = max_unreplied_echo_requests
        self.is_active = False
        self.listeners = []
        self.threads = []
        #: Bound ``(host, port)`` of the plain and the TLS listener.
        self.tcp_address = None
        self.ssl_address = None

    @property
    def use_ssl(self):
        """True when a certificate and private key were configured."""
        return self.ctl_cert is not None and self.ctl_privkey is not None

    def __call__(self):
        """Entry point: listen, then block until stopped."""
        self.start()
        hub.joinall(self.threads)

    def start(self):
        """Bind the listeners and start accepting. Returns the accept threads."""
        self.is_active = True
        sock = self._listen(self.tcp_port)
        self.tcp_address = sock.getsockname()
        self._accept_on(sock, None)
        if self.use_ssl:
            sock = self._listen(self.ssl_port)
            self.ssl_address = sock.getsockname()
            self._accept_on(sock, self.ssl_context())
        return list(self.threads)

    def stop(self):
        """Close the listeners and wait for the accept threads to finish."""
        self.is_active = False
        for sock in self.listeners:
            with contextlib.suppress(OSError):
                sock.close()
        hub.joinall(self.threads)
        self.listeners = []
        self.threads = []

    def ssl_context(self):
        """A server TLS context built from the configured certificate paths."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.options |= ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
        ctx.load_cert_chain(self.ctl_cert, self.ctl_privkey)
        if self.ca_certs is not None:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(self.ca_certs)
        if self.ciphers is not None:
            ctx.set_ciphers(self.ciphers)
        return ctx

    def _listen(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Closing a socket does not wake a thread blocked in accept(), so the
        # listener times out and rechecks is_active instead.
        sock.settimeout(self.socket_timeout)
        sock.bind((self.listen_host, port))
        sock.listen(LISTEN_BACKLOG)
        self.listeners.append(sock)
        return sock

    def _accept_on(self, sock, ssl_ctx):
        self.threads.append(hub.spawn(self._accept_loop, sock, ssl_ctx))

    def _accept_loop(self, listener, ssl_ctx):
        while self.is_active:
            try:
                sock, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if ssl_ctx is not None:
                try:
                    sock = ssl_ctx.wrap_socket(sock, server_side=True)
                except (OSError, ValueError) as exc:
                    LOG.debug("TLS handshake with %s failed: %s", address, exc)
                    sock.close()
                    continue
            hub.spawn(self.serve_connection, sock, address)

    def datapath(self, sock, address):
        """Build the :class:`Datapath` for an accepted connection."""
        return Datapath(
            sock,
            address,
            socket_timeout=self.socket_timeout,
            echo_request_interval=self.echo_request_interval,
            max_unreplied_echo_requests=self.max_unreplied_echo_requests,
        )

    def serve_connection(self, sock, address):
        """Run one accepted connection to completion."""
        datapath = self.datapath(sock, address)
        try:
            datapath.serve()
        except Exception:  # pylint: disable=broad-except
            LOG.exception("error in the datapath %s from %s", datapath, address)
        finally:
            datapath.close()


class OFPHandler(OFApp):
    """Negotiates the OpenFlow channel and keeps it alive.

    A hello with a usable version moves the datapath to CONFIG and asks for
    its features; the features reply and the port descriptions complete the
    handshake and move it to MAIN. Echoes are answered in any phase.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.controller = kwargs.get("controller")

    def start(self):
        """Start the dispatch thread, then the listeners."""
        super().start()
        if self.controller is None:
            self.controller = OpenFlowController()
        self.threads.extend(self.controller.start())
        return self.main_thread

    def close(self):
        """Stop listening."""
        if self.controller is not None:
            self.controller.stop()

    @set_ev_handler(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
    def hello_handler(self, ev):
        """Negotiate a version and ask the switch for its features."""
        msg = ev.msg
        datapath = msg.datapath
        supported = set(datapath.supported_ofp_version)
        elements = getattr(msg, "elements", None)
        if elements:
            offered = {v for elem in elements for v in elem.versions}
        else:
            # No bitmap: the spec's rule is min(version sent, version received).
            offered = {v for v in supported if v <= msg.version}
        usable = offered & supported
        if not usable:
            datapath.hello_failed(
                "no compatible version found: switch offers %s, controller "
                "speaks %s" % (sorted(offered) or [msg.version], sorted(supported))
            )
            return
        datapath.set_state(CONFIG_DISPATCHER)
        datapath.send_msg(datapath.ofproto_parser.OFPFeaturesRequest(datapath))

    @set_ev_handler(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Record the datapath id, configure the switch and ask for its ports."""
        msg = ev.msg
        datapath = msg.datapath
        # The id and the empty port map are set by Datapath._absorb, before
        # any observer sees this event.
        datapath.send_msg(
            datapath.ofproto_parser.OFPSetConfig(
                datapath, ofp.OFPC_FRAG_NORMAL, ofp.OFPCML_NO_BUFFER
            )
        )
        datapath.send_msg(datapath.ofproto_parser.OFPPortDescStatsRequest(datapath, 0))

    @set_ev_handler(ofp_event.EventOFPPortDescStatsReply, CONFIG_DISPATCHER)
    def multipart_reply_handler(self, ev):
        """Fill in the ports; the last part completes the handshake."""
        msg = ev.msg
        datapath = msg.datapath
        for port in msg.body:
            datapath.ports[port.port_no] = port
        if msg.flags & ofp.OFPMPF_REPLY_MORE:
            return
        datapath.set_state(MAIN_DISPATCHER)

    @set_ev_handler(
        ofp_event.EventOFPEchoRequest,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER],
    )
    def echo_request_handler(self, ev):
        """Echo the request straight back."""
        msg = ev.msg
        datapath = msg.datapath
        echo_reply = datapath.ofproto_parser.OFPEchoReply(datapath)
        echo_reply.xid = msg.xid
        echo_reply.data = msg.data
        datapath.send_msg(echo_reply)

    @set_ev_handler(
        ofp_event.EventOFPEchoReply,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER],
    )
    def echo_reply_handler(self, ev):
        """Clear the matching outstanding echo request."""
        ev.msg.datapath.acknowledge_echo_reply(ev.msg.xid)

    @set_ev_handler(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        """Track the port and republish the change as a port state event."""
        msg = ev.msg
        datapath = msg.datapath
        if msg.reason in (ofp.OFPPR_ADD, ofp.OFPPR_MODIFY):
            datapath.ports[msg.desc.port_no] = msg.desc
        elif msg.reason == ofp.OFPPR_DELETE:
            datapath.ports.pop(msg.desc.port_no, None)
        else:
            return
        self.send_event_to_observers(
            ofp_event.EventOFPPortStateChange(datapath, msg.reason, msg.desc.port_no),
            datapath.state,
        )

    @set_ev_handler(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER],
    )
    def error_msg_handler(self, ev):
        """Log an error report from the switch."""
        msg = ev.msg
        if msg.type == ofp.OFPET_EXPERIMENTER:
            self.logger.debug(
                "OFPErrorMsg xid=%s experimenter=%s exp_type=%s data=%r",
                msg.xid,
                msg.experimenter,
                msg.exp_type,
                msg.data,
            )
            return
        self.logger.debug(
            "OFPErrorMsg xid=%s type=%s code=%s data=%r",
            msg.xid,
            msg.type,
            msg.code,
            msg.data,
        )
        if msg.type != ofp.OFPET_HELLO_FAILED and len(msg.data) < ofp.OFP_HEADER_SIZE:
            self.logger.warning(
                "switch at %s sent an error with only %d bytes of the failed "
                "request; the spec asks for at least 64",
                msg.datapath.address,
                len(msg.data),
            )

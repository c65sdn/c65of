"""Application framework: events, handlers and the app event loop.

An application declares handlers with :func:`set_ev_cls` and receives the
events it declared on its own thread. There is one event queue and one
dispatch thread per application.

The queue is unbounded on purpose. A bounded queue has to block the sender
when full, and the sender is often the dispatch thread itself, which
deadlocks; an OpenFlow controller would rather grow a queue than stall its
control channel.
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
import importlib
import inspect
import logging
import queue

from c65of import hub

# Negotiation phases a datapath moves through. A handler can name the phases
# it is interested in; naming none means all of them.
HANDSHAKE_DISPATCHER = "handshake"
CONFIG_DISPATCHER = "config"
MAIN_DISPATCHER = "main"
DEAD_DISPATCHER = "dead"

LOG = logging.getLogger(__name__)

#: app name -> app instance.
APPS = {}


class EventBase:
    """Base of every event class."""


class EventRequestBase(EventBase):
    """A request awaiting a reply from another application."""

    def __init__(self):
        self.dst = None
        self.src = None
        self.sync = False
        self.reply_q = None


class EventReplyBase(EventBase):
    """A reply to an :class:`EventRequestBase`."""

    def __init__(self, dst):
        self.dst = dst


def _listify(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def set_ev_cls(ev_cls, dispatchers=None):
    """Declare a method an event handler.

    ``ev_cls`` is the event class (or list of them) to receive;
    ``dispatchers`` restricts delivery to those negotiation phases.
    """

    def _decorate(handler):
        callers = getattr(handler, "callers", None)
        if callers is None:
            callers = handler.callers = {}
        for cls in _listify(ev_cls):
            callers[cls] = _listify(dispatchers)
        return handler

    return _decorate


# set_ev_handler differs from set_ev_cls only in os-ken's service-brick
# bookkeeping, which c65of does not have; the two are the same decorator here.
set_ev_handler = set_ev_cls


class OFApp:
    """An application: a set of event handlers and the thread that runs them."""

    #: OpenFlow versions this application speaks.
    OFP_VERSIONS = None
    #: ``{name: class}`` of applications this one needs, passed in as kwargs.
    _CONTEXTS = {}
    #: Event classes this application sends.
    _EVENTS = []

    def __init__(self, *_args, **_kwargs):
        self.name = type(self).__name__
        self.logger = logging.getLogger(self.name)
        self.threads = []
        self.events = queue.Queue()
        self.is_active = True
        self.main_thread = None
        self._handlers = {}
        self._stop = object()
        for _, method in inspect.getmembers(self, inspect.ismethod):
            for ev_cls in getattr(method, "callers", {}):
                self.register_handler(ev_cls, method)

    def register_handler(self, ev_cls, handler):
        """Add a handler for ``ev_cls``."""
        self._handlers.setdefault(ev_cls, []).append(handler)

    def unregister_handler(self, ev_cls, handler):
        """Remove a handler for ``ev_cls``."""
        handlers = self._handlers.get(ev_cls, [])
        if handler in handlers:
            handlers.remove(handler)

    def handles(self, ev_cls):
        """True if this application has a handler for ``ev_cls``."""
        return bool(self._handlers.get(ev_cls))

    def get_handlers(self, ev, state=None):
        """Handlers for ``ev`` that are interested in phase ``state``."""
        return [
            handler
            for handler in self._handlers.get(type(ev), [])
            for dispatchers in [handler.callers[type(ev)]]
            if not dispatchers or state is None or state in dispatchers
        ]

    def start(self):
        """Start the dispatch thread."""
        self.is_active = True
        self.main_thread = hub.spawn(self._event_loop)
        self.threads.append(self.main_thread)

    def stop(self):
        """Ask the dispatch thread to drain and exit, and wait for it."""
        if self.main_thread is None:
            return
        self.is_active = False
        self.events.put((self._stop, None))
        hub.joinall([self.main_thread])
        self.main_thread = None

    def _event_loop(self):
        while self.is_active or not self.events.empty():
            ev, state = self.events.get()
            if ev is self._stop:
                continue
            for handler in self.get_handlers(ev, state):
                try:
                    handler(ev)
                except Exception:  # pylint: disable=broad-except
                    self.logger.exception("%s raised handling %s", handler, ev)

    def send_event(self, name, ev, state=None):
        """Deliver ``ev`` to the application called ``name``."""
        app = APPS.get(name)
        if app is not None:
            app.events.put((ev, state))

    def send_event_to_observers(self, ev, state=None):
        """Deliver ``ev`` to every application that handles its class."""
        for app in APPS.values():
            if app.handles(type(ev)):
                app.events.put((ev, state))

    def close(self):
        """Release resources. An override point."""


class AppManager:
    """Loads, wires and runs the applications named on the command line."""

    _instance = None

    def __init__(self):
        self.applications_cls = {}
        self.applications = {}
        self.contexts_cls = {}
        self.contexts = {}

    @classmethod
    def get_instance(cls):
        """The process-wide application manager."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def run_apps(cls, app_lists):
        """Load, instantiate and run the named applications until stopped."""
        manager = cls.get_instance()
        manager.load_apps(app_lists)
        contexts = manager.create_contexts()
        services = manager.instantiate_apps(**contexts)
        try:
            hub.joinall(services)
        except KeyboardInterrupt:
            LOG.debug("keyboard interrupt received, shutting down")
        finally:
            manager.close()

    def load_app(self, name):
        """Return the single :class:`OFApp` subclass defined by module ``name``."""
        module = importlib.import_module(name)
        for _, value in inspect.getmembers(module, inspect.isclass):
            if issubclass(value, OFApp) and value is not OFApp:
                if value.__module__ == name:
                    return value
        return None

    def load_apps(self, app_lists):
        """Import each named module and record the application it defines."""
        for name in app_lists:
            cls = self.load_app(name)
            if cls is None:
                raise ImportError("%s defines no OFApp subclass" % name)
            self.applications_cls[name] = cls
            # _CONTEXTS is the declaration name applications already use.
            for (
                key,
                context_cls,
            ) in cls._CONTEXTS.items():  # pylint: disable=protected-access
                self.contexts_cls[key] = context_cls

    def create_contexts(self):
        """Instantiate the context applications every loaded app depends on."""
        for key, cls in self.contexts_cls.items():
            context = cls()
            self.contexts[key] = context
            if isinstance(context, OFApp):
                APPS[context.name] = context
                self.applications[context.name] = context
        return dict(self.contexts)

    def instantiate_apps(self, **kwargs):
        """Instantiate and start every loaded application."""
        for cls in self.applications_cls.values():
            app = cls(**kwargs)
            APPS[app.name] = app
            self.applications[app.name] = app
        services = []
        for app in self.applications.values():
            app.start()
            if app.main_thread is not None:
                services.append(app.main_thread)
        return services

    def close(self):
        """Stop every application and forget it."""
        for app in list(self.applications.values()):
            app.stop()
            with contextlib.suppress(Exception):
                app.close()
        self.applications.clear()
        self.contexts.clear()
        APPS.clear()

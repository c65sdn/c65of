"""Declarative struct codec shared by the OpenFlow and packet layers.

OpenFlow and the ethernet/IP packet formats are C structs. Rather than hand
write ``__init__``/``parser``/``serialize`` per class, a class declares its
wire layout and this module compiles it:

    class OFPActionOutput(OFPAction):
        _TYPE_ID = ofp.OFPAT_OUTPUT
        _FMT = "IH6x"
        _FIELDS = "port max_len"
        _DEFAULTS = {"max_len": 0}

``__init_subclass__`` compiles a ``struct.Struct``, generates an ``__init__``
with the declared signature, and records the attribute order used for
``to_jsondict``/``from_jsondict``/``__str__``.

The JSON dict form is wire-compatible with os-ken's ``StringifyMixin``:
``{"ClassName": {attr: value}}``, bytes base64 encoded, nested objects
recursed. Class dicts are recognised by an exact registry lookup rather than
os-ken's name-prefix heuristic.
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

# The codec introspects the layout configuration of the classes it serves.
# pylint: disable=protected-access

import base64
import builtins
import struct

RESERVED = frozenset(dir(builtins))

# name -> class, for resolving {"ClassName": {...}} in JSON dicts.
REGISTRY = {}

#: Marker for a constructor parameter with no default.
REQUIRED = object()


def mangle(name):
    """Constructor parameter name for an attribute name.

    Attributes keep the wire name (``msg.type``); the constructor parameter
    that sets one clashing with a builtin gets a trailing underscore
    (``OFPErrorMsg(type_=...)``), the convention callers already use.
    """
    return name + "_" if name in RESERVED else name


class _AsciiType:
    """US-ASCII text, carried as text rather than base64."""

    @staticmethod
    def encode(value):
        """Text form of ``value``."""
        return value if isinstance(value, str) else str(value, "ascii")

    @staticmethod
    def decode(value):
        """``value`` unchanged."""
        return value


class _Utf8Type:
    """UTF-8 text."""

    encode = staticmethod(lambda value: str(value, "utf-8"))
    decode = staticmethod(lambda value: value.encode("utf-8"))


class _AsciiListType:
    """List of US-ASCII text."""

    encode = staticmethod(lambda values: [_AsciiType.encode(v) for v in values])
    decode = staticmethod(list)


TYPES = {"ascii": _AsciiType, "utf-8": _Utf8Type, "asciilist": _AsciiListType}


def _gen_init(cls, params, hook):
    """Compile an ``__init__`` with the declared signature.

    ``params`` is an ordered sequence of ``(attr_name, default)``; a default of
    :data:`REQUIRED` makes the parameter positional-or-keyword with no default.
    """
    sig, body, namespace = [], [], {}
    for i, (name, default) in enumerate(params):
        param = mangle(name)
        if default is REQUIRED:
            sig.append(param)
        else:
            namespace["_d%d" % i] = default
            sig.append("%s=_d%d" % (param, i))
        body.append("    self.%s = %s" % (name, param))
    if hook is not None:
        namespace["_hook"] = hook
        body.append("    _hook(self)")
    src = "def __init__(self, %s):\n%s\n" % (
        ", ".join(sig),
        "\n".join(body) or "    pass",
    )
    exec(src, namespace)  # pylint: disable=exec-used
    init = namespace["__init__"]
    init.__qualname__ = "%s.__init__" % cls.__name__
    return init


class Codec:
    """Base for anything with a declarative wire layout and a JSON dict form.

    Class attributes a subclass may declare:

    ``_FMT``       struct format for the fixed part, big-endian implied.
    ``_FIELDS``    space separated names for the values in ``_FMT``, in order.
    ``_DEFAULTS``  ``{name: default}`` overriding the default of ``0``.
    ``_EXTRA``     space separated attributes not in ``_FMT`` (default None).
    ``_LEAD``      space separated leading parameters with no default.
    ``_TYPE``      ``{'ascii': (...), 'utf-8': (...)}`` JSON coercions.
    ``_ABSTRACT``  set True to skip ``__init__`` generation.
    """

    _FMT = ""
    _FIELDS = ""
    _EXTRA = ""
    _LEAD = ""
    _DEFAULTS = {}
    _TYPE = {}
    _ABSTRACT = False
    # Pass constructor extras (a datapath) down into nested from_jsondict.
    _PASS_ARGS = False

    # Compiled at class creation.
    _STRUCT = None
    _SIZE = 0
    _NAMES = ()
    _ATTRS = ()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        existing = REGISTRY.get(cls.__name__)
        if existing is not None and existing is not cls:
            raise TypeError("duplicate codec class name %r" % cls.__name__)
        REGISTRY[cls.__name__] = cls
        own = cls.__dict__
        if "_FMT" in own or "_FIELDS" in own:
            cls._STRUCT = struct.Struct("!" + cls._FMT)
            cls._SIZE = cls._STRUCT.size
            cls._NAMES = tuple(cls._FIELDS.split())
            if len(cls._NAMES) != len(cls._STRUCT.unpack(bytes(cls._SIZE))):
                raise TypeError(
                    "%s: _FIELDS has %d names for format %r"
                    % (cls.__name__, len(cls._NAMES), cls._FMT)
                )
        extra = tuple(cls._EXTRA.split())
        cls._ATTRS = cls._NAMES + extra
        if cls._ABSTRACT or "__init__" in own:
            return
        params = [(n, REQUIRED) for n in cls._LEAD.split()]
        params += [(n, cls._DEFAULTS.get(n, 0)) for n in cls._NAMES]
        params += [(n, cls._DEFAULTS.get(n, None)) for n in extra]
        if params:
            cls.__init__ = _gen_init(cls, params, own.get("_init_hook"))

    # -- fixed part ------------------------------------------------------

    def pack_fixed(self):
        """Pack the ``_FMT`` fields of this object."""
        cls = type(self)
        return cls._STRUCT.pack(*[getattr(self, n) for n in cls._NAMES])

    @classmethod
    def unpack_fixed(cls, buf, offset=0):
        """Return ``{attr: value}`` for the ``_FMT`` fields at ``offset``."""
        return dict(zip(cls._NAMES, cls._STRUCT.unpack_from(buf, offset)))

    # -- JSON dict form --------------------------------------------------

    def iter_attrs(self):
        """Yield ``(name, value)`` pairs. An override point."""
        for name in self._ATTRS:
            yield name, getattr(self, name)

    def __str__(self):
        return "%s(%s)" % (
            type(self).__name__,
            ",".join("%s=%s" % (k, repr(v)) for k, v in self.iter_attrs()),
        )

    __repr__ = __str__

    @classmethod
    def _coercion(cls, name):
        for kind, names in cls._TYPE.items():
            if name in names:
                return TYPES[kind]
        return None

    @staticmethod
    def _is_class_dict(value):
        return len(value) == 1 and next(iter(value)) in REGISTRY

    @classmethod
    def _encode(cls, value, encode_string):
        if isinstance(value, (bytes, str)):
            if isinstance(value, str):
                value = value.encode("utf-8")
            return encode_string(value).decode("ascii")
        if isinstance(value, (list, tuple)):
            return [cls._encode(v, encode_string) for v in value]
        if isinstance(value, dict):
            return {str(k): cls._encode(v, encode_string) for k, v in value.items()}
        to_jsondict = getattr(value, "to_jsondict", None)
        return to_jsondict() if to_jsondict is not None else value

    def to_jsondict(self, encode_string=base64.b64encode):
        """Return ``{"ClassName": {attr: json_value}}``."""
        cls = type(self)
        out = {}
        for name, value in self.iter_attrs():
            coercion = cls._coercion(name)
            out[name] = (
                coercion.encode(value)
                if coercion is not None
                else cls._encode(value, encode_string)
            )
        return {cls.__name__: out}

    @classmethod
    def _decode(cls, value, decode_string, extra):
        if isinstance(value, (bytes, str)):
            return decode_string(value)
        if isinstance(value, list):
            return [cls._decode(v, decode_string, extra) for v in value]
        if isinstance(value, dict):
            if cls._is_class_dict(value):
                return cls.obj_from_jsondict(value, **extra)
            decoded = {
                k: cls._decode(v, decode_string, extra) for k, v in value.items()
            }
            try:
                return {int(k): v for k, v in decoded.items()}
            except (TypeError, ValueError):
                return decoded
        return value

    @classmethod
    def obj_from_jsondict(cls, jsondict, **extra):
        """Instantiate the class named by a single key ``{"Name": {...}}``."""
        ((name, params),) = jsondict.items()
        return REGISTRY[name].from_jsondict(params, **extra)

    @classmethod
    def from_jsondict(cls, params, decode_string=base64.b64decode, **extra):
        """Instantiate from the inner dict of the JSON dict form."""
        nested = extra if cls._PASS_ARGS else {}
        kwargs = {}
        for name, value in params.items():
            coercion = cls._coercion(name)
            kwargs[mangle(name)] = (
                coercion.decode(value)
                if coercion is not None
                else cls._decode(value, decode_string, nested)
            )
        kwargs.update(extra)
        return cls(**kwargs)


def msg_pack_into(fmt, buf, offset, *args):
    """``struct.pack_into`` that grows ``buf`` to fit."""
    needed = offset + struct.calcsize(fmt)
    if len(buf) < needed:
        buf += bytearray(needed - len(buf))
    struct.pack_into(fmt, buf, offset, *args)


class TLVRegistry:
    """Type-dispatched registry for a family of length-prefixed structures.

    Actions, instructions, multipart bodies, table feature properties and meter
    bands are all "u16 type, u16 len, body" families. One registry per family
    maps the type field to the class that parses the body.
    """

    __slots__ = ("name", "classes")

    def __init__(self, name):
        self.name = name
        self.classes = {}

    def register(self, cls):
        """Class decorator recording ``cls`` under its ``_TYPE_ID``."""
        type_id = cls._TYPE_ID
        if type_id in self.classes:
            raise TypeError(
                "%s: type %r already registered by %s"
                % (self.name, type_id, self.classes[type_id].__name__)
            )
        self.classes[type_id] = cls
        return cls

    def lookup(self, type_id):
        """Return the class for ``type_id``, or None."""
        return self.classes.get(type_id)

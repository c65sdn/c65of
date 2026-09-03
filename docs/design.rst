======
Design
======

Declarative wire layouts
========================

OpenFlow messages and packet headers are C structs. Rather than write
``__init__``, ``parser`` and ``serialize`` per class, a class declares its
layout and ``c65of.codec`` compiles it::

    class OFPActionOutput(OFPAction):
        _TYPE_ID = ofp.OFPAT_OUTPUT
        _FMT = "IH6x"
        _FIELDS = "port max_len"
        _DEFAULTS = {"max_len": ofp.OFPCML_MAX}

``__init_subclass__`` compiles a ``struct.Struct``, generates an ``__init__``
with that signature, and records the attribute order used by
``to_jsondict``, ``from_jsondict`` and ``__str__``. Only classes with a
variable length tail -- a match, a list of actions -- write any code, and then
only for the tail.

Attribute and parameter names
=============================

Attributes keep the wire name, so ``msg.type`` and ``action.len`` read
naturally. A constructor parameter that would shadow a builtin takes a
trailing underscore, so ``OFPErrorMsg(type_=...)``. This is the convention
callers already use.

JSON dict form
==============

``to_jsondict`` produces ``{"ClassName": {attr: value}}`` with bytes base64
encoded and nested objects recursed, matching os-ken so that REST and test
consumers need no changes. Where os-ken decides whether a dict denotes a class
by matching name prefixes, c65of looks the name up in a registry populated at
class creation.

Differential testing
====================

os-ken is a test dependency. Every encoding layer is checked against it: same
bytes out, same values back, same JSON dict. This is what makes the port
verifiable rather than a reimplementation to be eyeballed, and it is why the
layers were ported in dependency order with the tests written first.

Structure
=========

==========================  ==================================================
``c65of.codec``             Declarative struct codec, JSON dict form, TLV
                            registries.
``c65of.lib``               Address and type conversion.
``c65of.ofproto.consts``    OpenFlow 1.3 constants and struct formats.
``c65of.ofproto.oxm``       Match fields: wire encoding and user values.
``c65of.ofproto.parser``    OpenFlow 1.3 messages, actions, instructions.
``c65of.packet``            Ethernet, VLAN, ARP, IP, ICMP, LLDP, BPDU, LACP.
==========================  ==================================================

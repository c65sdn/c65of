===========================
Migrating faucet off os-ken
===========================

Import changes
==============

Mechanical, one line each.

============================================ ==========================================
os-ken                                       c65of
============================================ ==========================================
``os_ken.ofproto.ofproto_v1_3``              ``c65of.ofproto``
``os_ken.ofproto.ofproto_v1_3_parser``       ``c65of.ofproto.parser``
``os_ken.ofproto.ofproto_parser``            ``c65of.ofproto.parser``
``os_ken.ofproto.ether`` / ``inet``          ``c65of.ofproto.ether`` / ``inet``
``os_ken.lib.packet.*``                      ``c65of.packet.*``
``os_ken.lib.addrconv`` / ``mac``            ``c65of.lib.addrconv`` / ``mac``
``os_ken.lib.type_desc``                     ``c65of.lib.type_desc``
``os_ken.lib.ofctl_utils``                   ``c65of.ofctl``
``os_ken.lib.ofctl_v1_3``                    ``c65of.ofctl``
``os_ken.lib.hub``                           ``c65of.hub``
``os_ken.base.app_manager``                  ``c65of.app``
``os_ken.controller.handler``                ``c65of.app``
``os_ken.controller.event``                  ``c65of.app``
``os_ken.controller.ofp_event``              ``c65of.ofp_event``
============================================ ==========================================

Behaviour that is not identical
===============================

Each of these is deliberate, and each is pinned by a test.

**``icmpv6_pkt.type_`` becomes ``icmpv6_pkt.type``.** os-ken stores
``icmp.icmp.type`` but ``icmpv6.icmpv6.type_``. c65of is consistent: the
attribute is always the plain wire name, and only the constructor parameter
takes the underscore. Two live call sites change --
``faucet/valve_route.py`` and ``clib/valve_test_lib.py`` -- and a third,
``clib/valve_test_lib.py`` reading ``icmp_pkt.type_`` on an ICMPv4 packet,
is a latent ``AttributeError`` against os-ken today that the change fixes.

**No hub monkeypatch.** ``c65of.hub.spawn`` returns a daemon thread, so the
``HubThread.__init__`` patch in ``faucet/valve_ryuapp.py`` that stops the
interpreter hanging at exit can go, along with the ``HUB_TYPE`` check.

**No ``hub.patch``.** There is nothing to monkeypatch; drop the calls.

**No oslo.config.** ``faucet/__main__.py`` no longer needs the inlined
``osken-manager``: ``c65of.app.AppManager.run_apps`` takes the module names,
and the ``--ryu-*`` flags it translated become plain argparse arguments.

**``OFP_TCP_PORT`` is 6653.** os-ken's ``ofproto_v1_3`` ends with a stale
6633 that its own ``ofproto_common`` and controller contradict. The old value
is ``OFP_TCP_PORT_OLD``. Nothing in faucet reads either.

**Actions return their length from ``serialize``.** os-ken returns None and
expects the caller to read ``.len`` afterwards. Nothing in faucet reads
either.

**``mod_meter_entry`` returns the message.** os-ken only sends it, which is
why ``valve_of.meteradd`` builds a fake datapath whose ``send_msg`` records
the message. That stand-in can go.

**Protocols not ported.** TCP, UDP, SCTP, GRE, OSPF, IGMP, MPLS, PBB, LLC and
BPDU parsing have no consumer in faucet, so ``ipv4.parser`` and
``ipv6.parser`` return no next class for them and the payload stays raw
bytes. Matching on TCP and UDP ports is unaffected: that is OXM, not packet
parsing.

**Two os-ken bugs are not reproduced.** ``nd_option_mtu`` has a length, so a
router advertisement carrying an MTU option parses. The three LLDP TLVs whose
``from_jsondict`` raises ``KeyError`` still do, because that one is visible in
the JSON form and reproducing it was the safer choice.

Order of work
=============

The wire layers are drop-in and can land first, in one commit that changes
only imports. The framework layers change shape and want their own commit:
``valve_ryuapp.py`` loses the hub monkeypatch, ``__main__.py`` loses the
inlined ``osken-manager``, and ``requirements.txt`` loses ``os_ken`` along
with the oslo.config, eventlet and netaddr it brought with it.

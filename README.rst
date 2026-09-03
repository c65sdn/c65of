=====
c65of
=====

OpenFlow 1.3 protocol, packet parsing and controller library for python, with
no runtime dependencies.

c65of replaces `os-ken <https://opendev.org/openstack/os-ken>`_ for
`c65faucet <https://github.com/c65sdn/faucet>`_. It covers the OpenFlow 1.3
wire protocol, the ethernet/IP packet formats an OpenFlow controller needs to
parse, and the controller channel and application framework -- and nothing
else, so it does not shed surface underneath its consumers.

Install
=======

.. code:: bash

    pip3 install c65of

Use
===

.. code:: python

    from c65of import ofproto as ofp
    from c65of.ofproto import parser

    match = parser.OFPMatch(eth_type=0x800, ipv4_dst="10.0.0.0/8")
    mod = parser.OFPFlowMod(datapath, table_id=1, priority=100, match=match)

Design
======

Wire formats are declared, not hand written: a class states its struct layout
and the codec compiles the constructor, the packer and the JSON dict form. See
`docs/design.rst <docs/design.rst>`_.

Encoding is verified against os-ken byte for byte by the differential test
suite; os-ken is a test dependency only.

Development
===========

.. code:: bash

    pip3 install -r codecheck-requirements.txt
    ./run_tests.sh

Or in docker:

.. code:: bash

    docker build -f Dockerfile.tests -t c65of-tests . && docker run c65of-tests

Licence
=======

Apache 2.0. Portions are ported from os-ken, also Apache 2.0.

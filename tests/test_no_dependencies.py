"""Guard: importing c65of must pull in nothing but the standard library."""

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

import subprocess
import sys
import sysconfig

# Every module a consumer would import.
MODULES = (
    "c65of.app",
    "c65of.codec",
    "c65of.hub",
    "c65of.lib.addrconv",
    "c65of.lib.mac",
    "c65of.lib.type_desc",
    "c65of.ofctl",
    "c65of.ofp_event",
    "c65of.ofproto",
    "c65of.ofproto.parser",
    "c65of.packet.arp",
    "c65of.packet.ethernet",
    "c65of.packet.icmp",
    "c65of.packet.icmpv6",
    "c65of.packet.ipv4",
    "c65of.packet.ipv6",
    "c65of.packet.lldp",
    "c65of.packet.packet",
    "c65of.packet.slow",
    "c65of.packet.vlan",
)

PROBE = """
import sys, sysconfig
import %s
stdlib = sysconfig.get_paths()["stdlib"]
foreign = sorted({
    name.split(".")[0]
    for name, module in sys.modules.items()
    if not name.startswith(("c65of", "_", "encodings"))
    and getattr(module, "__file__", None)
    and not module.__file__.startswith(stdlib)
})
assert not foreign, foreign
""" % ", ".join(MODULES)


def test_import_graph_is_stdlib_only():
    """os-ken is a test dependency; nothing third party may reach the runtime.

    In particular not eventlet, oslo.config or netaddr, which os-ken brought
    with it and which faucet never wanted on their own merits.
    """
    result = subprocess.run(
        [sys.executable, "-c", PROBE], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, "third party imports leaked in:\n%s" % result.stderr


def test_no_module_imports_os_ken():
    """The library must never import its own test oracle."""
    result = subprocess.run(
        ["git", "grep", "-l", "os_ken", "--", "c65of/"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert not result.stdout.strip(), "c65of imports os_ken in:\n%s" % result.stdout


def test_the_stdlib_path_is_what_the_probe_assumes():
    """The probe's stdlib check is meaningful in this environment."""
    assert sysconfig.get_paths()["stdlib"]

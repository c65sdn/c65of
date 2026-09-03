"""Bridge Protocol Data Unit (BPDU, IEEE 802.1D) protocol constants.

The BPDU packet classes are deliberately not ported: a BPDU arrives inside an
LLC header, which c65of does not implement, so a BPDU is never parsed here.
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

# BPDU destination.
BRIDGE_GROUP_ADDRESS = "01:80:c2:00:00:00"

PROTOCOL_IDENTIFIER = 0
PROTOCOLVERSION_ID_BPDU = 0
PROTOCOLVERSION_ID_RSTBPDU = 2
TYPE_CONFIG_BPDU = 0
TYPE_TOPOLOGY_CHANGE_BPDU = 128
TYPE_RSTBPDU = 2
DEFAULT_BRIDGE_PRIORITY = 32768
DEFAULT_PORT_PRIORITY = 128
PORT_PATH_COST_100KB = 200000000
PORT_PATH_COST_1MB = 20000000
PORT_PATH_COST_10MB = 2000000
PORT_PATH_COST_100MB = 200000
PORT_PATH_COST_1GB = 20000
PORT_PATH_COST_10GB = 2000
PORT_PATH_COST_100GB = 200
PORT_PATH_COST_1TB = 20
PORT_PATH_COST_10TB = 2
DEFAULT_MAX_AGE = 20
DEFAULT_HELLO_TIME = 2
DEFAULT_FORWARD_DELAY = 15
VERSION_1_LENGTH = 0

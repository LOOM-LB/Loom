#!/bin/bash

# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SWITCH_PATH=/path/to/behavioral-model/targets/simple_switch/simple_switch

CLI_PATH=/path/to/behavioral-model/targets/simple_switch/sswitch_CLI

set -m
p4c --std p4-14 p4src/LBswitch.p4
# This gives libtool the opportunity to "warm-up"
sudo $SWITCH_PATH >/dev/null 2>&1

sudo $SWITCH_PATH LBswitch.json \
    -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10\
    --nanolog ipc:///tmp/bm-0-log.ipc \
     &
sleep 8
$CLI_PATH LBswitch.json < commands.txt
echo "READY!!!"

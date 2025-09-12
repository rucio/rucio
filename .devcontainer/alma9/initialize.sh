#!/bin/bash
# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

set -e


# Source common functions
source "$(dirname "${BASH_SOURCE[0]}")/common_functions.sh"

# Source config file if it exists in which RUCIO_DEV_PROFILES are specified, e.g. RUCIO_DEV_PROFILES="storage", RUCIO_DEV_PROFILES="storage,externalmetadata", RUCIO_DEV_PROFILES="storage,externalmetadata,iam"
echo -e "${CYAN}📋 Checking for profile configuration...${NC}"
if [ -f ".devcontainer/alma9/rucio_dev_profiles.cfg" ]; then
    echo -e "${GREEN} ✅ Found profile config file${NC}"
    source .devcontainer/alma9/rucio_dev_profiles.cfg
else
    echo -e "${YELLOW} ⚠️ No profile config file found, using defaults${NC}"
fi
PROFILES=${RUCIO_DEV_PROFILES:-"storage,externalmetadata"}
echo -e "${CYAN}Selected profiles: ${YELLOW}${PROFILES}${NC}"
echo ""

# Main initialization flow
print_header "Rucio External Services Initialization"

show_system_requirements
check_system_requirements
cleanup_existing_containers
start_external_services $PROFILES
show_system_status
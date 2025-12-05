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

# Main setup flow
print_header "Rucio Development Environment Setup"

install_docker_cli
install_python_dev_tools
install_nodejs_tools
install_rucio_dev
copy_rucio_certificates
check_docker_daemon
add_container_to_network "${HOSTNAME}" "dev_default"
show_external_services_info
show_system_status
show_ci_commands
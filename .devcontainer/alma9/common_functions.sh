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

# Common functions for Rucio development environment setup

# Color definitions
BLUE='\033[0;34m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Print a standardized header
print_header() {
    local title="$1"
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║$(printf "%62s" "$title")║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Check system requirements
check_system_requirements() {
    echo -e "${CYAN}📋 Checking System Requirements:${NC}"
    
    # Check available disk space (current directory)
    AVAILABLE_DISK_GB=$(df . | tail -1 | awk '{print int($4/1024/1024)}')
    echo -e "   Disk Space: ${AVAILABLE_DISK_GB}GB available in current directory"
    
    if [ "$AVAILABLE_DISK_GB" -lt 20 ]; then
        echo -e "${RED} ❌ Warning: Less than 20GB disk space available. Build may fail.${NC}"
        echo -e "${YELLOW}    Consider freeing up disk space before continuing.${NC}"
    else
        echo -e "${GREEN} ✅ Sufficient disk space available${NC}"
    fi
    
    # Check Docker daemon
    echo -e "   Docker: Checking daemon status..."
    if ! docker info > /dev/null 2>&1; then
        echo -e "${RED} ❌ Docker daemon not accessible. Please ensure Docker is running.${NC}"
        exit 1
    else
        echo -e "${GREEN} ✅ Docker daemon is running${NC}"
    fi
    echo ""
}

# Install Docker CLI for AlmaLinux
install_docker_cli() {
    echo -e "${BLUE}🐳 Installing Docker CLI and tools...${NC}"
    if ! command -v docker &> /dev/null 2>&1; then
        dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        dnf install -y docker-ce-cli docker-compose-plugin
        echo -e "${GREEN} ✅ Docker CLI installed${NC}"
    else
        echo -e "${GREEN} ✅ Docker CLI already available${NC}"
    fi
}

# Install Python development tools
install_python_dev_tools() {
    echo -e "${BLUE}🐍 Installing Python development tools...${NC}"
    pip install ruff flake8 flake8-annotations PyYAML pytest pytest-cov
    echo -e "${GREEN} ✅ Python tools installed${NC}"
}

# Install Node.js tools
install_nodejs_tools() {
    echo -e "${BLUE}📦 Installing Node.js tools...${NC}"
    if command -v npm &> /dev/null 2>&1; then
        npm install --global pyright
        echo -e "${GREEN} ✅ Node.js tools installed${NC}"
    else
        echo -e "${YELLOW} ⚠️ npm not found, skipping Node.js tools${NC}"
    fi
}

# Install Rucio in development mode
install_rucio_dev() {
    echo -e "${BLUE}📚 Installing Rucio in development mode...${NC}"
    pip install -e .
    echo -e "${GREEN} ✅ Rucio installed in development mode${NC}"
}

# Check Docker daemon with timeout
check_docker_daemon() {
    echo -e "${BLUE}🔍 Checking Docker daemon...${NC}"
    if timeout 30 bash -c 'until docker info > /dev/null 2>&1; do sleep 1; done'; then
        echo -e "${GREEN} ✅ Docker daemon is ready${NC}"
    else
        echo -e "${RED} ❌ Docker daemon failed to start within 30 seconds${NC}"
        exit 1
    fi
}

cleanup_existing_containers() {
    echo -e "${YELLOW}🔄 Cleaning up existing containers...${NC}"

    # Remove containers prefixed with 'dev-'
    echo -e "${YELLOW}🧹 Removing containers with prefix 'dev-'...${NC}"
    containers=$(docker ps -a --filter "name=^dev-" --format "{{.ID}}")
    if [ -n "$containers" ]; then
        docker rm -f $containers
        echo -e "${GREEN} ✅ Containers removed${NC}"
    else
        echo -e "${GREEN} ✅ No 'dev-' containers to remove${NC}"
    fi

    # Remove volumes prefixed with 'dev_'
    echo -e "${YELLOW}🧹 Removing volumes with prefix 'dev_'...${NC}"
    volumes=$(docker volume ls --filter "name=^dev_" --format "{{.Name}}")
    if [ -n "$volumes" ]; then
        docker volume rm $volumes
        echo -e "${GREEN} ✅ Volumes removed${NC}"
    else
        echo -e "${GREEN} ✅ No 'dev_' volumes to remove${NC}"
    fi

    # Remove network named 'dev_default' if exists
    echo -e "${YELLOW}🧹 Removing 'dev_default' network if exists...${NC}"
    if docker network ls --filter "name=^dev_default$" --format "{{.Name}}" | grep -q 'dev_default'; then
        docker network rm dev_default
        echo -e "${GREEN} ✅ Network 'dev_default' removed${NC}"
    else
        echo -e "${GREEN} ✅ Network 'dev_default' not found${NC}"
    fi

    echo ""
}

# Start external services
start_external_services() {    
    # Accept profiles as first argument, fallback to env var, then default
    local input_profiles="$1"
    PROFILES=${input_profiles:-${RUCIO_DEV_PROFILES:-"storage,externalmetadata"}}
    
    echo -e "${CYAN}Starting external services for Rucio development environment...${NC}"
    echo -e "${YELLOW}Selected profiles: ${PROFILES}${NC}"
    
    # Display what will be started based on profiles
    echo -e "${YELLOW}This will start:${NC}"
    if [[ "$PROFILES" == *"storage"* ]]; then
        echo "   • PostgreSQL database (ruciodb)"
        echo "   • InfluxDB for metrics"
        echo "   • Graphite for monitoring"
        echo "   • ActiveMQ message broker"
        echo "   • FTS transfer service + database"
        echo "   • XRootD storage endpoints (5x)"
        echo "   • MinIO S3 storage"
        echo "   • SSH/WebDAV storage"
    fi
    if [[ "$PROFILES" == *"externalmetadata"* ]]; then
        echo "   • MongoDB (with/without auth)"
        echo "   • PostgreSQL metadata database"
        echo "   • Elasticsearch metadata service"
    fi
    if [[ "$PROFILES" == *"monitoring"* ]]; then
        echo "   • Logstash, Kibana, Grafana stack"
    fi
    if [[ "$PROFILES" == *"iam"* ]]; then
        echo "   • Keycloak and IndigoIAM authentication"
    fi
    if [[ "$PROFILES" == *"client"* ]]; then
        echo "   • Rucio client container"
    fi
    echo ""
    
    echo -e "${BLUE}Starting Docker Compose services...${NC}"
    
    # Convert comma-separated profiles to --profile flags
    PROFILE_FLAGS=$(echo "$PROFILES" | sed 's/,/ --profile /g' | sed 's/^/--profile /')
    
    docker compose -f etc/docker/dev/docker-compose.yml -f etc/docker/dev/docker-compose.ports.yml $PROFILE_FLAGS up -d --build
    
    echo -e "${GREEN}✅ External services started successfully${NC}"
    echo -e "${CYAN}Services are now running and will be available to the dev container${NC}"
    echo ""
}

# Display external services notification
show_external_services_info() {
    echo -e "${CYAN}📋 External Services:${NC}"
    echo -e "${GREEN} ✅ External services managed by initialize script on host${NC}"
    echo -e "${GREEN}    All 'dev-' prefixed containers contain persistent data${NC}"
    echo ""
}

# Display CI-aligned development commands
show_ci_commands() {
    echo -e "${YELLOW}CI-Aligned Commands (match with workflows):${NC}"
    echo ""
    echo -e "${CYAN}Linting & Formatting:${NC}"
    echo "   ruff check --output-format=github .     # python_ruff job"
    echo "   python3 tools/add_header --dry-run --disable-progress-bar  # add_header job"
    echo ""
    echo -e "${CYAN}Type Checking & Annotations:${NC}"
    echo "   source tools/count_missing_type_annotations_utils.sh && create_missing_python_type_annotations_report report.txt"
    echo "   tools/run_pyright.sh generate report.json  # python_pyright job"
    echo "   tools/run_pyright.sh compare --Werror report1.json report2.json"
    echo ""
    echo -e "${CYAN}Unit Testing:${NC}"
    echo "   pytest tests/rucio --cov=lib/rucio      # Unit tests job (Python 3.9-3.12)"
    echo ""
    echo -e "${CYAN}Integration Tests (requires external services):${NC}"
    echo "   docker exec -t dev-rucio-1 tools/run_tests.sh -ir"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_rucio_server.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_upload.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_conveyor.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_tpc.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_did_meta_plugins.py::TestDidMetaMongo"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_impl_upload_download.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_rse_protocol_gfal2_impl.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_rse_protocol_xrootd.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_rse_protocol_ssh.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_rse_protocol_rsync.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_rse_protocol_rclone.py"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_reaper.py::test_deletion_with_tokens"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_download.py::test_download_from_archive_on_xrd"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_did_meta_plugins.py::TestDidMetaExternalPostgresJSON"
    echo "   docker exec -t dev-rucio-1 tools/pytest.sh -v --tb=short tests/test_did_meta_plugins.py::TestDidMetaElastic"
    echo ""
    echo -e "${CYAN}Development Helpers:${NC}"
    echo "   docker ps                               # View dev- prefixed containers"
    echo "   docker compose -f etc/docker/dev/docker-compose.yml --profile storage logs"
    echo "   docker exec -t dev-rucio-1 cat /var/log/rucio/httpd_error_log  # Check server logs"
    echo ""
}

# Display system requirements info
show_system_requirements() {
    echo -e "${CYAN}📋 System Requirements:${NC}"
    echo -e "${YELLOW} • Disk Space: 20-25 GB free (30+ GB for full testing)${NC}"
    echo -e "${YELLOW} • Memory: 8+ GB RAM (16+ GB recommended for all services)${NC}"
    echo -e "${YELLOW} • Docker: daemon running with sufficient resources${NC}"
    echo ""
}

# Display system status and resource usage
show_system_status() {
    echo -e "${CYAN}📊 System Status & Resource Usage:${NC}"
    echo ""
    echo -e "${YELLOW}Docker System Usage:${NC}"
    docker system df
    echo ""
    echo -e "${YELLOW}Container Resource Usage:${NC}"
    docker stats --no-stream
    echo ""
    echo -e "${YELLOW}Failed/Exited Containers:${NC}"
    FAILED_CONTAINERS=$(docker ps -a --filter "status=exited" --format "table {{.Names}}\t{{.Status}}" | grep -v "NAMES" || true)
    if [ -n "$FAILED_CONTAINERS" ]; then
        echo "$FAILED_CONTAINERS"
        echo ""
        echo -e "${RED}⚠️  Some containers have exited. Check logs with:${NC}"
        echo "   docker logs <container_name>"
    else
        echo -e "${GREEN}✅ All containers running successfully${NC}"
    fi
    echo ""
}
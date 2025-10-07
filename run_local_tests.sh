#!/bin/bash

# Script to run GitHub Action workflow locally
# Replicates .github/workflows/simple-autotest.yml

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values matching the workflow
DIST="alma9"
PYTHON_VERSION="3.9"
RDBMS="postgres14"
IMAGE_TAG=""
COMPOSE_PROJECT=""
CLEANUP=true
BUILD_ONLY=false

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Run Rucio tests locally, replicating the GitHub Action workflow.

OPTIONS:
    -p, --python VERSION     Python version (3.9 or 3.10, default: 3.9)
    -d, --db DATABASE       Database to use (postgres14 or sqlite, default: postgres14)
    -t, --tag TAG           Custom image tag (default: auto-generated)
    -n, --no-cleanup        Don't cleanup containers after tests
    -b, --build-only        Only build the image, don't run tests
    -h, --help              Show this help message

EXAMPLES:
    # Run with default settings (Python 3.9, PostgreSQL 14)
    $0

    # Run with Python 3.10 and SQLite
    $0 --python 3.10 --db sqlite

    # Build image only with custom tag
    $0 --build-only --tag my-test-image:latest

    # Run tests without cleanup (for debugging)
    $0 --no-cleanup

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--python)
            PYTHON_VERSION="$2"
            shift 2
            ;;
        -d|--db)
            RDBMS="$2"
            shift 2
            ;;
        -t|--tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        -n|--no-cleanup)
            CLEANUP=false
            shift
            ;;
        -b|--build-only)
            BUILD_ONLY=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate Python version
if [[ "$PYTHON_VERSION" != "3.9" && "$PYTHON_VERSION" != "3.10" ]]; then
    print_error "Invalid Python version: $PYTHON_VERSION. Must be 3.9 or 3.10"
    exit 1
fi

# Validate database
if [[ "$RDBMS" != "postgres14" && "$RDBMS" != "sqlite" ]]; then
    print_error "Invalid database: $RDBMS. Must be postgres14 or sqlite"
    exit 1
fi

# Set environment variables
export COMPOSE_PROJECT="rucio-test-${DIST}"
export PROFILE="${RDBMS}"
export RUCIO_HOME="/opt/rucio"
export RDBMS="${RDBMS}"

# Generate image tag if not provided
if [ -z "$IMAGE_TAG" ]; then
    # Generate a simple hash for requirements files
    HASH=$(find . -name "requirements*.txt" -exec cat {} \; | sha256sum | cut -c1-8)
    IMAGE_TAG="rucio-test:${DIST}-py${PYTHON_VERSION}-${HASH}"
fi

export RUCIO_TEST_IMAGE="${IMAGE_TAG}"

print_info "Configuration:"
print_info "  Distribution: ${DIST}"
print_info "  Python version: ${PYTHON_VERSION}"
print_info "  Database: ${RDBMS}"
print_info "  Image tag: ${IMAGE_TAG}"
print_info "  Compose project: ${COMPOSE_PROJECT}"

# Cleanup function
cleanup() {
    if [ "$CLEANUP" = true ]; then
        print_info "Cleaning up Docker containers..."
        docker compose -p "${COMPOSE_PROJECT}" \
            --file etc/docker/dev/docker-compose.yml \
            --file etc/docker/dev/docker-compose.test.override.yml \
            --profile "${PROFILE}" \
            down -t 30 || true
        print_success "Cleanup completed"
    else
        print_warning "Skipping cleanup. Containers are still running."
        print_info "To manually cleanup, run:"
        echo "docker compose -p ${COMPOSE_PROJECT} --profile ${PROFILE} down"
    fi
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Step 1: Build Docker image
print_info "Building Docker image..."
print_info "This may take several minutes on first run..."

docker build \
    --file etc/docker/test/alma9.Dockerfile \
    --build-arg PYTHON="${PYTHON_VERSION}" \
    --tag "${IMAGE_TAG}" \
    .

if [ $? -eq 0 ]; then
    print_success "Docker image built successfully: ${IMAGE_TAG}"
else
    print_error "Failed to build Docker image"
    exit 1
fi

# If build-only flag is set, exit here
if [ "$BUILD_ONLY" = true ]; then
    print_success "Image built successfully. Exiting (--build-only flag set)"
    exit 0
fi

# Step 2: Start services with docker-compose
print_info "Starting services with docker-compose..."

docker compose -p "${COMPOSE_PROJECT}" \
    --file etc/docker/dev/docker-compose.yml \
    --file etc/docker/dev/docker-compose.test.override.yml \
    --profile "${PROFILE}" \
    up -d

if [ $? -ne 0 ]; then
    print_error "Failed to start docker-compose services"
    exit 1
fi

print_success "Services started"

# Step 3: Wait for services to be ready
print_info "Waiting for services to be ready..."

# Wait for rucio container to be ready
print_info "Waiting for rucio container..."
timeout 60 bash -c "
    while ! docker compose -p ${COMPOSE_PROJECT} --profile ${PROFILE} ps rucio --status running --format=table 2>/dev/null | grep -q 'dev-rucio-1'; do
        echo -n '.'
        sleep 2
    done
"

if [ $? -ne 0 ]; then
    print_error "Timeout waiting for rucio container"
    docker compose -p "${COMPOSE_PROJECT}" --profile "${PROFILE}" ps
    exit 1
fi

echo  # New line after dots
print_success "Rucio container is running"

# Wait for database and httpd inside the container
print_info "Waiting for database and httpd inside the container..."

docker compose -p "${COMPOSE_PROJECT}" --profile "${PROFILE}" exec rucio bash -c "
    function wait_for_httpd() {
        echo 'Waiting for httpd'
        curl --retry 15 --retry-all-errors --retry-delay 1 -k https://localhost/ping
    }

    function wait_for_database() {
        echo 'Waiting for database to be ready'
        while ! python3 -c 'from rucio.db.sqla.session import wait_for_database; wait_for_database()'
        do
            if (( SECONDS > 60 ))
            then
               echo 'Cannot access database'
               exit 1
            fi
            sleep 1
        done
    }
    wait_for_database
    wait_for_httpd
"

if [ $? -ne 0 ]; then
    print_error "Services failed to become ready"
    print_info "Container logs:"
    docker compose -p "${COMPOSE_PROJECT}" --profile "${PROFILE}" logs rucio --tail=50
    exit 1
fi

print_success "All services are ready"

# Step 4: Run Tests
print_info "Running tests..."
print_info "This may take several minutes..."

export PYTEST_DISABLE_PLUGIN_AUTOLOAD="True"

docker compose -p "${COMPOSE_PROJECT}" --profile "${PROFILE}" exec rucio bash -c "
    python -m pytest \
        --suite=remote_dbs \
        -r fExX \
        --log-level=DEBUG \
        -v --tb=short \
        -p xdist --numprocesses=3 \
        tests/test_utils
"

TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    print_success "All tests passed!"
else
    print_error "Tests failed with exit code: $TEST_EXIT_CODE"
    print_info "You can check the logs with:"
    echo "docker compose -p ${COMPOSE_PROJECT} --profile ${PROFILE} logs rucio"
fi

# Return the test exit code
exit $TEST_EXIT_CODE
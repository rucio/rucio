# Local Test Execution Script

This directory contains a script to run the Rucio CI tests locally, replicating the GitHub Actions workflow defined in `.github/workflows/simple-autotest.yml`.

## Overview

The `run_local_tests.sh` script allows you to run the same database tests that execute in CI on your local machine. This is useful for:
- Debugging test failures before pushing to GitHub
- Testing changes without waiting for CI
- Reproducing CI issues locally
- Developing with a consistent test environment

## Prerequisites

- Docker and Docker Compose installed
- Sufficient disk space for Docker images (~2-3GB)
- Linux/macOS environment (WSL2 for Windows)

## Quick Start

```bash
# Make the script executable (first time only)
chmod +x run_local_tests.sh

# Run tests with default configuration
./run_local_tests.sh
```

## Configuration Options

The script supports the same matrix of configurations as the GitHub Action:

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--python`, `-p` | 3.9, 3.10 | 3.9 | Python version to test with |
| `--db`, `-d` | postgres14, sqlite | postgres14 | Database backend to use |
| `--tag`, `-t` | string | auto-generated | Custom Docker image tag |
| `--no-cleanup`, `-n` | flag | false | Keep containers running after tests |
| `--build-only`, `-b` | flag | false | Only build the image, don't run tests |
| `--help`, `-h` | flag | - | Show help message |

## Usage Examples

### Basic Testing

```bash
# Run with Python 3.9 and PostgreSQL 14 (default)
./run_local_tests.sh

# Run with Python 3.10 and SQLite
./run_local_tests.sh --python 3.10 --db sqlite

# Test all combinations (like the CI matrix)
for py in 3.9 3.10; do
  for db in postgres14 sqlite; do
    echo "Testing Python $py with $db"
    ./run_local_tests.sh --python $py --db $db
  done
done
```

### Development Workflow

```bash
# Build the test image once
./run_local_tests.sh --build-only --tag rucio-test:dev

# Run tests with the pre-built image
./run_local_tests.sh --tag rucio-test:dev

# Keep containers running for debugging
./run_local_tests.sh --no-cleanup

# Manually inspect the test environment
docker compose -p rucio-test-alma9 --profile postgres14 exec rucio bash
```

### Debugging Failed Tests

```bash
# Run tests without cleanup to inspect the environment
./run_local_tests.sh --no-cleanup

# Check container logs
docker compose -p rucio-test-alma9 --profile postgres14 logs rucio

# Execute commands in the test container
docker compose -p rucio-test-alma9 --profile postgres14 exec rucio bash -c "
  cd /opt/rucio
  python -m pytest tests/test_specific.py -v
"

# When done, cleanup manually
docker compose -p rucio-test-alma9 --profile postgres14 down
```

## What the Script Does

The script replicates the GitHub Action workflow by:

1. **Building the Docker Image**
   - Uses `etc/docker/test/alma9.Dockerfile`
   - Configures the specified Python version
   - Installs all dependencies and test requirements

2. **Starting Services**
   - Launches docker-compose with the test configuration
   - Starts the selected database (PostgreSQL or SQLite)
   - Configures the Rucio service container

3. **Health Checks**
   - Waits for the Rucio container to be running
   - Verifies database connectivity
   - Ensures the HTTP service is responding

4. **Test Execution**
   - Runs pytest with the same parameters as CI
   - Uses 3 parallel processes for faster execution
   - Captures detailed output and logs

5. **Cleanup**
   - Automatically stops and removes containers (unless `--no-cleanup`)
   - Preserves exit codes for scripting

## Environment Variables

The script sets the following environment variables (matching the CI):

- `COMPOSE_PROJECT`: Project name for docker-compose (default: `rucio-test-alma9`)
- `PROFILE`: Docker compose profile (postgres14 or sqlite)
- `RUCIO_HOME`: Rucio installation directory in container (`/opt/rucio`)
- `RDBMS`: Database backend identifier
- `RUCIO_TEST_IMAGE`: Docker image tag to use

## Troubleshooting

### Build Failures

If the Docker build fails:
```bash
# Clear Docker cache and rebuild
docker system prune -a
./run_local_tests.sh --build-only
```

### Container Startup Issues

If containers fail to start:
```bash
# Check for conflicting containers
docker ps -a | grep rucio-test

# Remove any existing test containers
docker compose -p rucio-test-alma9 down

# Check Docker compose configuration
docker compose --file etc/docker/dev/docker-compose.yml \
               --file etc/docker/dev/docker-compose.test.override.yml \
               config
```

### Test Failures

For test failures:
```bash
# Run with debug output and no cleanup
./run_local_tests.sh --no-cleanup

# Check detailed logs
docker compose -p rucio-test-alma9 --profile postgres14 logs --tail=100

# Run specific tests manually
docker compose -p rucio-test-alma9 --profile postgres14 exec rucio bash -c "
  python -m pytest tests/path/to/specific_test.py::TestClass::test_method -vvs
"
```

## Differences from CI

While the script closely replicates the CI environment, there are some differences:

1. **No GitHub Actions cache**: The local build doesn't use the GitHub Actions cache layer
2. **No container registry**: Images are stored locally, not pushed to ghcr.io
3. **Single job execution**: Tests run sequentially, not in parallel matrix jobs
4. **Local resource constraints**: Performance depends on your local machine

## Performance Tips

- **Reuse images**: Use `--tag` to avoid rebuilding unchanged images
- **Selective testing**: Modify the pytest command in the container for specific tests
- **Resource allocation**: Ensure Docker has sufficient CPU and memory allocated
- **SSD storage**: Use SSD for Docker storage for better performance

## Contributing

When modifying the test infrastructure:

1. Update both the GitHub Action (`.github/workflows/simple-autotest.yml`) and this script
2. Test changes locally first using this script
3. Verify the changes work in CI after pushing

## Related Files

- `.github/workflows/simple-autotest.yml` - GitHub Action workflow definition
- `etc/docker/test/alma9.Dockerfile` - Test container Dockerfile
- `etc/docker/dev/docker-compose.yml` - Base docker-compose configuration
- `etc/docker/dev/docker-compose.test.override.yml` - Test-specific overrides
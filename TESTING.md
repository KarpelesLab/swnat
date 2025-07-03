# Testing Guide for swnat

This document describes the test suite for the swnat library.

## Test Structure

The test suite is organized into several categories:

### Unit Tests

- **ip_test.go** - Tests for IPv4/IPv6 address parsing and string conversion
- **packet_test.go** - Tests for packet parsing and header manipulation
- **table_test.go** - Tests for NAT table core functionality

### Integration Tests

- **integration_test.go** - End-to-end tests simulating real NAT scenarios
- **example_test.go** - Example usage tests (existing)

### Benchmark Tests

- **benchmark_test.go** - Performance benchmarks for critical operations

## Running Tests

### Run all tests
```bash
make test
```

### Run tests with coverage
```bash
make test-coverage
```

### Run benchmarks
```bash
make benchmark
```

### Run short tests only
```bash
make test-short
```

## CI Configuration

The project includes GitHub Actions workflow (`.github/workflows/test.yml`) that:
- Runs tests on multiple Go versions (1.21, 1.22, 1.23)
- Performs linting with golangci-lint
- Tests on multiple platforms (Linux, macOS, Windows)
- Uploads coverage reports to codecov

## Test Coverage Areas

### Core Functionality
- IPv4/IPv6 address parsing and formatting
- Packet header parsing (IPv4, TCP, UDP, ICMP)
- NAT translation (outbound and inbound)
- Connection tracking and cleanup
- Namespace isolation and limits

### Advanced Features
- Port allocation and exhaustion handling
- Connection persistence
- Concurrent access and thread safety
- Redirection rules
- Drop rules
- Checksum calculation and validation

### Performance
- Packet parsing speed
- NAT translation throughput
- Concurrent connection handling
- Memory usage with large connection tables
- Cleanup performance

## Known Test Failures

Some tests may fail due to:
1. Checksum validation after NAT translation (implementation-specific)
2. ICMP packet handling differences
3. Race conditions in concurrent scenarios

These failures indicate areas where the implementation behavior differs from test expectations and should be reviewed based on the intended library behavior.

## Adding New Tests

When adding new functionality:
1. Add unit tests for individual functions
2. Add integration tests for end-to-end scenarios
3. Add benchmarks for performance-critical code
4. Update this documentation

## Test Data

Tests use predefined packet structures and IP addresses:
- Local network: 192.168.1.0/24
- External IPs: 8.8.8.8, 1.1.1.1, etc.
- NAT IP: 1.2.3.4 (configurable)
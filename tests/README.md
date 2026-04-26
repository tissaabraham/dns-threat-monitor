# DNS Threat Monitor - Test Suite

This directory contains unit tests and integration tests for the DNS Threat Monitor system.

## Running Tests

### Prerequisites
```bash
pip install pytest
```

### Run All Tests
```bash
python -m pytest tests/
```

### Run Specific Test File
```bash
python -m pytest tests/test_basic.py
```

### Run with Coverage
```bash
python -m pytest --cov=src --cov-report=html tests/
```

## Test Structure

- `test_basic.py` - Basic unit tests for core components
- `test_parser.py` - Tests for input parsing functionality
- `test_detection.py` - Tests for threat detection rules
- `test_database.py` - Tests for database operations
- `test_integration.py` - Full system integration tests

## Test Coverage Goals

- **Unit Tests**: 80%+ coverage of individual functions
- **Integration Tests**: End-to-end pipeline testing
- **Performance Tests**: System performance under load

## Writing Tests

### Test Naming Convention
- Test files: `test_*.py`
- Test classes: `Test*`
- Test methods: `test_*`

### Example Test Structure
```python
class TestComponentName:
    def test_specific_functionality(self):
        # Arrange
        # Act
        # Assert
```

## Continuous Integration

Tests are automatically run on:
- Code commits (GitHub Actions)
- Pull requests
- Manual execution

## Test Data

Test data files are located in `tests/data/`:
- Sample DNS logs
- Mock threat intelligence feeds
- Performance test datasets

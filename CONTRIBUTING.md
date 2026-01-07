# Contributing to Instanton

Thank you for your interest in contributing to Instanton! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Git

### Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/instanton.git
   cd instanton
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/macOS
   source .venv/bin/activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Verify your setup:
   ```bash
   pytest tests/ -v
   ruff check src/
   ```

## Development Workflow

### Branching Strategy

- `main` - Stable release branch
- `develop` - Development branch (default target for PRs)
- Feature branches should be named: `feature/description`
- Bug fix branches should be named: `fix/description`

### Making Changes

1. Create a new branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards.

3. Write or update tests for your changes.

4. Run the test suite:
   ```bash
   pytest tests/ -v
   ```

5. Run linting:
   ```bash
   ruff check src/
   ruff format src/
   ```

6. Commit your changes with a descriptive message:
   ```bash
   git commit -m "Add feature: description of changes"
   ```

### Pull Request Process

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Open a Pull Request against the `main` branch.

3. Fill out the PR template with:
   - Description of changes
   - Related issue numbers
   - Testing performed
   - Screenshots (if applicable)

4. Wait for review and address any feedback.

## Coding Standards

### Style Guidelines

- Use Python 3.11+ features (match statements, type unions with `|`)
- Type hints on all function signatures
- Use async/await for all I/O operations
- Follow PEP 8 guidelines (enforced by ruff)
- Maximum line length: 100 characters

### Import Order

1. Standard library imports
2. Third-party imports
3. Local imports

Example:
```python
import asyncio
from pathlib import Path

import aiohttp
from pydantic import BaseModel

from instanton.core.config import Config
```

### Documentation

- All public functions and classes need docstrings
- Use Google-style docstrings
- Include type hints in signatures, not docstrings

Example:
```python
async def forward(port: int, subdomain: str | None = None) -> Listener:
    """Create a tunnel to a local port.

    Args:
        port: The local port to tunnel.
        subdomain: Optional custom subdomain.

    Returns:
        A Listener object with the public URL.

    Raises:
        ConnectionError: If unable to connect to relay server.
    """
```

### Error Handling

- Use custom exception classes where appropriate
- Log errors with context using structlog
- Never swallow exceptions silently

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=instanton --cov-report=html

# Run specific test file
pytest tests/test_protocol.py -v

# Run tests matching pattern
pytest tests/ -v -k "test_websocket"
```

### Writing Tests

- Place tests in the `tests/` directory
- Name test files `test_*.py`
- Use pytest fixtures for setup/teardown
- Use pytest-asyncio for async tests
- Aim for high coverage of critical paths

Example:
```python
import pytest
from instanton.protocol.messages import TunnelRequest

@pytest.mark.asyncio
async def test_tunnel_request_serialization():
    request = TunnelRequest(subdomain="test", port=8000)
    data = request.to_bytes()
    restored = TunnelRequest.from_bytes(data)
    assert restored.subdomain == "test"
```

## Reporting Issues

### Bug Reports

Include:
- Python version and OS
- Steps to reproduce
- Expected vs actual behavior
- Error messages and stack traces
- Minimal reproducible example

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternative solutions considered

## Getting Help

- Open a [GitHub Discussion](https://github.com/DrRuin/instanton/discussions) for questions
- Check existing issues before creating new ones
- Join our community chat (if available)

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to Instanton!

# Contributing to APTtrail

Thank you for your interest in contributing!

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/trilwu/apttrail.git
   cd apttrail
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # on Windows: venv\Scripts\activate
   ```

3. **Install development dependencies:**
   ```bash
   pip install -r requirements-dev.txt
   pip install -e .
   ```

4. **Install pre-commit hooks:**
   ```bash
   pre-commit install
   ```

## Coding Standards

- We use **Ruff** for linting and formatting.
- We use **MyPy** for static type checking.
- All public functions must have type hints and docstrings.

Run checks manually:
```bash
ruff check src/ tests/
mypy src/apttrail/
```

## Testing

We use **pytest**. All new features must have tests.

Run tests:
```bash
pytest
```

## Adding a New Exporter

1. Create a new file in `src/apttrail/exporters/`.
2. Inherit from `BaseExporter`.
3. Implement the `export()` method.
4. Add to `src/apttrail/exporters/__init__.py`.
5. Add CLI flag in `src/apttrail/cli.py`.
6. Add unit test in `tests/test_exporters.py`.

## Pull Request Process

1. Fork the repo and create your branch from `main`.
2. Ensure tests pass and code is linted.
3. Submit PR with description of changes.

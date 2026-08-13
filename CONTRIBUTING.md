# Contributing to PcapHunt

Thank you for your interest in contributing to PcapHunt!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/bel3ota/PcapHunt.git
   cd PcapHunt
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install in editable mode with development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Verify installation:
   ```bash
   pcaphunt --version
   pcaphunt --help
   python -m pcaphunt --version
   ```

## Running Tests

Run the full test suite:

```bash
python -m pytest tests/ -v
```

Run a specific test file:

```bash
python -m pytest tests/test_integration.py -v
```

## Building and Validating

Build the distribution:

```bash
rm -rf dist build *.egg-info
python -m build
```

Validate the distribution:

```bash
python -m twine check dist/*
```

Test the installed wheel in a clean environment:

```bash
python -m venv /tmp/clean_venv
/tmp/clean_venv/bin/pip install dist/*.whl
/tmp/clean_venv/bin/pcaphunt --version
/tmp/clean_venv/bin/pcaphunt --help
```

## Code Style

- Follow PEP 8
- Use type hints where practical
- Keep functions focused and modular
- Add docstrings to public functions and classes
- Maintain backwards compatibility when possible

## Adding a Detector

To add a new data detector:

1. Create a new file in `pcaphunt/detectors/`
2. Inherit from `BaseDetector`
3. Implement the `name` property and `detect()` method
4. Register the detector in `pcaphunt/engine.py` (`DETECTOR_MAP`)
5. Add the detector name to `DEFAULT_CONFIG["enabled_detectors"]` in `pcaphunt/config.py`
6. Add comprehensive tests in `tests/test_detectors.py`

## Adding a Protocol Extractor

To add a new protocol extractor:

1. Create a new file in `pcaphunt/protocols/`
2. Implement an extraction function that returns finding-like dicts
3. Register it in `pcaphunt/protocols/extractor.py`
4. Add tests in `tests/test_protocols.py`

## Adding Custom Rules

Custom rules are defined in YAML files. See `examples/rules.yaml` for the schema.

## Adding Plugins

Plugins must subclass `PcapHuntPlugin` from `pcaphunt/plugins.py`.

See `examples/example_plugin.py` for a complete working example.

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes with clear, focused commits
3. Add or update tests for any changed functionality
4. Ensure all tests pass: `python -m pytest`
5. Ensure the package builds and validates: `python -m build && python -m twine check dist/*`
6. Update documentation (README, docstrings) if needed
7. Submit a pull request with a clear description

## Release Process

Releases are automated via GitHub Actions. To create a release:

1. Ensure all tests pass on `main`
2. Update the version in `pcaphunt/version.py` and `pyproject.toml`
3. Commit the version change
4. Create and push a Git tag:
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```
5. GitHub Actions will build, validate, and publish to PyPI using Trusted Publishing (OIDC)

## Questions?

Open a [GitHub issue](https://github.com/bel3ota/PcapHunt/issues) for questions or discussions.

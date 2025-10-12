.PHONY: help install test audit clean

# Default command when running 'make'
help:
	@echo "Available commands:"
	@echo "  test       - Runs the test suite."
	@echo "  audit      - Runs a security audit of all dependencies for known vulnerabilities."
	@echo "  clean      - Removes temporary files and build artifacts."

# Runs the test suite
test:
	@echo ">>> Running tests..."
	pytest

# Runs a security audit of all dependencies
audit:
	@echo ">>> Running security audit with pip-audit..."
	pip-audit

# Cleans up the project directory
clean:
	@echo ">>> Cleaning up..."
	rm -rf .pytest_cache .mypy_cache .coverage
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
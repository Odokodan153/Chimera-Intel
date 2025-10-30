# Contributing to Chimera Intel

We welcome contributions from the community! Please follow these guidelines to help us keep the project organized and maintainable.

## How to Contribute
1.  **Fork the repository** and create your branch from `main`.
2.  **Set up your development environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate
    pip install -e .[dev]
    ```
3.  **Make your changes**. Please add tests for any new features.
4.  **Run tests** to ensure everything is working correctly:
    ```bash
    pytest
    ```
5.  **Submit a pull request** with a clear description of your changes.

## Coding Style
Please follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for Python code. We use `black` for code formatting and `flake8` for linting.
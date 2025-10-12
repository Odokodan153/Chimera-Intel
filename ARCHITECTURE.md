# Chimera Intel - Architecture Overview

This document provides a detailed overview of the Chimera Intel application's architecture, design principles, and key technical decisions. The goal is to explain not just *what* was built, but *why* it was built this way.

## 1. Core Principles

The architecture of Chimera Intel is guided by three core principles that ensure the project is scalable, maintainable, and efficient.

* **Modularity:** The primary design goal was to avoid a monolithic script. The application is broken down into independent, single-responsibility modules (e.g., `footprint`, `defensive`, `ai_core`). This separation of concerns means that a change to the technology scanning logic will not risk breaking the defensive scanning logic. It also makes the codebase easier for new developers to understand and contribute to.

* **Reusability:** Core logic is strictly decoupled from the user interface. For example, the `gather_footprint_data` async function contains the actual scanning logic, while the `run_footprint_scan` CLI command and the `webapp` API route are simply thin wrappers that call this core function. This powerful pattern allows us to reuse the exact same battle-tested logic across multiple interfaces (CLI, Web, and potentially a future API) without duplicating code.

* **Asynchronous First:** For performance-critical tasks, especially network I/O, an asynchronous approach was chosen. Using `asyncio` and `httpx` allows the tool to initiate multiple API calls concurrently rather than sequentially. This is the single most important architectural decision for performance, as it can reduce scan times by up to 90% when querying multiple external services.

---

## 2. Key Components

The application is composed of several key components that work together to form a complete intelligence platform.

* **Main CLI Entrypoint (`src/chimera_intel/cli.py`):**
    This file acts as the central orchestrator for the command-line interface. It uses the `Typer` library to build a powerful and user-friendly command-line application. Its sole responsibility is to register the different command groups (modules) and delegate tasks to them, making it the "brain" of the CLI operations.

* **Intelligence Modules (`src/chimera_intel/core/`):**
    Each file in this package represents a logical unit of functionality. They contain the core business logic of the application.
    * **Scan Modules** (`footprint.py`, `web_analyzer.py`, etc.): Responsible for *offensive* data gathering. They interact with external APIs and parse the results.
    * **Defensive Module** (`defensive.py`): Responsible for *defensive* counter-intelligence, such as checking for data breaches or finding potential phishing domains.
    * **Analysis Modules** (`ai_core.py`, `strategist.py`, etc.): These modules do not gather new data. Instead, they consume data collected by other modules to perform high-level analysis.
    * **Economic Intelligence (ECONINT) Module** (`econint.py`): Provides deep analysis of macroeconomic factors and supply chain vulnerabilities. This module integrates global economic indicators, trade data, and shipping logistics to model the impact of geopolitical events on specific industries or companies.

* **Data Schemas (`src/chimera_intel/core/schemas.py`):**
    This file is the **single source of truth for all data structures** in the application. By using Pydantic models, we ensure that all data flowing between modules is validated, type-safe, and predictable. This eliminates a huge category of potential bugs and makes the code much easier to reason about.

* **Historical Database (`src/chimera_intel/core/database.py`):**
    For local development and testing, a simple `SQLite` database (in WAL mode for concurrency) gives the application a "memory." For production environments, **PostgreSQL** is the official database. Its purpose is to enable powerful historical features like the `diff` and `forecast` commands. By storing timestamped JSON snapshots of every scan, it lays the foundation for all time-series analysis and change detection.

* **Web Dashboard (`webapp/main.py`):**
    A `FastAPI`-based web application provides a graphical user interface (GUI), making the tool accessible to non-technical users. It reuses the core logic from the intelligence modules, proving the effectiveness of the decoupled architecture.

* **Docker Containerization (`Dockerfile`):**
    The `Dockerfile` packages the entire application—including the Python interpreter, all dependencies, and system-level tools like `dnstwist`—into a portable container. A multi-stage build is used to keep the final image small, and it's configured to run as a non-root user for enhanced security.

---

## 3. Data Flow Diagram

The following diagram illustrates the typical data flow for a `scan` command, from user input to final output and persistence.

```mermaid
graph TD
    subgraph User Interface
        A[User runs 'chimera scan footprint google.com'] --> B{CLI Entrypoint (cli.py)};
    end

    subgraph Core Logic
        B --> C[Footprint Module (footprint.py)];
        C --> D{gather_footprint_data()};
        D -- Calls --> E[External APIs (VirusTotal, etc.)];
        D -- Calls --> F[Local Libraries (whois, dnspython)];
        E --> G[Pydantic Models (schemas.py)];
        F --> G;
        G --> H[Aggregated FootprintResult];
    end

    subgraph Output & Persistence
        H --> I[Utils (utils.py)];
        I -- Output File? --> J{Save to JSON};
        I -- No Output File --> K[Print to Console];
        H --> L[Database Module (database.py)];
        L --> M[Save to chimera_intel.db];
    end

    subgraph Analysis (Later Stage)
        M --> N[Analysis Modules (strategist.py, differ.py)];
        N --> O[AI Models / Historical Comparison];
        O --> P[Final Report/Analysis];
    end
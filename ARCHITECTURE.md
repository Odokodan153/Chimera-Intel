# Chimera Intel - Architecture Overview

This document provides a detailed overview of the Chimera Intel application's architecture, design principles, and key technical decisions. The goal is to explain not just *what* was built, but *why* it was built this way.

## 1. Core Principles

The architecture of Chimera Intel is guided by three core principles that ensure the project is scalable, maintainable, and efficient.

* **Modularity:** The primary design goal was to avoid a monolithic script where all logic resides in a single, massive file. The application is broken down into independent, single-responsibility modules (e.g., `footprint`, `defensive`, `ai_core`). This separation of concerns means that a change to the technology scanning logic will not risk breaking the defensive scanning logic. It also makes the codebase easier for new developers to understand and contribute to.

* **Reusability:** Core logic is strictly decoupled from the user interface. For example, the `gather_footprint_data` async function contains the actual scanning logic, while the `run_footprint_scan` CLI command and the `webapp.py` Flask route are simply thin wrappers that call this core function. This powerful pattern allows us to reuse the exact same battle-tested logic across multiple interfaces (CLI, Web, and potentially a future API) without duplicating code.

* **Asynchronous First:** For performance-critical tasks, especially network I/O, an asynchronous approach was chosen. Using `asyncio` and `httpx` allows the tool to initiate multiple API calls concurrently rather than sequentially. This is the single most important architectural decision for performance, as it can reduce scan times by up to 90% when querying multiple external services.

***

### **Example 1: The Core Principles in Practice**

Here is a practical example of how these principles work together. Imagine we want to add a new feature to find a company's social media profiles.

1.  **Modularity:** Instead of editing a massive file, we would create a new, small file: `modules/social_media.py`. This keeps the new logic isolated and easy to test.
2.  **Reusability:** Inside this new file, we would create a core logic function like `async def gather_social_profiles(domain: str)`. This function would contain all the logic for scraping or querying APIs for social media links.
3.  **Extensibility:** We would then add a new CLI command (`scan social`) and a new button in the Web Dashboard. Both of these new interface elements would simply call our single `gather_social_profiles` function. We've added a feature to two different interfaces by writing the core logic only once, significantly reducing development time and potential for bugs.

---

## 2. Key Components

The application is composed of several key components that work together to form a complete intelligence platform.



#### a. Main CLI Entrypoint (`src/chimera_intel/cli.py`)
This file acts as the central orchestrator for the command-line interface. It uses the `Typer` library to build a powerful and user-friendly command-line application. Its sole responsibility is to register the different command groups (modules) and delegate tasks to them, making it the "brain" of the CLI operations.

#### b. Intelligence Modules (`src/chimera_intel/core/`)
Each file in this package represents a logical unit of functionality.
* **Scan Modules** (`footprint.py`, `web_analyzer.py`, `business_intel.py`): These are responsible for *offensive* data gathering. They contain the functions that interact with external APIs (like VirusTotal, BuiltWith) and parse the results into a standardized format.
* **Defensive Module** (`defensive.py`): This module is responsible for *defensive* counter-intelligence. It contains functions for analyzing an organization's own public footprint, such as checking for data breaches or finding potential phishing domains.
* **Analysis Modules** (`ai_core.py`, `forecaster.py`, etc.): These modules do not gather new data. Instead, they consume data collected by other modules to perform high-level analysis, such as sentiment analysis, SWOT generation, and predictive forecasting.

#### c. Historical Database (`src/chimera_intel/core/database.py`)
A simple `SQLite` database is used for persistence. Its purpose is to give the application a "memory," enabling powerful historical features like the `diff` command. By storing timestamped JSON snapshots of every scan, it lays the foundation for all time-series analysis and change detection.

#### d. Web Dashboard (`webapp.py` & `templates/`)
A `Flask`-based web application provides a graphical user interface (GUI) for the core scanning functionality. This component demonstrates full-stack capability and makes the tool accessible to non-technical users. It reuses the core logic from the intelligence modules, proving the effectiveness of the decoupled architecture.

#### e. Docker Containerization (`Dockerfile`)
The `Dockerfile` packages the entire application—including the Python interpreter, all dependencies, and system-level tools like `dnstwist`—into a portable container. A multi-stage build is used to keep the final image small and secure, ensuring that the tool runs reliably and consistently in any environment.

---

### **Example 2: Data Flow of a `scan footprint` Command**

Here is a step-by-step example of the data flow for a typical command: `chimera scan footprint google.com`

1.  **User Input:** The user executes the command in their terminal.
2.  **CLI Orchestration (`cli.py`):** `Typer` parses the command. It recognizes the `scan` command group and the `footprint` subcommand and calls the `run_footprint_scan` function inside `src/chimera_intel/core/footprint.py`, passing "google.com" as the argument.
3.  **Core Logic Execution (`footprint.py`):**
    * The `run_footprint_scan` function acts as a simple wrapper and immediately calls the reusable `gather_footprint_data("google.com")` function.
    * `gather_footprint_data` starts its work:
        * It makes an asynchronous HTTP request to the VirusTotal API using `httpx`.
        * Concurrently, it makes synchronous calls to the `whois` and `dnspython` libraries (as they don't support `asyncio`).
        * It waits for all these tasks to complete.
    * The function then aggregates all the results, merges the subdomains from different sources, and calculates a confidence score for each one.
4.  **Output Handling (`utils.py`):**
    * The final, structured dictionary of results is passed to the `save_or_print_results` function.
    * Since no `--output` file was specified, this function uses the `rich` library to print a beautifully formatted and color-coded JSON object to the console.
5.  **Database Persistence (`database.py`):**
    * Finally, the results dictionary is also passed to the `save_scan_to_db` function.
    * This function connects to the `chimera_intel.db` SQLite database, timestamps the data, and inserts the entire JSON result as a new row in the `scans` table.

This entire process, from user input to final output and database storage, demonstrates the clean separation of concerns and the robust data flow designed into the application.
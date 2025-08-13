# Chimera Intel - Architecture Overview

This document provides a high-level overview of the Chimera Intel application's architecture, design principles, and key technical decisions.

## 1. Core Principles

The architecture of Chimera Intel is guided by three core principles:

* **Modularity:** The primary design goal was to avoid a monolithic script. The application is broken down into independent, single-responsibility modules (e.g., `footprint`, `defensive`, `ai_core`). This makes the codebase easier to understand, test, maintain, and extend.
* **Reusability:** Core logic is decoupled from the user interface. This allows the same logic to be reused across different interfaces.
* **Asynchronous First:** For performance-critical tasks, especially network I/O, an asynchronous approach was chosen. Using `asyncio` and `httpx` allows the tool to perform multiple API calls concurrently, dramatically reducing scan times.

***

### **➡️ Example 1: The Core Principles in Practice**

Here is a practical example of how these principles work together. Imagine we want to add a new feature to find a company's social media profiles.

1.  **Modularity:** Instead of editing a massive file, we would create a new, small file: `modules/social_media.py`. This keeps the new logic isolated.
2.  **Reusability:** Inside this new file, we would create a core logic function like `async def gather_social_profiles(domain: str)`.
3.  **Extensibility:** We would then add a new CLI command (`scan social`) and a new button in the Web Dashboard. Both of these would simply call our new `gather_social_profiles` function. We've added a feature to two different interfaces by writing the core logic only once.

---

## 2. Key Components

The application is composed of several key components that work together.



#### a. Main CLI Entrypoint (`main.py`)

This file acts as the central orchestrator. It uses the `Typer` library to build a powerful and user-friendly command-line interface. Its sole responsibility is to register the different command groups (modules) and delegate tasks to them.

#### b. Intelligence Modules (`modules/`)

Each file in this package represents a logical unit of functionality.

* **Scan Modules** (`footprint.py`, `web_analyzer.py`, `business_intel.py`): Responsible for *offensive* data gathering.
* **Defensive Module** (`defensive.py`): Responsible for *defensive* counter-intelligence.
* **Analysis Modules** (`ai_core.py`, `forecaster.py`, etc.): These modules consume data collected by other modules to perform high-level analysis.

#### c. Historical Database (`modules/database.py`)

A simple `SQLite` database is used for persistence. Its purpose is to give the application a "memory," enabling powerful historical features like the `diff` command.

#### d. Web Dashboard (`webapp.py` & `templates/`)

A `Flask`-based web application provides a graphical user interface (GUI) for the core scanning functionality.

#### e. Docker Containerization (`Dockerfile`)

The `Dockerfile` packages the entire application into a portable container. A multi-stage build is used to keep the final image small and secure.

---

### **➡️ Example 2: Data Flow of a `scan footprint` Command**

Here is a step-by-step example of the data flow for a typical command, `python main.py scan footprint google.com`:

1.  **User Input:** The user executes the command in their terminal.
2.  **CLI Orchestration (`main.py`):** `Typer` parses the command. It recognizes the `scan` command group and the `footprint` subcommand and calls the `run_footprint_scan` function inside `modules/footprint.py`, passing "google.com" as the argument.
3.  **Core Logic Execution (`footprint.py`):**
    * The `run_footprint_scan` function calls the reusable `gather_footprint_data("google.com")` function.
    * `gather_footprint_data` starts its work:
        * It makes an asynchronous HTTP request to the VirusTotal API using `httpx`.
        * Concurrently, it makes synchronous calls to the `whois` and `dnspython` libraries (as they don't support `asyncio`).
        * It waits for all tasks to complete.
    * The function then aggregates all the results, merges the subdomains, and calculates a confidence score for each one.
4.  **Output Handling (`utils.py`):**
    * The final, structured dictionary of results is passed to the `save_or_print_results` function.
    * Since no `--output` file was specified, this function uses the `rich` library to print a beautifully formatted JSON object to the console.
5.  **Database Persistence (`database.py`):**
    * Finally, the results dictionary is passed to the `save_scan_to_db` function.
    * This function connects to the `chimera_intel.db` SQLite database, timestamps the data, and inserts the entire JSON result as a new row in the `scans` table.

This entire process, from user input to final output and database storage, demonstrates the clean separation of concerns and the robust data flow designed into the application.
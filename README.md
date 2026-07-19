# Vuln-Finder 🛡️

A lightweight, fast, and dependency-free Command Line Interface (CLI) security scanner written in Python. It detects hardcoded credentials, secret leaks, and sensitive data tokens in your source code before committing them to public repositories.

## Features

- **Multi-Target Scanning:** Scan individual files or entire directory trees recursively.
- **Smart Noise Control:** Automatically skips heavy metadata, dependency folders (`node_modules`, `.git`, `venv`, etc.), and `.json` log outputs.
- **Structured Reporting:** Export findings seamlessly into formatted JSON files for audit history.
- **Colorized Output:** Distinct visual indicators highlighting vulnerabilities directly in your terminal.
- **Zero Dependencies:** Runs natively using built-in Python packages (requires only `colorama` for terminal styling).

## Detected Secret Types

- **Telegram Bot Tokens**
- **Generic API Keys / Secrets / Passwords**
- **Private SSH / RSA Keys**

## Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/Vuln-Finder.git](https://github.com/YOUR_USERNAME/Vuln-Finder.git)
   cd Vuln-Finder ```

2. Install the required terminal coloring library:
    pip3 install colorama

## How to use?

1. Basic Folder or File Scan
    python3 main.py /path/to/your/project

2. Scan and Generate a JSON Report
    python3 main.py /path/to/your/project --json reports/scan_1.json

3. Exclude Custom Directories
    python3 main.py /path/to/your/project --exclude testreport_folder test_code

4. Display Help Menu
    python3 main.py --help




    
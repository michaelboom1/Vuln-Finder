# Vuln-Finder 🛡️

A lightweight, fast, and dependency-free Command Line Interface (CLI) security scanner written in Python. It detects hardcoded credentials, secret leaks, and sensitive data tokens in your source code before committing them to public repositories.

## Features

- **Multi-Target Scanning:** Scan individual files or entire directory trees recursively.
- **Hybrid Detection Engine:** Combines **Regex pattern matching** for known service keys with **Shannon Entropy analysis** to catch custom or obfuscated secrets.
- **Smart Noise Control:** Automatically ignores standard metadata/dependency folders (`node_modules`, `.git`, `venv`, etc.) and `.json` log files to prevent infinite loops.
- **`.vulnignore` Support:** Custom exclusion rules using wildcards and path pattern matching (similar to `.gitignore`).
- **Structured JSON Reports:** Safely exports findings into organized JSON files with auto-created target directories.
- **Colorized Terminal Output:** Clear, real-time visual alerts highlighting vulnerabilities, file paths, and exact line numbers.

## Detected Secret Types

- **Messaging & Communication:** Telegram Bot Tokens, Slack Tokens
- **Cloud & Infrastructure:** AWS Access Key IDs, Google API Keys
- **AI & Developer Services:** OpenAI API Keys, GitHub Personal Access Tokens
- **Payment Gateways:** Stripe API Keys (Test & Live)
- **Auth & Tokens:** Generic JWT Tokens, Private SSH/RSA Keys
- **Heuristic Leaks:** High Entropy Tokens (Shannon Entropy Analysis)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/michaelboom1/Vuln-Finder.git
   cd Vuln-Finder

2. Install the required terminal coloring library:
   ```bash
   pip3 install colorama

## How to use?

1. Basic Folder or File Scan
   ```bash
   python3 main.py /path/to/your/project

2. Scan and Generate a JSON Report
   ```bash
   python3 main.py /path/to/your/project --json reports/scan_1.json

3. Exclude Custom Directories
   ```bash
   python3 main.py /path/to/your/project --exclude testreport_folder test_code

4. Display Help Menu
   ```bash
    python3 main.py --help

5. Adjust Shannon Entropy Sensitivity

## Set a custom entropy threshold (default is 4.5)
   ```bash
   python3 main.py . --min-entropy 5.0
   ```

## Custom Ignore Rules

You can place a `.vulnignore` file in your target project directory to bypass specific files, directories, or wildcards during the scan:

## Ignore environment and test files
```txt
*.env
tests/
secrets_mock.py
```

## CLI Options

```txt
positional arguments:
  path                  Path to the file or folder to be scanned

options:
  -h, --help            Show help menu and exit
  --exclude EXCLUDE     Additional directories to ignore during the scan
  --json JSON           Save results to a specified JSON file (e.g.,reports/result.json)
  --min-entropy MIN     Minimum Shannon entropy threshold for suspicious token detection (default: 4.5)
```

    

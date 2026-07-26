import os
import re
import json
import math
import argparse
import fnmatch
from collections import Counter
from colorama import Fore, Style, init

init(autoreset=True)

PATTERNS = {
    "Telegram Bot Token": r"\d{9,10}:[A-Za-z0-9_-]{35}",
    "Generic API Key / Secret": r"['\"]?(?:key|secret|password|token)['\"]?\s*[:=]\s*['\"](.*?)['\"]",
    "Private SSH/RSA Key": r"-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC)?\s+PRIVATE\s+KEY-----",
    "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "GitHub Personal Access Token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
    "OpenAI API Key": r"sk-[A-Za-z0-9]{48}",
    "Slack Token": r"xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24}",
    "Stripe API Key": r"(rk|sk)_(test|live)_[0-9a-zA-Z]{24,99}",
    "Generic JWT Token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+",
    "Google API Key": r"AIzaSy[A-Za-z0-9-_]{35}"
}

DEFAULT_IGNORE_DIRS = {
    '.git', '__pycache__', 'node_modules', '.venv', 'venv', 
    'env', 'bin', 'obj', '.idea', '.vscode'
}

def load_vulnignore(target_path):
    ignore_patterns = set()
    base_dir = target_path if os.path.isdir(target_path) else os.path.dirname(os.path.abspath(target_path))
    ignore_file_path = os.path.join(base_dir, ".vulnignore")
    
    if os.path.exists(ignore_file_path):
        try:
            with open(ignore_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line and not clean_line.startswith("#"):
                        ignore_patterns.add(clean_line)
            print(f"{Fore.CYAN}[*] Loaded .vulnignore rules ({len(ignore_patterns)} patterns found)")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Warning: Could not read .vulnignore: {e}")
            
    return ignore_patterns

def is_ignored(file_path, ignore_patterns):
    norm_path = os.path.normpath(file_path)
    file_name = os.path.basename(file_path)

    for pattern in ignore_patterns:
        clean_pattern = pattern.rstrip("/\\")
        
        if fnmatch.fnmatch(file_name, pattern):
            return True
        if fnmatch.fnmatch(norm_path, pattern) or fnmatch.fnmatch(norm_path, f"*{os.sep}{pattern}"):
            return True
        path_parts = norm_path.split(os.sep)
        if clean_pattern in path_parts:
            return True

    return False

def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def scan_file(file_path, report_data, min_entropy=4.5):
    found_in_file = 0
    triggered_lines = set()

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            for line_num, line in enumerate(file, 1):
                clean_line = line.strip()

                for secret_type, regex in PATTERNS.items():
                    match = re.search(regex, line, re.IGNORECASE)
                    
                    if match:
                        if line_num in triggered_lines and secret_type == "Generic API Key / Secret":
                            continue
                            
                        matched_value = match.group(1 if secret_type == "Generic API Key / Secret" else 0)
                        
                        print(f"{Fore.RED}[!] VULNERABILITY FOUND!")
                        print(f"    Type: {Fore.YELLOW}{secret_type}")
                        print(f"    File: {file_path}")
                        print(f"    Line {line_num}: {Fore.WHITE}{clean_line}")
                        print(f"    Match: {Fore.CYAN}{matched_value}\n")
                        
                        report_data.append({
                            "file": file_path,
                            "line": line_num,
                            "type": secret_type,
                            "match": matched_value
                        })
                        
                        triggered_lines.add(line_num)
                        found_in_file += 1

                if line_num not in triggered_lines:
                    words = re.findall(r'[A-Za-z0-9_\-\+\/=]{16,}', clean_line)
                    for word in words:
                        entropy = calculate_entropy(word)
                        if entropy >= min_entropy:
                            print(f"{Fore.RED}[!] HIGH ENTROPY SECRET DETECTED!")
                            print(f"    Type: {Fore.YELLOW}High Entropy Token (Entropy: {entropy:.2f})")
                            print(f"    File: {file_path}")
                            print(f"    Line {line_num}: {Fore.WHITE}{clean_line}")
                            print(f"    Match: {Fore.CYAN}{word}\n")

                            report_data.append({
                                "file": file_path,
                                "line": line_num,
                                "type": f"High Entropy Token (Entropy: {entropy:.2f})",
                                "match": word
                            })

                            triggered_lines.add(line_num)
                            found_in_file += 1
                            break

    except Exception as e:
        print(f"{Fore.RED}[-] Failed to read file {file_path}: {e}")
        
    return found_in_file

def start_scanning(target_path, custom_exclude=None, json_output=None, min_entropy=4.5):
    if not os.path.exists(target_path):
        print(f"{Fore.RED}[-] Error: Path '{target_path}' is not found.")
        return

    ignore_dirs = DEFAULT_IGNORE_DIRS.copy()
    if custom_exclude:
        ignore_dirs.update(custom_exclude)

    vulnignore_patterns = load_vulnignore(target_path)

    total_secrets = 0
    report_data = []
    
    print(f"{Fore.BLUE}[*] Starting security scan on: {target_path}...\n")

    if os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            
            for file in files:
                if json_output and file == os.path.basename(json_output):
                    continue
                if file.endswith('.json'):
                    continue
                    
                full_path = os.path.join(root, file)
                if is_ignored(full_path, vulnignore_patterns):
                    continue

                total_secrets += scan_file(full_path, report_data, min_entropy=min_entropy)
    else:
        if not is_ignored(target_path, vulnignore_patterns):
            total_secrets += scan_file(target_path, report_data, min_entropy=min_entropy)

    print(f"{Fore.BLUE}{'='*50}")
    if total_secrets == 0:
        print(f"{Fore.GREEN}[+] Scanning is done. No secrets detected. Code is safe!")
    else:
        print(f"{Fore.RED}[Result]: Scan finished. Total vulnerabilities found: {total_secrets}.")
        print(f"{Fore.RED}[Action Required]: Remove secrets before committing to GitHub!")

    if json_output and report_data:
        try:
            out_dir = os.path.dirname(json_output)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            with open(json_output, "w", encoding="utf-8") as jf:
                json.dump(report_data, jf, indent=4, ensure_ascii=False)
            print(f"{Fore.GREEN}[+] Structured report successfully saved to: {json_output}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to save JSON report: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Vuln-Finder: A simple CLI scanner for detecting vulnerabilities and secret leaks in code."
    )
    parser.add_argument(
        "path", 
        type=str, 
        help="Path to the file or folder to be scanned"
    )
    parser.add_argument(
        "--exclude", 
        nargs="+", 
        help="Additional directories to ignore during the scan"
    )
    parser.add_argument(
        "--json", 
        type=str, 
        help="Save results to a specified JSON file (e.g., report.json)"
    )
    parser.add_argument(
        "--min-entropy",
        type=float,
        default=4.5,
        help="Minimum Shannon entropy threshold for suspicious token detection (default: 4.5)"
    )
    
    args = parser.parse_args()
    start_scanning(args.path, custom_exclude=args.exclude, json_output=args.json, min_entropy=args.min_entropy)
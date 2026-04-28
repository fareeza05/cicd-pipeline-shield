import sys
import argparse
import os
from engine import ScanEngine
from reporter import generate_report

def main():
    # 1. Setup CLI Arguments
    parser = argparse.ArgumentParser(
        description="Shield-Pipe: A Lightweight DevSecOps Scanner"
    )
    parser.add_argument(
        "path", 
        help="The target directory to scan for security risks",
        default=".",
        nargs="?" # This makes the path optional; defaults to current directory
    )
    
    args = parser.parse_args()
    target_path = os.path.abspath(args.path)

    # 2. Path Validation
    if not os.path.exists(target_path):
        print(f"ERROR: Path '{target_path}' does not exist.")
        sys.exit(1)

    print(f"[*] Initializing Shield-Pipe Scan on: {target_path}")

    # 3. Execution
    engine = ScanEngine(target_path)
    findings = engine.run_all_checks()

    # 4. Generate the JSON/Markdown Report
    generate_report(findings)

    # 5. The Security Gate (The Jenkins Contract)
    if findings:
        print(f"\n[!] SCAN FAILED: {len(findings)} security risks identified.")
        # We exit with 1 so the Jenkins Pipeline turns RED
        sys.exit(1)
    
    print("\n[+] SCAN PASSED: No immediate security risks found.")
    # We exit with 0 so the Jenkins Pipeline turns GREEN
    sys.exit(0)

if __name__ == "__main__":
    main()

import sys
import argparse
import os
from engine import ScanEngine
from reporter import generate_report

# Exit code contract (documented for CI operators):
#   0 = clean scan
#   1 = findings detected (security gate tripped)
#   2 = tool error (bad input, report write failure, unexpected exception)
EXIT_CLEAN    = 0
EXIT_FINDINGS = 1
EXIT_ERROR    = 2

def main():
    parser = argparse.ArgumentParser(
        description="Shield-Pipe: A Lightweight DevSecOps Scanner"
    )
    parser.add_argument(
        "path",
        help="The target directory to scan for security risks",
        default=".",
        nargs="?"
    )

    args = parser.parse_args()
    target_path = os.path.abspath(args.path)

    if not os.path.exists(target_path):
        print(f"[!] ERROR: Path '{target_path}' does not exist.")
        sys.exit(EXIT_ERROR)

    print(f"[*] Initializing Shield-Pipe Scan on: {target_path}")

    try:
        engine = ScanEngine(target_path)
        findings = engine.run_all_checks()
    except Exception as e:
        print(f"[!] ERROR: Scanner failed unexpectedly: {e}")
        sys.exit(EXIT_ERROR)

    try:
        generate_report(findings)
    except Exception as e:
        print(f"[!] ERROR: Could not write report: {e}")
        sys.exit(EXIT_ERROR)

    if findings:
        print(f"\n[!] SCAN FAILED: {len(findings)} security risks identified.")
        sys.exit(EXIT_FINDINGS)

    print("\n[+] SCAN PASSED: No immediate security risks found.")
    sys.exit(EXIT_CLEAN)

if __name__ == "__main__":
    main()

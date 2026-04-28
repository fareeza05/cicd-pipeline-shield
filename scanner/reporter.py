import json
import os

def generate_report(findings):
    report_path = "reports/security_report.json"
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    # Structure the final data
    report_data = {
        "scan_status": "FAILED" if findings else "PASSED",
        "total_issues": len(findings),
        "findings": findings
    }
    
    # Write to JSON file
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=4)
    
    print(f"\n[+] Security report generated at: {report_path}")
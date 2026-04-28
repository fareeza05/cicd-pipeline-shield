## Project Overview

This project is a lightweight Static Application Security Testing (SAST) tool. It is designed to be a database-free, containerized CLI utility that audits source code for security risks before it is deployed.

---

## Setup & Getting Started

### 1.Prerequisites
- Python 3.1+
- Docker Desktop
- Github

###  1.Local Development Setup**

**Clone the repository**
```bash
git clone https://github.com/fareeza05/cicd-pipeline-shield.git
cd cicd-pipeline-shield
```
**Create and activate virtual environment**
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
```
**Install dependencies**
```bash
pip install -r requirements.txt
```
**Run the scanner**
```bash
python3 scanner/main.py [path_to_target_folder]
```

### 1. Running with Docker

**Build docker image**
```bash
docker build -t shield-pipe -f deployment/Dockerfile .
```

**Run a scan on current directory**
```bash
docker run --rm -v $(pwd):/data shield-pipe /data
```

---

## Project File Structure

```bash
shield-pipe/
├── scanner/                # Core Application Logic
│   ├── main.py             # CLI Entrypoint & Argument Parsing
│   ├── engine.py           # The "Brain" (Regex & Permission checks)
│   └── reporter.py         # Report Generation (JSON output)
├── tests/                  # Sample Data
│   └── samples/            # "Vulnerable" files for testing the scanner
├── deployment/             # Infrastructure & Automation
│   └── Dockerfile          # Container definition
├── Jenkinsfile             # CI/CD Pipeline definition
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```
---

## Core Components
1. The Scanner (`/scanner`)
    `main.py`: Handles the command-line interface. It receives the target path, triggers the engine, and determines the final exit code based on the findings.

    `engine.py`: Contains the ScanEngine class. It recursively crawls the filesystem, runs regex patterns against file contents to find secrets (API keys, passwords), and checks for dangerous file permissions (e.g., 777).

    `reporter.py`: Summarizes the findings into a structured JSON format saved in `reports/security_report.json.`

2. The Deployment (/deployment & Root)

    `Dockerfile`: Packages the Python environment and the scanner logic into an isolated, portable image.

    `Jenkinsfile`: Automates the build and scan process. It ensures that any security risks detected by the scanner will automatically stop the build pipeline.

---

## Operational Logic

**Exit Codes:** The tool uses standard shell exit codes to indicate security status.

`0`: Scan passed (No threats found).

`1`: Scan failed (Security risks identified).

Statelessness: No database is required. Each scan is independent, and results are written directly to the filesystem for archival by the CI/CD system.

---

## Example
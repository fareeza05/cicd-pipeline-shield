## Project Overview

This project is a lightweight Static Application Security Testing (SAST) tool. It is designed to be a database-free, containerized CLI utility that audits source code for security risks before it is deployed.

---

## Setup & Getting Started

### 1.Prerequisites
- Python 3.1+
- Docker Desktop
- Github

### 1. Local Development Setup

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

### 2. Running with Docker

**Build docker image**
```bash
docker build -t shield-pipe:dev -f deployment/Dockerfile .
```

**Run a scan on current directory**

Source is mounted read-only (the scanner shouldn't mutate your code); the reports directory is mounted read-write so `security_report.json` lands back on the host.

```bash
docker run --rm \
  -v $(pwd):/data:ro \
  -v $(pwd)/reports:/app/reports \
  shield-pipe:dev /data
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
│   ├── samples/            # "Vulnerable" files for testing the scanner
│   └── test_scanner.py     # Unit tests
├── deployment/             # Infrastructure & Automation
│   ├── Dockerfile          # Container definition
│   └── entrypoint.sh       # Container startup script (banner + scanner exec)
├── reports/                # Scan output — security_report.json lands here (gitignored)
├── Jenkinsfile             # CI/CD Pipeline definition
├── requirements.txt        # Python dependencies
├── .dockerignore           # Files excluded from the Docker build context
├── .gitignore              # Files excluded from version control
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

## CI/CD Pipeline Setup

The repository ships a [Jenkinsfile](Jenkinsfile) that defines a 3-stage declarative pipeline (Checkout → Build → Scan) plus a `post` block that archives `reports/security_report.json` on every run.

### 1. Run Jenkins locally (Docker-out-of-Docker)

The pipeline shells out to `docker build` / `docker run`, so the Jenkins container needs access to the host Docker daemon. Equally important: the Jenkins workspace path **inside** the container must match the path **on** the host, because `docker run -v ${WORKSPACE}:/data` is resolved by the host daemon — not by Jenkins.

The simplest way to satisfy both is to bind-mount a host directory at the same path used inside the container:

```bash
mkdir -p ~/jenkins_home

docker run -d --name jenkins \
  -p 8080:8080 -p 50000:50000 \
  -v ~/jenkins_home:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add $(stat -f '%g' /var/run/docker.sock) \
  jenkins/jenkins:lts
```

Then install the Docker CLI inside the container so the pipeline's `sh 'docker ...'` calls work:

```bash
docker exec -u root jenkins bash -c "apt-get update && apt-get install -y docker.io"
```

Get the initial admin password and finish the web setup at `http://localhost:8080`:

```bash
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

### 2. Install required plugins

From **Manage Jenkins → Plugins → Available**, install:
- **GitHub** — webhook integration
- **Pipeline** + **Pipeline: Stage View** — declarative pipeline support
- **Docker Pipeline** — optional, for cleaner Docker syntax in future iterations

### 3. Create the Pipeline job

1. **New Item → Pipeline**, name it `shield-pipe`
2. Under **Build Triggers**, check **GitHub hook trigger for GITScm polling**
3. Under **Pipeline**:
   - Definition: **Pipeline script from SCM**
   - SCM: **Git**
   - Repository URL: `https://github.com/fareeza05/cicd-pipeline-shield.git`
   - Branch: `*/main`
   - Script Path: `Jenkinsfile`
4. **Save**

### 4. Wire up the GitHub webhook

Local Jenkins isn't reachable from `github.com` by default. Expose it with [ngrok](https://ngrok.com/):

```bash
ngrok http 8080
```

Copy the `https://...ngrok-free.app` URL, then in the GitHub repo:

**Settings → Webhooks → Add webhook**
- Payload URL: `https://<your-ngrok-id>.ngrok-free.app/github-webhook/` (trailing slash matters)
- Content type: `application/json`
- Events: **Just the push event**
- Active: ✓

### 5. Verify the loop

```bash
git commit --allow-empty -m "trigger pipeline"
git push
```

Watch the Jenkins build start automatically. With the test fixtures in [tests/samples/](tests/samples/) intact, the build should go **RED** and `security_report.json` should be downloadable from the build's **Artifacts** section.

---

## Example
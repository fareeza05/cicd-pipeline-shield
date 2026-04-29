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

This walkthrough assumes you have **Docker Desktop running on macOS** and a **GitHub account**. Follow each step in order — every command is copy-paste ready.

### Step 1 — Start the Jenkins container

The pipeline runs `docker build` / `docker run` from inside Jenkins, so the Jenkins container needs to reach your host's Docker daemon. We also need the workspace path **inside** the Jenkins container to match the path **on** the host, because `docker run -v ${WORKSPACE}:/data` is resolved by the host daemon — not by Jenkins. The bind-mount below satisfies both.

Run from any directory:

```bash
mkdir -p ~/jenkins_home

docker run -d --name jenkins \
  -p 8080:8080 -p 50000:50000 \
  -v ~/jenkins_home:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add $(stat -f '%g' /var/run/docker.sock) \
  jenkins/jenkins:lts
```

The first run pulls the image (~600MB), so give it a minute. Verify it's up:

```bash
docker ps --filter name=jenkins
```

You should see one row with `STATUS` like `Up 30 seconds` and `0.0.0.0:8080->8080/tcp` in the ports column.

### Step 2 — Install the Docker CLI inside Jenkins

The Jenkins image doesn't ship with the `docker` binary, but our pipeline calls `sh 'docker build ...'`. Install it:

```bash
docker exec -u root jenkins bash -c "apt-get update && apt-get install -y docker.io"
```

This takes about 30 seconds. The `-u root` flag is required because installing packages needs root inside the container — Jenkins itself still runs as the `jenkins` user.

### Step 3 — Fix the Docker socket permissions (macOS gotcha)

On Docker Desktop for macOS, the socket inside the Jenkins container is owned by `root:root`, but the `jenkins` user isn't in the root group by default. Without this fix, you'll see `permission denied while trying to connect to the Docker daemon socket`.

Add `jenkins` to the root group, then restart so the new group membership takes effect:

```bash
docker exec -u root jenkins usermod -aG root jenkins
docker restart jenkins
```

> **Why this is acceptable here:** giving `jenkins` group-read access to root-owned files inside this single container is a common pattern for local DooD setups. For production Jenkins you'd use a dedicated `docker` group at the right GID, rootless Docker, or a `dind` sidecar.

### Step 4 — Verify Jenkins can drive Docker

```bash
docker exec jenkins docker version
```

You should see **two** sections — `Client:` *and* `Server: Docker Desktop ...`. If you only see `Client:` and a permission error, repeat Step 3.

### Step 5 — Unlock Jenkins and complete first-time setup

Get the initial admin password:

```bash
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

Open `http://localhost:8080` in your browser, then:

1. **Unlock Jenkins** — paste the password, click **Continue**.
2. **Customize Jenkins** — click **Install suggested plugins**. Wait ~2 minutes. (The suggested set includes Git, Pipeline, and GitHub — everything we need.)
3. **Create First Admin User** — fill in username/password/email, click **Save and Continue**.
4. **Instance Configuration** — leave the URL as `http://localhost:8080/`, click **Save and Finish**.
5. Click **Start using Jenkins**. You should land on the dashboard.

### Step 6 — Make sure Jenkins can read your GitHub repo

GitHub dropped HTTPS password authentication in 2021, so Jenkins can't clone a **private** repo without credentials. Pick **one** of the two options below.

**Option A — Make the repo public (simplest):**

GitHub → your repo → **Settings → General → scroll to "Danger Zone" → Change repository visibility → Make public**. The test fixtures in this project only contain *fake* secrets, so there's no real risk.

**Option B — Use a Personal Access Token (keeps the repo private):**

1. GitHub → click your avatar (top-right) → **Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token (classic)**.
2. **Note:** `jenkins-shield-pipe`. **Expiration:** 90 days. **Scopes:** check `repo`.
3. Click **Generate token** and copy the `ghp_...` string immediately — GitHub will not show it again.
4. You'll add this token to the Jenkins job in Step 7 below.

### Step 7 — Create the Pipeline job

In the Jenkins dashboard:

1. Click **New Item** (top-left).
2. Enter the name `shield-pipe`, select **Pipeline**, click **OK**.
3. On the configuration page:
   - **Build Triggers:** check **GitHub hook trigger for GITScm polling**.
   - **Pipeline** section:
     - **Definition:** `Pipeline script from SCM`
     - **SCM:** `Git`
     - **Repository URL:** `https://github.com/<your-username>/cicd-pipeline-shield.git`
     - **Credentials:** if you chose Option B above, click **Add → Jenkins**, set Kind = `Username with password`, Username = your GitHub username, Password = the `ghp_...` token, ID = `github-pat`, click **Add**, then select `github-pat` from the dropdown. If you chose Option A, leave this as `- none -`.
     - **Branch Specifier:** `*/main`
     - **Script Path:** `Jenkinsfile` (default)
4. Click **Save**.

### Step 8 — Test the pipeline manually

Before involving GitHub webhooks, run the pipeline directly to confirm it works.

On the job page, click **Build Now** in the left sidebar. A build appears under **Build History**. Click the build number, then **Console Output** to stream logs.

Expected sequence:

1. Git clone of your repo
2. `docker build` running through the Dockerfile
3. `docker run` executing the scanner against the workspace
4. Scanner exits with code `1` (because [tests/samples/](tests/samples/) contains a fake AWS key and password)
5. Build marked **FAILED** (red ball) — this is the *expected* outcome; the security gate is working

Go back to the build page and look for the **Artifacts** section in the left sidebar — `security_report.json` should be downloadable there.

### Step 9 — Wire up the GitHub webhook

Local Jenkins isn't reachable from `github.com` by default. Expose it with [ngrok](https://ngrok.com/):

```bash
ngrok http 8080
```

Copy the `https://...ngrok-free.app` URL ngrok prints. Then in the GitHub repo:

**Settings → Webhooks → Add webhook**
- **Payload URL:** `https://<your-ngrok-id>.ngrok-free.app/github-webhook/` (the trailing slash matters)
- **Content type:** `application/json`
- **Which events?:** Just the push event.
- **Active:** checked.
- Click **Add webhook**.

GitHub will send a test ping immediately. Refresh the webhook page — you should see a green checkmark next to **Recent Deliveries** at the bottom.

### Step 10 — Verify end-to-end

```bash
git commit --allow-empty -m "trigger pipeline"
git push
```

Within a few seconds, a new build should appear under **Build History** in Jenkins, started automatically by the push. With the test fixtures intact it should go RED and `security_report.json` should be archived as an artifact.

---

### Common issues

- **"permission denied while trying to connect to the Docker daemon socket"** in Step 4 — repeat Step 3 (`usermod -aG root jenkins` + `docker restart jenkins`).
- **"Authentication failed for ..."** when saving the job in Step 7 — the repo is private and you skipped Option B. Either make the repo public or add a Personal Access Token credential.
- **Webhook delivery shows red X in GitHub** — your ngrok tunnel probably stopped. Restart `ngrok http 8080` and update the Payload URL on the webhook (ngrok URLs change each session unless you have a paid plan).
- **Build stuck "pending"** — Jenkins can't reach `docker`. Re-run `docker exec jenkins docker version` and confirm both Client and Server show.

---

## Example
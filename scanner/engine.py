import os
import re
import stat
import math
from packaging import version

class ScanEngine:
    def __init__(self, target_path):
        self.target_path = target_path
        self.findings = []

        #Loading ignore patterns 
        self.ignore_list = self._load_ignore_patterns()
        
        # High-fidelity Regex Patterns
        self.signatures = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Private Key Block": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
            # ^ anchor + \b prevents matching keywords inside longer words or dict key definitions
            "Potential Password/Secret": r"""(?im)^\s*['"]*(?:export\s+)?\b(password|passwd|secret|api_key|auth_token)\b['"]*\s*[:=]\s*\S+""",
            "SSN (PII)": r"\b\d{3}-\d{2}-\d{4}\b"
        }

    # Exact filenames and glob-style suffix patterns that should never be committed
    SENSITIVE_FILENAMES = {
        ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    }
    SENSITIVE_EXTENSIONS = {".pem", ".key", ".pfx", ".p12"}

    def run_all_checks(self):
            for root, dirs, files in os.walk(self.target_path):
                # 1. Filter directories in-place (pruning the tree)
                dirs[:] = [d for d in dirs if d not in self.ignore_list]

                for file in files:
                    # 2. Skip files in the ignore list
                    if file in self.ignore_list:
                        continue

                    file_path = os.path.join(root, file)
                    self._check_sensitive_filename(file, file_path)
                    self._audit_file_permissions(file_path)
                    self._scan_file_content(file_path)
                    if "requirements.txt" in file:
                        self._audit_dependencies(file_path)

            return self.findings

    def _check_sensitive_filename(self, filename, file_path):
        _, ext = os.path.splitext(filename)
        if filename in self.SENSITIVE_FILENAMES or ext in self.SENSITIVE_EXTENSIONS:
            self.findings.append({
                "file": file_path,
                "type": "Sensitive File Committed",
                "detail": f"File '{filename}' should not be committed to version control"
            })
    
    def _audit_file_permissions(self, file_path):
        """Checks if a file has dangerously broad permissions (777)."""
        try:
            mode = os.stat(file_path).st_mode
            # World-executable (755) is normal for scripts; only world-writable is dangerous
            if bool(mode & stat.S_IWOTH):
                self.findings.append({
                    "file": file_path,
                    "type": "Dangerous Permissions",
                    "detail": f"File is world-writable/executable (Mode: {oct(mode)[-3:]})"
                })
        except Exception:
            pass

    def _scan_file_content(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return

        high_entropy_hits = []
        first_entropy_line = None

        for line_num, line in enumerate(lines, start=1):
            if "# nosec" in line:
                continue

            # Regex signature checks
            for label, pattern in self.signatures.items():
                if re.search(pattern, line):
                    self.findings.append({
                        "file": file_path,
                        "line": line_num,
                        "type": "Sensitive Data Leak",
                        "detail": label
                    })

            # High-entropy detection — aggregated to one finding per file
            for word in line.split():
                if len(word) > 16 and not word.startswith(("http", "https")):
                    entropy_score = self._calculate_entropy(word)
                    if entropy_score > 4.5:
                        if first_entropy_line is None:
                            first_entropy_line = line_num
                        high_entropy_hits.append(round(entropy_score, 2))

        if high_entropy_hits:
            self.findings.append({
                "file": file_path,
                "line": first_entropy_line,
                "type": "High-Entropy String (Potential Key)",
                "detail": f"{len(high_entropy_hits)} high-entropy string(s) detected. Max entropy: {max(high_entropy_hits)}"
            })
    
    def _load_ignore_patterns(self):
        """Reads .shieldignore and returns a set of directory/file names to skip."""
        # Standard defaults to ensure the scanner doesn't break itself
        patterns = {".git", "venv", "__pycache__", ".venv", ".shieldignore"}
        
        ignore_file = os.path.join(self.target_path, ".shieldignore")
        
        if os.path.exists(ignore_file):
            try:
                with open(ignore_file, 'r') as f:
                    for line in f:
                        clean_line = line.strip()
                        # Ignore empty lines and comments
                        if clean_line and not clean_line.startswith("#"):
                            patterns.add(clean_line)
            except Exception as e:
                print(f"[!] Warning: Could not read .shieldignore: {e}")
        
        return patterns
    

    def _calculate_entropy(self, text):
        """Calculates the Shannon entropy of a string."""
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    

    def _audit_dependencies(self, file_path):
        """Checks requirements.txt for known vulnerable library versions."""
        # Mock Database: In a real app, you'd fetch this from OSV.dev or GitHub Advisory
        VULNERABLE_PACKAGES = {
            "flask": "2.2.0",  # Any version < 2.2.5 is 'vulnerable' for this demo
            "requests": "2.28.0",
            "django": "4.0.0"
        }

        if "requirements.txt" in file_path:
            try:
                with open(file_path, 'r') as f:
                    for line_num, line in enumerate(f, start=1):
                        line = line.split("#")[0].split(";")[0].strip()
                        if "==" not in line:
                            continue
                        parts = line.split("==", 1)
                        if len(parts) != 2:
                            continue
                        pkg, ver = parts[0].strip(), parts[1].strip()
                        if pkg.lower() in VULNERABLE_PACKAGES:
                            vuln_ver = VULNERABLE_PACKAGES[pkg.lower()]
                            if version.parse(ver) <= version.parse(vuln_ver):
                                self.findings.append({
                                    "file": file_path,
                                    "line": line_num,
                                    "type": "Vulnerable Dependency (SCA)",
                                    "detail": f"{pkg} {ver} is outdated. Minimum safe version: >{vuln_ver}"
                                })
            except Exception as e:
                print(f"[!] Error scanning dependencies: {e}")
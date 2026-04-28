import os
import re
import stat

class ScanEngine:
    def __init__(self, target_path):
        self.target_path = target_path
        self.findings = []
        
        # High-fidelity Regex Patterns
        self.signatures = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Private Key Block": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
            # This version catches 'key=val', 'key: val', and 'key : "val"'
            "Potential Password/Secret": r"(?i)(password|passwd|secret|api_key|auth_token)\s*[:=]\s*.+",
            "SSN (PII)": r"\b\d{3}-\d{2}-\d{4}\b"
        }

    def run_all_checks(self):
            """Main entry point for the engine logic."""
            for root, dirs, files in os.walk(self.target_path):
                # Optimization: Doesn't dive into .git or virtual environments
                dirs[:] = [d for d in dirs if d not in ['.git', 'venv', '__pycache__']]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    self._audit_file_permissions(file_path)
                    self._scan_file_content(file_path)
            
            return self.findings
    
    def _audit_file_permissions(self, file_path):
        """Checks if a file has dangerously broad permissions (777)."""
        try:
            mode = os.stat(file_path).st_mode
            # Check for 'World Writable' or 'World Executable' (Octal 007)
            if bool(mode & stat.S_IWOTH) or bool(mode & stat.S_IXOTH):
                self.findings.append({
                    "file": file_path,
                    "type": "Dangerous Permissions",
                    "detail": f"File is world-writable/executable (Mode: {oct(mode)[-3:]})"
                })
        except Exception as e:
            pass # Handle permission denied errors silently


    def _scan_file_content(self, file_path):
        """Opens a file and runs regex signatures against its text."""
        print(f"[DEBUG] Scanning file: {file_path}") # See if it's even opening the file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for label, pattern in self.signatures.items():
                    if re.search(pattern, content):
                        self.findings.append({
                            "file": file_path,
                            "type": "Sensitive Data Leak",
                            "detail": label
                        })
        except Exception:
            # This skips binary files like images that can't be read as text
            pass
import os
import re
import stat
import math

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
            # Catches key=val, key: val, "key" = val, 'key' = 'val', etc.
            "Potential Password/Secret": r"""(?i)(password|passwd|secret|api_key|auth_token)['"]*\s*[:=]\s*.+""",
            "SSN (PII)": r"\b\d{3}-\d{2}-\d{4}\b"
        }

    def run_all_checks(self):
            for root, dirs, files in os.walk(self.target_path):
                # 1. Filter directories in-place (pruning the tree)
                dirs[:] = [d for d in dirs if d not in self.ignore_list]
                
                for file in files:
                    # 2. Skip files in the ignore list
                    if file in self.ignore_list:
                        continue
                        
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
        except Exception:
            pass

    def _scan_file_content(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # 1. Existing Regex Checks
                for label, pattern in self.signatures.items():
                    if re.search(pattern, content):
                        self.findings.append({"file": file_path, "type": "Sensitive Data Leak", "detail": label})
                
                # 2. NEW: High-Entropy Detection
                # Split content into individual 'words' or strings
                words = content.split()
                for word in words:
                    # We only care about long strings (keys are usually 16+ chars)
                    # And we ignore common things like long URLs
                    if len(word) > 16 and not word.startswith(("http", "https")):
                        entropy_score = self._calculate_entropy(word)
                        
                        # 4.5 is a standard threshold for 'random' looking strings
                        if entropy_score > 4.5:
                            self.findings.append({
                                "file": file_path, 
                                "type": "High-Entropy String (Potential Key)", 
                                "detail": f"Entropy: {round(entropy_score, 2)}"
                            })
        except Exception:
            pass
    
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
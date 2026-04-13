import re

def analyze_code(code):
    issues = []

    # ---------------- Hardcoded Credentials ---------------- #
    if re.search(r'(password|api_key|secret)\s*=\s*["\'].*["\']', code, re.IGNORECASE):
        issues.append({
            "type": "Hardcoded Credentials",
            "severity": "HIGH",
            "message": "Sensitive credentials found in source code.",
            "fix": "Use environment variables or secure vaults."
        })

    # ---------------- Insufficient Input Validation ---------------- #
    if re.search(r'input\(', code) or re.search(r'cin\s*>>', code):
        if not re.search(r'validate|sanitize|isdigit|isalpha', code):
            issues.append({
                "type": "Insufficient Input Validation",
                "severity": "HIGH",
                "message": "User input is used without validation.",
                "fix": "Validate and sanitize all user inputs."
            })

    # ---------------- Insecure Logging ---------------- #
    if re.search(r'print\(.*(password|token|secret).*', code, re.IGNORECASE):
        issues.append({
            "type": "Insecure Logging",
            "severity": "MEDIUM",
            "message": "Sensitive data is being logged.",
            "fix": "Avoid logging secrets or mask sensitive values."
        })

    # ---------------- Dependency/Supply Chain ---------------- #
    if re.search(r'requirements\.txt|package\.json', code):
        issues.append({
            "type": "Dependency Risk",
            "severity": "MEDIUM",
            "message": "Dependencies should be checked for vulnerabilities.",
            "fix": "Use tools like npm audit or pip-audit."
        })

    # ---------------- Insecure Deserialization ---------------- #
    if re.search(r'pickle\.loads|yaml\.load', code):
        issues.append({
            "type": "Insecure Deserialization",
            "severity": "HIGH",
            "message": "Deserializing untrusted data can lead to RCE.",
            "fix": "Use safe loaders like yaml.safe_load()."
        })

    # ---------------- Race Conditions ---------------- #
    if re.search(r'thread|Thread|multiprocessing', code):
        issues.append({
            "type": "Race Condition Risk",
            "severity": "MEDIUM",
            "message": "Concurrent execution detected.",
            "fix": "Ensure proper synchronization (locks, semaphores)."
        })

    # ---------------- Path Traversal ---------------- #
    if re.search(r'\.\./', code):
        issues.append({
            "type": "Path Traversal",
            "severity": "HIGH",
            "message": "Relative path traversal detected.",
            "fix": "Sanitize file paths and restrict access."
        })

    # ---------------- Weak Cryptography ---------------- #
    if re.search(r'MD5|DES|RC4', code):
        issues.append({
            "type": "Weak Cryptography",
            "severity": "HIGH",
            "message": "Weak encryption algorithm detected.",
            "fix": "Use strong algorithms like AES-256 or SHA-256."
        })

    # ---------------- Information Disclosure ---------------- #
    if re.search(r'print\(.*error|exception|stack trace', code, re.IGNORECASE):
        issues.append({
            "type": "Information Disclosure",
            "severity": "LOW",
            "message": "Verbose error messages may leak system details.",
            "fix": "Use generic error messages in production."
        })

    # ================= SQL Injection =================
    if re.search(r'SELECT.*\+|INSERT.*\+|UPDATE.*\+', code, re.IGNORECASE):
        issues.append({
        "type": "SQL Injection",
        "severity": "HIGH",
        "message": "SQL query built using string concatenation.",
        "fix": "Use parameterized queries (prepared statements)."
    })

# ================= Command Injection =================
    if re.search(r'os\.system|subprocess\.call|system\(', code):
        issues.append({
        "type": "Command Injection",
        "severity": "HIGH",
        "message": "User input passed to system command.",
        "fix": "Sanitize input or avoid shell execution."
    })

# ================= XSS =================
    if re.search(r'<script>|innerHTML|document\.write', code, re.IGNORECASE):
        issues.append({
        "type": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "message": "Untrusted input rendered in HTML.",
        "fix": "Escape output and use safe rendering."
    })

# ================= Path Traversal =================
    if re.search(r'\.\./', code):
        issues.append({
        "type": "Path Traversal",
        "severity": "HIGH",
        "message": "Directory traversal pattern detected.",
        "fix": "Validate file paths and restrict access."
    })

# ================= SSRF =================
    if re.search(r'requests\.get\(|http\.client|urllib', code):
        issues.append({
        "type": "SSRF",
        "severity": "HIGH",
        "message": "External request may be user-controlled.",
        "fix": "Validate URLs and restrict internal access."
    })

# ================= File Inclusion =================
    if re.search(r'include\(|require\(|open\(', code):
        issues.append({
        "type": "File Inclusion",
        "severity": "HIGH",
        "message": "Dynamic file inclusion detected.",
        "fix": "Whitelist allowed files."
    })

# ================= Open Redirect =================
    if re.search(r'redirect\(|window\.location', code):
       issues.append({
        "type": "Open Redirect",
        "severity": "MEDIUM",
        "message": "Redirect may be user-controlled.",
        "fix": "Validate redirect URLs."
    })

# ================= Sensitive Data Exposure =================
    if re.search(r'print\(.*(password|token|secret)', code, re.IGNORECASE):
        issues.append({
        "type": "Sensitive Data Exposure",
        "severity": "HIGH",
        "message": "Sensitive data is exposed in output.",
        "fix": "Mask or remove sensitive data."
    })

# ================= XXE =================
    if re.search(r'xml\.etree|lxml', code):
        issues.append({
        "type": "XML External Entity (XXE)",
        "severity": "HIGH",
        "message": "XML parsing may allow external entities.",
        "fix": "Disable external entity processing."
    })

# ================= Insecure File Upload =================
    if re.search(r'upload|file\.save', code):
        issues.append({
        "type": "Insecure File Upload",
        "severity": "HIGH",
        "message": "File upload without validation.",
        "fix": "Validate file type and size."
    })

# ================= ReDoS =================
    if re.search(r'\(.*\+\)\+', code):
        issues.append({
        "type": "ReDoS",
        "severity": "MEDIUM",
        "message": "Potential catastrophic backtracking regex.",
        "fix": "Optimize regex patterns."
    })

    return issues
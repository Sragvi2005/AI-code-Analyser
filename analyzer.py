import re

def analyze_code(code):
    issues = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):

        # Buffer overflow (gets)
        if re.search(r'\bgets\s*\(', line):
            issues.append({
                "type": "Buffer Overflow",
                "line": i,
                "severity": "HIGH",
                "message": "Use of gets() is unsafe.",
                "fix": "Use fgets() instead."
            })

        # strcpy
        if re.search(r'\bstrcpy\s*\(', line):
            issues.append({
                "type": "Unsafe Function",
                "line": i,
                "severity": "HIGH",
                "message": "strcpy() can cause overflow.",
                "fix": "Use strncpy() instead."
            })

        # eval
        if re.search(r'\beval\s*\(', line):
            issues.append({
                "type": "Code Injection",
                "line": i,
                "severity": "HIGH",
                "message": "eval() can execute arbitrary code.",
                "fix": "Use ast.literal_eval()."
            })

        # SQL injection
        if re.search(r'SELECT.*\+', line, re.IGNORECASE):
            issues.append({
                "type": "SQL Injection",
                "line": i,
                "severity": "HIGH",
                "message": "Query built via string concatenation.",
                "fix": "Use parameterized queries."
            })

        # Path traversal
        if "../" in line:
            issues.append({
                "type": "Path Traversal",
                "line": i,
                "severity": "HIGH",
                "message": "Directory traversal detected.",
                "fix": "Sanitize file paths."
            })

        # Hardcoded password
        if re.search(r'password\s*=\s*["\'].*["\']', line):
            issues.append({
                "type": "Hardcoded Credential",
                "line": i,
                "severity": "HIGH",
                "message": "Hardcoded password found.",
                "fix": "Use environment variables."
            })

        # Sensitive logging
        if re.search(r'print\(.*(password|token)', line, re.IGNORECASE):
            issues.append({
                "type": "Sensitive Data Exposure",
                "line": i,
                "severity": "MEDIUM",
                "message": "Sensitive data printed.",
                "fix": "Remove or mask logs."
            })

    return issues

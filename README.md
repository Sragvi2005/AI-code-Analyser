# AI-code-Analyser
# 🔍 AI Code Vulnerability Analyzer

## 📌 Overview

The **AI Code Vulnerability Analyzer** is a static analysis tool designed to detect security vulnerabilities in source code using a combination of **rule-based pattern matching** and **context-aware analysis**.

This project aligns with the concept of **Digital Trust**, focusing on improving the reliability, security, and trustworthiness of software systems.

---

## 🎯 Objectives

* Detect common security vulnerabilities in code
* Provide actionable fixes for identified issues
* Simulate real-world static analysis tools (e.g., Bandit, Semgrep)
* Demonstrate understanding of secure coding practices

---

## 🧠 Key Features

### ✅ 1. Multi-Language Support

* Supports analysis for:

  * C / C++
  * Python
  * Basic Web (HTML/JS patterns)

---

### ✅ 2. Vulnerability Detection Categories

#### 🔐 Input & Injection Vulnerabilities

* SQL Injection
* Command Injection
* Code Injection
* XSS (Cross-Site Scripting)
* SSRF (Server-Side Request Forgery)
* XPath Injection

---

#### 🧱 Memory & System-Level Issues

* Buffer Overflow
* Unsafe Function Usage (`gets`, `strcpy`)
* Out-of-bounds access (basic detection)

---

#### 🔑 Security Misconfigurations

* Hardcoded Credentials
* Sensitive Data Exposure
* Insecure Logging

---

#### 📂 File & Path Vulnerabilities

* Path Traversal (`../`)
* File Inclusion
* Insecure File Uploads

---

#### 🔄 Advanced Vulnerabilities

* Insecure Deserialization
* Weak Cryptography (MD5, DES, RC4)
* XML External Entity (XXE)
* Open Redirect
* ReDoS (Regex DoS)

---

### ⚠️ Partially Supported / Heuristic-Based

* NoSQL Injection
* LDAP Injection
* Template Injection

---

### ❌ Not Fully Detectable via Static Analysis

* Authentication Bypass
* IDOR
* Race Conditions
* Use After Free
* Prototype Pollution

> These require dynamic/runtime or deeper semantic analysis.

---

## ⚙️ System Architecture

### Flow:

1. User inputs code via web interface
2. Code is sent to backend (Flask)
3. Analyzer processes code:

   * Pattern-based detection (Regex)
   * Context-based detection (Input → Usage tracking)
4. Issues are returned with:

   * Type
   * Severity (HIGH / MEDIUM / LOW)
   * Suggested Fix
5. Results displayed in UI

---

## 🏗 Tech Stack

| Component       | Technology                      |
| --------------- | ------------------------------- |
| Backend         | Python, Flask                   |
| Frontend        | HTML, CSS                       |
| Analysis Engine | Regex + Context-based logic     |
| Optional        | OpenAI API (future enhancement) |

---

## 🧩 Project Structure

```
ai-code-analyzer/
│
├── app.py              # Flask backend
├── analyzer.py         # Core vulnerability detection engine
├── templates/
│   └── index.html     # Frontend UI
├── test_code/         # Sample vulnerable code
└── README.md
```

---

## 🔍 Detection Approach

### 1. Rule-Based Analysis

Uses regex patterns to detect:

* Unsafe functions
* Injection patterns
* Known vulnerability signatures

### 2. Context-Based Analysis

Tracks:

* User input sources (`input()`, `cin`)
* Data flow into sensitive operations (`sleep`, `system`)

---

## 🧪 Example

### Input Code:

```cpp
char inLine[64];
cin >> inLine;
int i = atoi(inLine);
sleep(i);
```

### Output:

* ⚠️ Buffer Overflow Risk
* ⚠️ Unsafe Conversion
* ⚠️ Denial of Service Risk

---

## 🎨 Frontend Features

* Dark theme UI
* Code input editor
* Color-coded severity:

  * 🔴 High
  * 🟠 Medium
  * 🟢 Low
* Clean card-based result display

---

## 🚀 Future Enhancements

* 🔹 Line number detection
* 🔹 Risk scoring system (/10)
* 🔹 Downloadable reports (PDF/JSON)
* 🔹 AI-based explanations (LLM integration)
* 🔹 Custom rule engine (user-defined rules)
* 🔹 Syntax highlighting editor

---

## 🎯 Learning Outcomes

* Understanding of **secure coding practices**
* Hands-on experience with **static code analysis**
* Exposure to **Digital Trust and AI security concepts**
* Practical implementation of **security detection systems**

---

## 📌 Conclusion

This project demonstrates how **rule-based and context-aware techniques** can be combined to build a simplified static analysis tool. While not as advanced as industrial tools, it provides a strong foundation for understanding **software security and trustworthiness**.

---

## 👤 Author

**Sragvi Jaisimha**
B.Tech CSE, BMS College of Engineering

---

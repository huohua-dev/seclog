# seclog - Local Security Log Analyzer

A lightweight, privacy-focused security log analysis tool for detecting security threats in log files.

## Features

- **Multi-format Parsing**: JSON, CSV, Syslog, Apache/Nginx access logs
- **Rule Engine**: YAML-based rules with single-event matching and aggregation detection
- **Built-in Rules**: 19 security detection rules covering common attack patterns
- **Analysis Engine**: Real-time log analysis and alert generation
- **Reporting**: Terminal colored output + Markdown report export with ASCII charts
- **CLI Interface**: Full-featured command-line interface

## Installation

```bash
pip install -e .
```

## Usage

### 1. Generate Sample Data

```bash
# Generate 100 Apache-style log samples
seclog generate-sample --format apache --count 100

# Output to file
seclog generate-sample --format apache --count 100 -o sample.log
```

**Sample Output:**
```
185.220.101.35 - - [09/Feb/2026:12:03:00 +0800] "POST /wp-login.php HTTP/1.1" 500 2399
192.168.1.101 - - [09/Feb/2026:19:11:00 +0800] "GET /blog/post-1 HTTP/1.1" 302 5881
185.220.101.35 - - [09/Feb/2026:02:17:00 +0800] "GET /js/app.js HTTP/1.1" 301 5090
203.0.113.45 - - [09/Feb/2026:22:06:00 +0800] "GET /api/search HTTP/1.1" 204 9775
...
```

### 2. Scan Logs

```bash
# Basic scan
seclog scan sample.log

# Filter by severity (critical/high/medium/low)
seclog scan sample.log --severity high
```

**Sample Output:**
```
============================================================
  SECURITY LOG ANALYSIS REPORT
============================================================

SUMMARY
----------------------------------------
Total Logs Processed: 100
Total Alerts: 120

ALERTS BY SEVERITY
----------------------------------------
CRITICAL   | 73    ██████████████████████████████████████████████████
HIGH       | 9     ████████
MEDIUM     | 38    ██████████████████████████

TOP ATTACKING SOURCE IPs
----------------------------------------
 1. 185.220.101.35       |    30 alerts
 2. 192.0.2.8            |    22 alerts
 3. 198.51.100.12        |    20 alerts
```

### 3. Parse Logs

```bash
# Parse and output as JSON
seclog parse sample.log --output parsed.json
```

**Sample Output:**
```json
[
  {
    "timestamp": "2026-02-09T10:57:05.822110",
    "source_ip": "192.168.1.100",
    "action": "GET",
    "severity": "info",
    "path": "/about",
    "status": 204,
    "user_agent": "Mozilla/5.0..."
  }
]
```

### 4. Rule Management

```bash
# List all built-in rules
seclog rules list
```

**Sample Output:**
```
Loaded Rules:
------------------------------------------------------------

Name: ssh_brute_force
  Description: SSH brute force attack detected
  Severity: critical
  Type: aggregate
  Pattern: Failed password for.*from
  Threshold: 5 in 5 minutes

Name: sql_injection_union_select
  Description: SQL injection attempt (UNION SELECT)
  Severity: critical
  Type: single
  Pattern: (?i)union\s+(?:all\s+)?select
```

### 5. Generate Markdown Report

```bash
seclog report sample.log --output report.md
```

**Report Contents:**
- Total logs processed, alert count statistics
- Distribution by severity level
- Top 10 attacking source IPs
- Alert time distribution (ASCII bar chart)
- Rule hit statistics
- Detailed alert list

## Built-in Detection Rules

| Rule | Type | Severity |
|------|------|----------|
| SSH Brute Force | Aggregate | critical |
| SQL Injection (UNION SELECT) | Single | critical |
| SQL Injection (OR 1=1) | Single | critical |
| Directory Traversal | Single | high |
| 403 Aggregation | Aggregate | medium |
| 404 Aggregation | Aggregate | medium |
| sqlmap User-Agent | Single | critical |
| nikto User-Agent | Single | high |
| nmap User-Agent | Single | medium |
| Command Injection | Single | critical |
| Large File Upload | Single | medium |
| /admin Access | Single | medium |
| /wp-login.php | Single | high |
| /.env Access | Single | critical |
| /api/debug | Single | high |
| Off-hours (2-5 AM) | Single | low |
| XSS <script> | Single | high |
| XSS javascript: | Single | high |

## Project Structure

```
seclog/
├── seclog/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── parser.py           # Multi-format log parser
│   ├── models.py           # Data models (LogEntry, Alert, etc.)
│   ├── rules.py            # Rule engine
│   ├── analyzer.py         # Analysis engine
│   ├── reporter.py         # Report generator
│   ├── sample_generator.py # Sample data generator
│   └── rules.yaml          # Built-in rules
└── tests/
    ├── __init__.py
    ├── test_parser.py
    ├── test_rules.py
    ├── test_analyzer.py
    └── test_reporter.py
```

## Requirements

- Python 3.8+
- PyYAML (optional, falls back to JSON)

## License

MIT

---

**中文文档**: [README_CN.md](README_CN.md)

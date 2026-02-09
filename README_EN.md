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
cd projects/seclog
pip install -e .
```

## Usage

### Scan Logs

```bash
# Basic scan
seclog scan <logfile>

# Filter by severity
seclog scan <logfile> --severity high

# Export Markdown report
seclog scan <logfile> --format markdown -o report.md
```

### Parse Logs

```bash
seclog parse <logfile> --output parsed.json
```

### Rule Management

```bash
# List built-in rules
seclog rules list

# Validate custom rules
seclog rules validate <rules.yaml>
```

### Generate Reports

```bash
seclog report <logfile> --output report.md
```

### Generate Sample Data

```bash
# Generate 1000 Apache-style logs
seclog generate-sample --format apache --count 1000

# Output to file
seclog generate-sample --format syslog --count 500 -o sample.log
```

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

**中文版文档**: [README_CN.md](README_CN.md)

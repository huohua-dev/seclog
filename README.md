# seclog - 本地安全日志分析工具

本地安全日志分析工具，支持多格式日志解析、规则检测、告警生成和报告导出。

## 功能特性

- **多格式日志解析**：支持 JSON、CSV、Syslog、Apache/Nginx access log
- **规则引擎**：YAML 规则定义，支持单事件匹配和聚合检测
- **内置规则集**：19 条安全检测规则
- **分析引擎**：实时日志分析和告警生成
- **报告生成**：终端彩色输出 + Markdown 报告导出
- **CLI 接口**：丰富的命令行操作

## 安装

```bash
pip install -e .
```

## 使用方法

### 1. 生成测试数据

```bash
# 生成 100 条 Apache 格式日志样本
seclog generate-sample --format apache --count 100

# 输出到文件
seclog generate-sample --format apache --count 100 -o sample.log
```

**示例输出：**
```
185.220.101.35 - - [09/Feb/2026:12:03:00 +0800] "POST /wp-login.php HTTP/1.1" 500 2399
192.168.1.101 - - [09/Feb/2026:19:11:00 +0800] "GET /blog/post-1 HTTP/1.1" 302 5881
185.220.101.35 - - [09/Feb/2026:02:17:00 +0800] "GET /js/app.js HTTP/1.1" 301 5090
203.0.113.45 - - [09/Feb/2026:22:06:00 +0800] "GET /api/search HTTP/1.1" 204 9775
...
```

### 2. 扫描日志

```bash
# 基础扫描
seclog scan sample.log

# 按严重级别过滤（critical/high/medium/low）
seclog scan sample.log --severity high
```

**示例输出：**
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

### 3. 解析日志

```bash
# 解析并输出为 JSON
seclog parse sample.log --output parsed.json
```

**示例输出：**
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

### 4. 规则管理

```bash
# 列出所有内置规则
seclog rules list
```

**示例输出：**
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

### 5. 生成 Markdown 报告

```bash
seclog report sample.log --output report.md
```

**报告内容：**
- 总日志数、告警数统计
- 按严重级别分布
- Top 10 攻击源 IP
- 告警时间分布（ASCII 图表）
- 规则命中统计
- 详细告警列表

## 内置检测规则

| 规则 | 类型 | 严重级别 |
|------|------|----------|
| SSH 暴力破解 | 聚合 | critical |
| SQL 注入 (UNION SELECT) | 单事件 | critical |
| SQL 注入 (OR 1=1) | 单事件 | critical |
| 目录遍历 | 单事件 | high |
| 403 聚合检测 | 聚合 | medium |
| 404 聚合检测 | 聚合 | medium |
| sqlmap User-Agent | 单事件 | critical |
| nikto User-Agent | 单事件 | high |
| nmap User-Agent | 单事件 | medium |
| 命令注入 | 单事件 | critical |
| 大文件上传 | 单事件 | medium |
| /admin 访问 | 单事件 | medium |
| /wp-login.php | 单事件 | high |
| /.env 访问 | 单事件 | critical |
| /api/debug | 单事件 | high |
| 非工作时间 (2-5点) | 单事件 | low |
| XSS <script> | 单事件 | high |
| XSS javascript: | 单事件 | high |

## 项目结构

```
seclog/
├── seclog/
│   ├── __init__.py
│   ├── cli.py              # CLI 入口
│   ├── parser.py           # 日志解析器
│   ├── models.py           # 数据模型（LogEntry, Alert 等）
│   ├── rules.py            # 规则引擎
│   ├── analyzer.py         # 分析引擎
│   ├── reporter.py         # 报告生成器
│   ├── sample_generator.py # 测试数据生成器
│   └── rules.yaml          # 内置规则集
└── tests/
    ├── __init__.py
    ├── test_parser.py
    ├── test_rules.py
    ├── test_analyzer.py
    └── test_reporter.py
```

## 要求

- Python 3.8+
- PyYAML（可选，无则使用 JSON 格式）

## 许可证

MIT

---

**English Documentation**: [README_EN.md](README_EN.md)

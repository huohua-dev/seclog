# seclog - 本地安全日志分析工具

本地安全日志分析工具，支持多格式日志解析、规则检测、告警生成和报告导出。

## 功能特性

- **多格式日志解析**：支持 JSON、CSV、Syslog、Apache/Nginx access log
- **规则引擎**：YAML 规则定义，支持单事件匹配和聚合检测
- **内置规则集**：10+ 条安全检测规则
- **分析引擎**：实时日志分析和告警生成
- **报告生成**：终端彩色输出 + Markdown 报告导出
- **CLI 接口**：丰富的命令行操作

## 安装

```bash
pip install -e .
```

## 使用方法

### 扫描日志

```bash
seclog scan <logfile> [--rules rules.yaml] [--severity high] [--format markdown]
```

### 解析日志

```bash
seclog parse <logfile> [--output parsed.json]
```

### 规则管理

```bash
seclog rules list
seclog rules validate <rules.yaml>
```

### 生成报告

```bash
seclog report <logfile> [--output report.md]
```

### 生成测试数据

```bash
seclog generate-sample --format apache --count 1000
```

## 项目结构

```
seclog/
├── __init__.py
├── cli.py              # CLI 入口
├── parser.py           # 日志解析器
├── models.py           # 数据模型（LogEntry, Alert 等）
├── rules.py            # 规则引擎
├── analyzer.py         # 分析引擎
├── reporter.py         # 报告生成器
├── sample_generator.py # 测试数据生成器
├── rules.yaml          # 内置规则集
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

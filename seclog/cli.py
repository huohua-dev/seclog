#!/usr/bin/env python3
"""
seclog - Local Security Log Analyzer

Usage:
    seclog scan <logfile> [--rules RULES] [--severity LEVEL] [--format FORMAT]
    seclog parse <logfile> [--output OUTPUT]
    seclog rules list
    seclog rules validate <rules.yaml>
    seclog report <logfile> [--output OUTPUT]
    seclog generate-sample [--format FORMAT] [--count N] [--output FILE]
    seclog (-h | --help)
    seclog --version
"""

import argparse
import sys
from typing import List, Optional

from . import __version__
from .analyzer import SecurityAnalyzer
from .models import Severity
from .parser import parse_file
from .reporter import ReportGenerator, print_result_terminal
from .rules import RuleEngine, load_default_rules
from .sample_generator import generate_sample_logs


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="seclog",
        description="Local Security Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"seclog {__version__}")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan log file for security threats")
    scan_parser.add_argument("logfile", help="Path to log file to analyze")
    scan_parser.add_argument("--rules", "-r", help="Path to custom rules file (YAML/JSON)")
    scan_parser.add_argument(
        "--severity", "-s",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity level to report",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["terminal", "markdown"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Output file for markdown report",
    )
    
    # parse command
    parse_parser = subparsers.add_parser("parse", help="Parse log file and output as JSON")
    parse_parser.add_argument("logfile", help="Path to log file to parse")
    parse_parser.add_argument(
        "--output", "-o",
        help="Output file for parsed JSON (default: stdout)",
    )
    
    # rules command
    rules_parser = subparsers.add_parser("rules", help="Rule management commands")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", help="Rules subcommands")
    
    rules_list_parser = rules_subparsers.add_parser("list", help="List all loaded rules")
    
    rules_validate_parser = rules_subparsers.add_parser("validate", help="Validate rules file")
    rules_validate_parser.add_argument("rulesfile", help="Path to rules file (YAML/JSON)")
    
    # report command
    report_parser = subparsers.add_parser("report", help="Generate analysis report")
    report_parser.add_argument("logfile", help="Path to log file to analyze")
    report_parser.add_argument(
        "--output", "-o",
        help="Output file for markdown report",
    )
    
    # generate-sample command
    sample_parser = subparsers.add_parser(
        "generate-sample",
        help="Generate sample logs for testing",
    )
    sample_parser.add_argument(
        "--format", "-f",
        choices=["apache", "syslog", "json"],
        default="apache",
        help="Log format (default: apache)",
    )
    sample_parser.add_argument(
        "--count", "-n",
        type=int,
        default=1000,
        help="Number of log lines to generate (default: 1000)",
    )
    sample_parser.add_argument(
        "--output", "-o",
        help="Output file (default: stdout)",
    )
    
    return parser


def cmd_scan(args):
    """Handle scan command."""
    # Load rules
    if args.rules:
        engine = RuleEngine()
        errors = engine.load_rules(args.rules)
        if errors:
            for err in errors:
                print(f"ERROR: {err}", file=sys.stderr)
            sys.exit(1)
        analyzer = SecurityAnalyzer(engine.rules)
    else:
        analyzer = SecurityAnalyzer.with_default_rules()
    
    # Severity filter
    severity_filter = None
    if args.severity:
        severity_order = ["critical", "high", "medium", "low"]
        idx = severity_order.index(args.severity)
        severity_filter = severity_order[idx:]
    
    # Analyze
    try:
        result = analyzer.analyze_file(args.logfile, severity_filter)
    except FileNotFoundError:
        print(f"ERROR: File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to analyze file: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Output
    if args.format == "markdown" or args.output:
        report = ReportGenerator(result).generate_markdown(args.output)
        if not args.output:
            print(report)
    else:
        print_result_terminal(result)


def cmd_parse(args):
    """Handle parse command."""
    try:
        entries = parse_file(args.logfile)
    except FileNotFoundError:
        print(f"ERROR: File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to parse file: {e}", file=sys.stderr)
        sys.exit(1)
    
    import json
    output_data = [e.to_dict() for e in entries]
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
    else:
        print(json.dumps(output_data, indent=2, default=str))


def cmd_rules_list(args):
    """Handle rules list command."""
    analyzer = SecurityAnalyzer.with_default_rules()
    
    print("Loaded Rules:")
    print("-" * 60)
    for rule in analyzer.engine.rules:
        print(f"\nName: {rule.name}")
        print(f"  Description: {rule.description}")
        print(f"  Severity: {rule.severity}")
        print(f"  Type: {rule.type}")
        if rule.pattern:
            print(f"  Pattern: {rule.pattern[:50]}..." if len(rule.pattern) > 50 else f"  Pattern: {rule.pattern}")
        if rule.threshold:
            print(f"  Threshold: {rule.threshold} in {rule.timewindow} minutes")


def cmd_rules_validate(args):
    """Handle rules validate command."""
    engine = RuleEngine()
    is_valid, errors = engine.validate_rules(args.rulesfile)
    
    if is_valid:
        print(f"✓ Rules file '{args.rulesfile}' is valid")
    else:
        print(f"✗ Rules file '{args.rulesfile}' has errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)


def cmd_report(args):
    """Handle report command."""
    analyzer = SecurityAnalyzer.with_default_rules()
    
    try:
        result = analyzer.analyze_file(args.logfile)
    except FileNotFoundError:
        print(f"ERROR: File not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to analyze file: {e}", file=sys.stderr)
        sys.exit(1)
    
    report = ReportGenerator(result).generate_markdown(args.output)
    if not args.output:
        print(report)


def cmd_generate_sample(args):
    """Handle generate-sample command."""
    import io
    
    if args.output:
        with open(args.output, 'w') as f:
            generate_sample_logs(
                count=args.count,
                format=args.format,
                output=f,
            )
    else:
        generate_sample_logs(
            count=args.count,
            format=args.format,
            output=sys.stdout,
        )


def main():
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Route to appropriate handler
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "parse":
        cmd_parse(args)
    elif args.command == "rules":
        if args.rules_command == "list":
            cmd_rules_list(args)
        elif args.rules_command == "validate":
            cmd_rules_validate(args)
        else:
            parser.parse_args(["rules", "--help"])
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "generate-sample":
        cmd_generate_sample(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

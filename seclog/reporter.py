"""
Report generator for security analysis results.
"""

from datetime import datetime
from typing import Dict, List, Optional, TextIO

from .models import Alert, AnalysisResult, Severity

# ANSI color codes
COLORS = {
    "critical": "\033[91m",  # Red
    "high": "\033[93m",      # Orange/Yellow
    "medium": "\033[94m",    # Blue
    "low": "\033[96m",       # Cyan
    "info": "\033[0m",       # Default
    "reset": "\033[0m",
    "bold": "\033[1m",
}

# Severity order for display
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def colorize(text: str, color: str, file: Optional[TextIO] = None) -> str:
    """Add ANSI color to text if output is a TTY."""
    if file and hasattr(file, "isatty") and not file.isatty():
        return text
    return f"{COLORS.get(color, COLORS['reset'])}{text}{COLORS['reset']}"


def severity_color(severity: str) -> str:
    """Get color for severity level."""
    return COLORS.get(severity.lower(), COLORS['reset'])


class ReportGenerator:
    """Generator for security analysis reports."""
    
    def __init__(self, result: AnalysisResult):
        self.result = result
    
    def print_terminal(self, file: Optional[TextIO] = None):
        """Print colored report to terminal."""
        if file is None:
            import sys
            file = sys.stdout
        
        # Header
        print(colorize("=" * 60, "bold"), file=file)
        print(colorize("  SECURITY LOG ANALYSIS REPORT", "bold"), file=file)
        print(colorize("=" * 60, "bold"), file=file)
        print(file=file)
        
        # Summary
        self._print_summary(file)
        print(file=file)
        
        # Severity distribution
        self._print_severity_distribution(file)
        print(file=file)
        
        # Top attacking IPs
        self._print_top_ips(file)
        print(file=file)
        
        # Time distribution
        self._print_time_distribution(file)
        print(file=file)
        
        # Rule statistics
        self._print_rule_stats(file)
        print(file=file)
        
        # Alert details
        self._print_alerts(file)
    
    def _print_summary(self, file: Optional[TextIO] = None):
        """Print summary statistics."""
        print(colorize("SUMMARY", "bold", file=file))
        print("-" * 40, file=file)
        print(f"Total Logs Processed: {self.result.total_logs}", file=file)
        print(f"Total Alerts: {len(self.result.alerts)}", file=file)
    
    def _print_severity_distribution(self, file: Optional[TextIO] = None):
        """Print severity distribution."""
        print(colorize("ALERTS BY SEVERITY", "bold", file=file))
        print("-" * 40, file=file)
        counts = self.result.count_by_severity()
        for severity in ["critical", "high", "medium", "low"]:
            count = counts.get(severity, 0)
            bar = "█" * min(count, 50)
            print(
                f"{colorize(severity.upper(), severity, file=file):10} | "
                f"{colorize(str(count), severity, file=file):5} {bar}",
                file=file,
            )
    
    def _print_top_ips(self, file: Optional[TextIO] = None):
        """Print top attacking source IPs."""
        print(colorize("TOP ATTACKING SOURCE IPs", "bold", file=file))
        print("-" * 40, file=file)
        top_ips = self.result.top_source_ips(10)
        for i, (ip, count) in enumerate(top_ips, 1):
            print(f"{i:2}. {ip:20} | {count:5} alerts", file=file)
    
    def _print_time_distribution(self, file: Optional[TextIO] = None):
        """Print alert time distribution."""
        print(colorize("ALERT TIME DISTRIBUTION (24h)", "bold", file=file))
        print("-" * 40, file=file)
        hourly = self.result.alerts_by_hour()
        max_count = max(hourly.values()) if hourly else 1
        
        for hour in range(24):
            count = hourly.get(hour, 0)
            bar_len = int(count / max_count * 20) if max_count > 0 else 0
            bar = "█" * bar_len
            time_str = f"{hour:02d}:00"
            print(f"{time_str} | {bar} {count}", file=file)
    
    def _print_rule_stats(self, file: Optional[TextIO] = None):
        """Print rule hit statistics."""
        print(colorize("RULE HIT STATISTICS", "bold", file=file))
        print("-" * 40, file=file)
        stats = self.result.rule_hit_stats()
        for rule, count in list(stats.items())[:10]:
            print(f"  {rule:40} | {count:5}", file=file)
    
    def _print_alerts(self, file: Optional[TextIO] = None):
        """Print alert details."""
        if not self.result.alerts:
            print(colorize("No alerts detected.", "info", file=file))
            return
        
        print(colorize("DETECTED ALERTS", "bold", file=file))
        print("-" * 60, file=file)
        
        # Sort by severity and time
        sorted_alerts = sorted(
            self.result.alerts,
            key=lambda a: (SEVERITY_ORDER.index(a.severity) if a.severity in SEVERITY_ORDER else 5, a.timestamp),
        )
        
        for alert in sorted_alerts[:50]:  # Limit to 50 for display
            print(
                f"{colorize(alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'info', file=file)} | "
                f"{colorize(alert.source_ip, 'info', file=file):18} | "
                f"{colorize(alert.severity.upper(), alert.severity, file=file):8} | "
                f"{alert.rule_name}",
                file=file
            )
        
        if len(sorted_alerts) > 50:
            print(f"... and {len(sorted_alerts) - 50} more alerts", file=file)
    
    def generate_markdown(self, output_path: Optional[str] = None) -> str:
        """Generate Markdown report."""
        lines = []
        
        # Title
        lines.append("# Security Log Analysis Report")
        lines.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Summary
        lines.append("## Summary")
        lines.append("-" * 40)
        lines.append(f"- **Total Logs Processed:** {self.result.total_logs}")
        lines.append(f"- **Total Alerts:** {len(self.result.alerts)}\n")
        
        # Severity distribution
        lines.append("## Alerts by Severity")
        lines.append("-" * 40)
        counts = self.result.count_by_severity()
        for severity in ["critical", "high", "medium", "low"]:
            count = counts.get(severity, 0)
            bar = "█" * min(count, 50)
            lines.append(f"- **{severity.upper()}:** {count} {bar}")
        lines.append("")
        
        # Top IPs
        lines.append("## Top Attacking Source IPs")
        lines.append("-" * 40)
        lines.append("| Rank | IP Address | Alert Count |")
        lines.append("|------|------------|-------------|")
        top_ips = self.result.top_source_ips(10)
        for i, (ip, count) in enumerate(top_ips, 1):
            lines.append(f"| {i} | {ip} | {count} |")
        lines.append("")
        
        # Time distribution (ASCII chart)
        lines.append("## Alert Time Distribution (24h)")
        lines.append("-" * 40)
        lines.append("```")
        hourly = self.result.alerts_by_hour()
        max_count = max(hourly.values()) if hourly else 1
        
        for hour in range(24):
            count = hourly.get(hour, 0)
            bar_len = int(count / max_count * 30) if max_count > 0 else 0
            bar = "█" * bar_len
            lines.append(f"{hour:02d}:00 |{bar} {count}")
        lines.append("```\n")
        
        # Rule statistics
        lines.append("## Rule Hit Statistics")
        lines.append("-" * 40)
        lines.append("| Rule | Hit Count |")
        lines.append("|------|-----------|")
        stats = self.result.rule_hit_stats()
        for rule, count in stats.items():
            lines.append(f"| {rule} | {count} |")
        lines.append("")
        
        # Alert details
        lines.append("## Detected Alerts")
        lines.append("-" * 40)
        
        if not self.result.alerts:
            lines.append("*No alerts detected.*\n")
        else:
            # Sort by severity
            sorted_alerts = sorted(
                self.result.alerts,
                key=lambda a: (SEVERITY_ORDER.index(a.severity) if a.severity in SEVERITY_ORDER else 5, a.timestamp),
            )
            
            for alert in sorted_alerts:
                lines.append(f"### {alert.rule_name}")
                lines.append(f"- **Severity:** {alert.severity.upper()}")
                lines.append(f"- **Time:** {alert.timestamp.isoformat()}")
                lines.append(f"- **Source IP:** {alert.source_ip}")
                lines.append(f"- **Description:** {alert.description}")
                lines.append(f"- **Matched Log:** `{alert.matched_log[:200]}`")
                lines.append("")
        
        report = "\n".join(lines)
        
        if output_path:
            with open(output_path, 'w') as f:
                f.write(report)
        
        return report


def print_result_terminal(result: AnalysisResult, file: Optional[TextIO] = None):
    """Convenience function to print analysis result to terminal."""
    generator = ReportGenerator(result)
    generator.print_terminal(file)


def generate_markdown_report(result: AnalysisResult, output_path: Optional[str] = None) -> str:
    """Convenience function to generate Markdown report."""
    generator = ReportGenerator(result)
    return generator.generate_markdown(output_path)

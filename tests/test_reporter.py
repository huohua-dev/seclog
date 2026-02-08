"""
Unit tests for reporter module.
"""

import unittest
from datetime import datetime

from seclog.reporter import ReportGenerator, print_result_terminal, generate_markdown_report
from seclog.models import AnalysisResult, Alert


class TestReporter(unittest.TestCase):
    """Test cases for reporter module."""
    
    def setUp(self):
        """Set up test fixtures."""
        now = datetime.now()
        self.sample_alerts = [
            Alert(
                rule_name="sql_injection",
                severity="critical",
                timestamp=now,
                source_ip="192.168.1.100",
                matched_log='192.168.1.100 - - [09/Feb/2026:12:00:00] "GET /api?id=1 UNION SELECT"',
                description="SQL injection attempt",
            ),
            Alert(
                rule_name="xss_attempt",
                severity="high",
                timestamp=now,
                source_ip="10.0.0.50",
                matched_log='192.168.1.100 - - [09/Feb/2026:12:01:00] "GET /search?q=<script>"',
                description="XSS attempt",
            ),
            Alert(
                rule_name="directory_traversal",
                severity="high",
                timestamp=now,
                source_ip="192.168.1.100",
                matched_log='192.168.1.100 - - [09/Feb/2026:12:02:00] "GET /../../etc/passwd"',
                description="Directory traversal attempt",
            ),
        ]
        self.result = AnalysisResult(
            total_logs=1000,
            alerts=self.sample_alerts,
        )
    
    def test_generate_markdown_basic(self):
        """Test basic Markdown report generation."""
        report = ReportGenerator(self.result).generate_markdown()
        
        self.assertIn("# Security Log Analysis Report", report)
        self.assertIn("Total Logs Processed", report)
        self.assertIn("**Total Alerts:** 3", report)
    
    def test_generate_markdown_alerts_section(self):
        """Test alerts section in Markdown report."""
        report = ReportGenerator(self.result).generate_markdown()
        
        self.assertIn("## Detected Alerts", report)
        self.assertIn("sql_injection", report)
        self.assertIn("xss_attempt", report)
    
    def test_generate_markdown_with_output_file(self):
        """Test Markdown report generation to file."""
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            output_path = f.name
        
        try:
            ReportGenerator(self.result).generate_markdown(output_path)
            
            with open(output_path, 'r') as f:
                content = f.read()
            
            self.assertIn("# Security Log Analysis Report", content)
            self.assertIn("sql_injection", content)
        finally:
            os.unlink(output_path)
    
    def test_generate_markdown_empty_result(self):
        """Test Markdown report with no alerts."""
        empty_result = AnalysisResult(total_logs=100, alerts=[])
        report = ReportGenerator(empty_result).generate_markdown()
        
        self.assertIn("No alerts detected", report)
    
    def test_count_by_severity_integration(self):
        """Test severity count integration with reporter."""
        # This tests that AnalysisResult methods work correctly with reporter
        counts = self.result.count_by_severity()
        self.assertEqual(counts.get("critical", 0), 1)
        self.assertEqual(counts.get("high", 0), 2)
    
    def test_top_source_ips_integration(self):
        """Test top source IPs integration with reporter."""
        top_ips = self.result.top_source_ips(10)
        self.assertEqual(len(top_ips), 2)
        self.assertEqual(top_ips[0][0], "192.168.1.100")
        self.assertEqual(top_ips[0][1], 2)  # 2 alerts
    
    def test_alerts_by_hour_integration(self):
        """Test alerts by hour integration with reporter."""
        hourly = self.result.alerts_by_hour()
        now_hour = datetime.now().hour
        self.assertEqual(hourly.get(now_hour, 0), 3)
    
    def test_rule_hit_stats_integration(self):
        """Test rule hit stats integration with reporter."""
        stats = self.result.rule_hit_stats()
        self.assertEqual(stats['sql_injection'], 1)
        self.assertEqual(stats['xss_attempt'], 1)
        self.assertEqual(stats['directory_traversal'], 1)
    
    def test_print_terminal_output(self):
        """Test terminal output doesn't raise errors."""
        import io
        output = io.StringIO()
        
        # Should not raise
        print_result_terminal(self.result, output)
        
        content = output.getvalue()
        self.assertIn("SECURITY LOG ANALYSIS REPORT", content)
        self.assertIn("Total Logs Processed", content)
    
    def test_markdown_rule_section(self):
        """Test rule statistics section in Markdown."""
        report = ReportGenerator(self.result).generate_markdown()
        
        self.assertIn("## Rule Hit Statistics", report)
        self.assertIn("sql_injection", report)
    
    def test_markdown_time_distribution(self):
        """Test time distribution section in Markdown."""
        report = ReportGenerator(self.result).generate_markdown()
        
        self.assertIn("## Alert Time Distribution", report)
        self.assertIn("```", report)  # ASCII chart uses code block


if __name__ == "__main__":
    unittest.main()

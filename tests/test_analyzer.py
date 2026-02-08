"""
Unit tests for analyzer module.
"""

import unittest
from datetime import datetime

from seclog.analyzer import SecurityAnalyzer
from seclog.models import LogEntry, AnalysisResult


class TestAnalyzer(unittest.TestCase):
    """Test cases for analyzer module."""
    
    def test_analyze_empty_logs(self):
        """Test analyzing empty log list."""
        analyzer = SecurityAnalyzer.with_default_rules()
        result = analyzer.analyze_entries([])
        self.assertEqual(result.total_logs, 0)
        self.assertEqual(len(result.alerts), 0)
    
    def test_analyze_normal_logs_no_alerts(self):
        """Test normal logs generate no alerts."""
        normal_lines = [
            '192.168.1.1 - - [09/Feb/2026:12:00:00 +0800] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
            '192.168.1.2 - - [09/Feb/2026:12:01:00 +0800] "GET /css/style.css HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        ]
        analyzer = SecurityAnalyzer.with_default_rules()
        result = analyzer.analyze_lines(normal_lines)
        # Should have minimal alerts (only off-hours if applicable)
        self.assertEqual(result.total_logs, 2)
    
    def test_analyze_sql_injection_alert(self):
        """Test SQL injection detection."""
        attack_lines = [
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET /api/users?id=1 UNION SELECT * FROM users HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        ]
        analyzer = SecurityAnalyzer.with_default_rules()
        result = analyzer.analyze_lines(attack_lines)
        
        alert_names = [a.rule_name for a in result.alerts]
        self.assertIn("sql_injection_union_select", alert_names)
    
    def test_analyze_xss_alert(self):
        """Test XSS detection."""
        attack_lines = [
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        ]
        analyzer = SecurityAnalyzer.with_default_rules()
        result = analyzer.analyze_lines(attack_lines)
        
        alert_names = [a.rule_name for a in result.alerts]
        self.assertIn("xss_script_tag", alert_names)
    
    def test_analyze_directory_traversal_alert(self):
        """Test directory traversal detection."""
        attack_lines = [
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET /files/../../../etc/passwd HTTP/1.1" 404 512 "-" "Mozilla/5.0"',
        ]
        analyzer = SecurityAnalyzer.with_default_rules()
        result = analyzer.analyze_lines(attack_lines)
        
        alert_names = [a.rule_name for a in result.alerts]
        self.assertIn("directory_traversal", alert_names)
    
    def test_analyze_sensitive_path_alert(self):
        """Test sensitive path access detection."""
        attack_lines = [
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET /.env HTTP/1.1" 404 512 "-" "Mozilla/5.0"',
        ]
        analyzer = SecurityAnalyzer.with_default_rules()
        result = analyzer.analyze_lines(attack_lines)
        
        alert_names = [a.rule_name for a in result.alerts]
        self.assertIn("sensitive_path_env", alert_names)
    
    def test_analyze_scanner_useragent_alert(self):
        """Test suspicious User-Agent detection."""
        attack_lines = [
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET / HTTP/1.1" 200 512 "-" "sqlmap/1.4.7#stable"',
        ]
        analyzer = SecurityAnalyzer.with_default_rules()
        result = analyzer.analyze_lines(attack_lines)
        
        alert_names = [a.rule_name for a in result.alerts]
        self.assertIn("suspicious_useragent_sqlmap", alert_names)
    
    def test_severity_filter_critical(self):
        """Test severity filter (critical only)."""
        lines = [
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET /.env HTTP/1.1" 404 512 "-" "Mozilla/5.0"',  # critical
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET /admin HTTP/1.1" 403 512 "-" "Mozilla/5.0"',  # medium
        ]
        analyzer = SecurityAnalyzer.with_default_rules()
        result = analyzer.analyze_lines(lines, severity_filter=["critical"])
        
        self.assertEqual(len(result.alerts), 1)
        self.assertEqual(result.alerts[0].severity, "critical")
    
    def test_severity_filter_high_and_above(self):
        """Test severity filter (high and critical)."""
        lines = [
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET /.env HTTP/1.1" 404 512 "-" "Mozilla/5.0"',  # critical
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET /admin HTTP/1.1" 403 512 "-" "Mozilla/5.0"',  # medium
            '192.168.1.100 - - [09/Feb/2026:12:00:00 +0800] "GET /search?q=<script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"',  # high
        ]
        analyzer = SecurityAnalyzer.with_default_rules()
        result = analyzer.analyze_lines(lines, severity_filter=["critical", "high"])
        
        self.assertEqual(len(result.alerts), 2)
        severities = {a.severity for a in result.alerts}
        self.assertEqual(severities, {"critical", "high"})
    
    def test_count_by_severity(self):
        """Test severity count functionality."""
        result = AnalysisResult(
            total_logs=10,
            alerts=[
                type('Alert', (), {'severity': 'critical'})(),
                type('Alert', (), {'severity': 'critical'})(),
                type('Alert', (), {'severity': 'high'})(),
                type('Alert', (), {'severity': 'medium'})(),
            ]
        )
        counts = result.count_by_severity()
        self.assertEqual(counts.get("critical", 0), 2)
        self.assertEqual(counts.get("high", 0), 1)
        self.assertEqual(counts.get("medium", 0), 1)
    
    def test_top_source_ips(self):
        """Test top source IPs functionality."""
        now = datetime.now()
        alerts = [
            type('Alert', (), {'source_ip': '192.168.1.100'})(),
            type('Alert', (), {'source_ip': '192.168.1.100'})(),
            type('Alert', (), {'source_ip': '10.0.0.1'})(),
            type('Alert', (), {'source_ip': '172.16.0.1'})(),
        ]
        result = AnalysisResult(total_logs=10, alerts=alerts)
        
        top_ips = result.top_source_ips(2)
        self.assertEqual(len(top_ips), 2)
        self.assertEqual(top_ips[0], ('192.168.1.100', 2))
    
    def test_rule_hit_stats(self):
        """Test rule hit statistics."""
        alerts = [
            type('Alert', (), {'rule_name': 'sql_injection'})(),
            type('Alert', (), {'rule_name': 'sql_injection'})(),
            type('Alert', (), {'rule_name': 'xss'})(),
        ]
        result = AnalysisResult(total_logs=10, alerts=alerts)
        
        stats = result.rule_hit_stats()
        self.assertEqual(stats['sql_injection'], 2)
        self.assertEqual(stats['xss'], 1)
    
    def test_reset(self):
        """Test analyzer reset functionality."""
        analyzer = SecurityAnalyzer.with_default_rules()
        analyzer.reset()
        # Just verify it doesn't raise an error


if __name__ == "__main__":
    unittest.main()

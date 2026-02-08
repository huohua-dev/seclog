"""
Unit tests for parser module.
"""

import unittest
import tempfile
import os
from datetime import datetime

from seclog.parser import (
    parse_line,
    parse_file,
    parse_lines,
    parse_json,
    parse_csv,
    parse_syslog,
    parse_apache,
    detect_format,
)
from seclog.models import LogEntry


class TestParser(unittest.TestCase):
    """Test cases for log parser."""
    
    def test_parse_json_valid(self):
        """Test parsing valid JSON log."""
        line = '{"timestamp": "2026-02-09T02:00:00", "source_ip": "192.168.1.100", "action": "GET", "path": "/index.html"}'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "192.168.1.100")
        self.assertEqual(entry.action, "GET")
        self.assertEqual(entry.path, "/index.html")
    
    def test_parse_json_invalid(self):
        """Test parsing invalid JSON returns None."""
        line = 'not valid json'
        entry = parse_line(line)
        self.assertIsNone(entry)
    
    def test_parse_json_extra_fields(self):
        """Test parsing JSON with extra fields."""
        line = '{"timestamp": "2026-02-09T02:00:00", "source_ip": "10.0.0.1", "action": "POST", "user_id": 123, "org_id": 456}'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.extra.get("user_id"), 123)
        self.assertEqual(entry.extra.get("org_id"), 456)
    
    def test_detect_format_json(self):
        """Test format detection for JSON."""
        self.assertEqual(detect_format('{"key": "value"}'), "json")
    
    def test_detect_format_syslog(self):
        """Test format detection for Syslog."""
        self.assertEqual(detect_format("Feb  9 02:00:00 hostname process[123]: message"), "syslog")
    
    def test_detect_format_apache(self):
        """Test format detection for Apache/Nginx."""
        line = '192.168.1.1 - - [09/Feb/2026:02:00:00 +0800] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        self.assertEqual(detect_format(line), "apache")
    
    def test_detect_format_csv(self):
        """Test format detection for CSV (fallback)."""
        line = "2026-02-09T02:00:00,192.168.1.1,GET,/index.html"
        self.assertEqual(detect_format(line), "csv")
    
    def test_parse_apache_log(self):
        """Test parsing Apache/Nginx access log."""
        line = '192.168.1.100 - - [09/Feb/2026:02:00:00 +0800] "GET /admin HTTP/1.1" 403 512 "-" "Mozilla/5.0"'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "192.168.1.100")
        self.assertEqual(entry.path, "/admin")
        self.assertEqual(entry.status, 403)
        self.assertEqual(entry.action, "GET")
        self.assertIn("Mozilla", entry.user_agent)
    
    def test_parse_apache_with_referer(self):
        """Test parsing Apache log with referer."""
        line = '10.0.0.50 - - [09/Feb/2026:02:00:00 +0800] "POST /api/users HTTP/1.1" 201 123 "-" "Mozilla/5.0"'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.action, "POST")
        self.assertEqual(entry.status, 201)
    
    def test_parse_syslog_basic(self):
        """Test parsing basic Syslog."""
        line = "Feb  9 02:00:00 webserver sshd[1234]: Failed password for root from 192.168.1.1"
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "192.168.1.1")
        self.assertEqual(entry.action, "ssh")
    
    def test_parse_csv_basic(self):
        """Test parsing CSV format."""
        header = ["timestamp", "source_ip", "action", "path"]
        line = "2026-02-09T02:00:00,192.168.1.1,GET,/index.html"
        entry = parse_line(line, header=header)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "192.168.1.1")
        self.assertEqual(entry.action, "GET")
    
    def test_parse_empty_line(self):
        """Test parsing empty line returns None."""
        entry = parse_line("")
        self.assertIsNone(entry)
    
    def test_parse_whitespace_line(self):
        """Test parsing whitespace-only line returns None."""
        entry = parse_line("   \n\t  ")
        self.assertIsNone(entry)
    
    def test_parse_file(self):
        """Test parsing entire file."""
        content = '''{"timestamp": "2026-02-09T02:00:00", "source_ip": "192.168.1.1", "action": "GET", "path": "/a"}
{"timestamp": "2026-02-09T02:01:00", "source_ip": "192.168.1.2", "action": "POST", "path": "/b"}
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(content)
            f.flush()
            
            entries = parse_file(f.name)
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0].source_ip, "192.168.1.1")
            self.assertEqual(entries[1].source_ip, "192.168.1.2")
            
            os.unlink(f.name)
    
    def test_parse_file_with_csv_header(self):
        """Test parsing CSV file with header."""
        content = '''timestamp,source_ip,action,path
2026-02-09T02:00:00,192.168.1.1,GET,/a
2026-02-09T02:01:00,192.168.1.2,POST,/b
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(content)
            f.flush()
            
            entries = parse_file(f.name)
            self.assertEqual(len(entries), 2)
            
            os.unlink(f.name)
    
    def test_parse_lines(self):
        """Test parsing list of lines."""
        lines = [
            '{"timestamp": "2026-02-09T02:00:00", "source_ip": "10.0.0.1", "action": "GET", "path": "/x"}',
            '192.168.1.1 - - [09/Feb/2026:02:00:00 +0800] "GET /y HTTP/1.1" 200 100 "-" "Mozilla"',
        ]
        entries = parse_lines(lines)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].source_ip, "10.0.0.1")
        self.assertEqual(entries[1].source_ip, "192.168.1.1")


if __name__ == "__main__":
    unittest.main()

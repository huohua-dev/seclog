"""
Log parser for multiple formats.
"""

import csv
import json
import re
from datetime import datetime
from io import StringIO
from typing import Optional

from .models import LogEntry

# Syslog month patterns
SYSLOG_MONTH_PATTERN = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
)

# Apache/Nginx timestamp pattern
APACHE_TS_PATTERN = re.compile(
    r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4})\]'
)

# Common Apache/Nginx log format regex
# Combined log format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
APACHE_LOG_PATTERN = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d+)\s+(?P<size>\d+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_apache_timestamp(ts_str: str) -> datetime:
    """Parse Apache/Nginx timestamp to datetime."""
    # Format: 09/Feb/2026:02:00:00 +0800
    ts_str = ts_str.replace(":", " ", 1)  # Replace first : with space for strptime
    ts_str = ts_str.split()[0]  # Remove timezone for simplicity
    try:
        return datetime.strptime(ts_str, "%d/%b/%Y %H:%M:%S")
    except ValueError:
        return datetime.now()


def parse_syslog_timestamp(line: str) -> datetime:
    """Parse Syslog timestamp (RFC 3164 format)."""
    # Format: Feb  9 02:00:00
    now = datetime.now()
    # Handle both "Feb  9" and "Feb 09" formats
    match = re.match(r'^(\w+)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})', line)
    if match:
        month_str, day, hour, minute, second = match.groups()
        month_map = {
            "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
            "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
        }
        month = month_map.get(month_str, 1)
        try:
            return datetime(now.year, month, int(day), int(hour), int(minute), int(second))
        except ValueError:
            return now
    return now


def parse_json(line: str) -> Optional[LogEntry]:
    """Parse JSON format log."""
    try:
        data = json.loads(line.strip())
        return LogEntry(
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now().isoformat())),
            source_ip=data.get("source_ip", "0.0.0.0"),
            action=data.get("action", "unknown"),
            severity=data.get("severity", "info"),
            raw_message=line.strip(),
            path=data.get("path"),
            method=data.get("method"),
            status=data.get("status"),
            user_agent=data.get("user_agent"),
            extra={k: v for k, v in data.items() if k not in ["timestamp", "source_ip", "action", "severity", "path", "method", "status", "user_agent"]},
        )
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def parse_csv(line: str, header: Optional[list] = None) -> Optional[LogEntry]:
    """Parse CSV format log."""
    try:
        # Handle CSV parsing
        parts = line.strip().split(',')
        
        if header:
            # Use provided header fields
            fields = header
            values = parts
        else:
            # First part is header
            fields = parts
            return None  # First line is header, not data
        
        if len(values) < len(fields):
            # Not enough fields for CSV
            return None
        
        # Create dict from fields and values
        row = {}
        for i, field in enumerate(fields):
            if i < len(values):
                row[field] = values[i]
            else:
                row[field] = ""
        
        return LogEntry(
            timestamp=datetime.fromisoformat(row.get("timestamp", datetime.now().isoformat())),
            source_ip=row.get("source_ip", "0.0.0.0"),
            action=row.get("action", "unknown"),
            severity=row.get("severity", "info"),
            raw_message=line.strip(),
            path=row.get("path"),
            method=row.get("method"),
            status=int(row.get("status", 0)) if row.get("status") else None,
            user_agent=row.get("user_agent"),
            extra={k: v for k, v in row.items() if k not in ["timestamp", "source_ip", "action", "severity", "path", "method", "status", "user_agent"]},
        )
    except (csv.Error, ValueError, TypeError):
        return None


def parse_syslog(line: str) -> Optional[LogEntry]:
    """Parse Syslog format."""
    # Extract timestamp and message
    timestamp = parse_syslog_timestamp(line)
    
    # Try to extract process and message
    # Format: Feb  9 02:00:00 hostname process[pid]: message
    match = re.search(r'(\w+)\[(\d+)\]:\s*(.*)', line)
    if match:
        process = match.group(1)
        message = match.group(3)
    else:
        process = "unknown"
        message = line
    
    # Try to extract source IP from common SSH/WEB patterns
    ip_match = re.search(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})', message)
    ip = ip_match.group(1) if ip_match else "0.0.0.0"
    
    # Determine action from message content
    action = "unknown"
    if "sshd" in line.lower():
        action = "ssh"
    elif "http" in line.lower() or "apache" in line.lower() or "nginx" in line.lower():
        action = "http"
    
    return LogEntry(
        timestamp=timestamp,
        source_ip=ip,
        action=action,
        severity="info",
        raw_message=line.strip(),
    )


def parse_apache(line: str) -> Optional[LogEntry]:
    """Parse Apache/Nginx access log format."""
    match = APACHE_LOG_PATTERN.match(line)
    if match:
        groups = match.groupdict()
        request = groups.get("request", "")
        
        # Parse request line: "METHOD /path?query HTTP/x.x"
        req_match = re.match(r'(\w+)\s+(.+?)\s+HTTP/\d+\.\d+', request)
        method = req_match.group(1) if req_match else None
        # Extract path (without query string for cleaner matching)
        full_path = req_match.group(2) if req_match else None
        path = full_path.split('?')[0] if full_path else None
        
        return LogEntry(
            timestamp=parse_apache_timestamp(groups.get("timestamp", "")),
            source_ip=groups.get("ip", "0.0.0.0"),
            action=method or "unknown",
            severity="info",
            raw_message=line.strip(),
            path=path,
            status=int(groups.get("status", 0)) if groups.get("status") else None,
            user_agent=groups.get("ua"),
        )
    return None


def detect_format(line: str) -> str:
    """Detect log format from line."""
    stripped = line.strip()
    if stripped.startswith('{'):
        return "json"
    if SYSLOG_MONTH_PATTERN.match(stripped):
        return "syslog"
    if APACHE_TS_PATTERN.search(stripped):
        return "apache"
    # CSV is the fallback
    return "csv"


def parse_line(line: str, header: Optional[list] = None) -> Optional[LogEntry]:
    """Parse a single log line with auto-detection."""
    if not line.strip():
        return None
    
    format_type = detect_format(line)
    
    if format_type == "json":
        return parse_json(line)
    elif format_type == "syslog":
        return parse_syslog(line)
    elif format_type == "apache":
        return parse_apache(line)
    else:
        return parse_csv(line, header)


def parse_file(filepath: str) -> list[LogEntry]:
    """Parse entire log file."""
    entries = []
    header = None
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # For CSV, first line is header
            if header is None and detect_format(line) == "csv":
                header = line.split(',')
                continue
            
            entry = parse_line(line, header)
            if entry:
                entries.append(entry)
    
    return entries


def parse_lines(lines: list[str]) -> list[LogEntry]:
    """Parse list of log lines."""
    entries = []
    header = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # For CSV, first line is header
        if header is None and detect_format(line) == "csv":
            header = line.split(',')
            continue
        
        entry = parse_line(line, header)
        if entry:
            entries.append(entry)
    
    return entries

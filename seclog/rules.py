"""
Rule engine for security detection.
"""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Pattern, Set, Tuple

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from .models import LogEntry, Rule, Severity


class RuleEngine:
    """Engine for loading and executing security rules."""
    
    def __init__(self):
        self.rules: List[Rule] = []
        self.compiled_patterns: Dict[str, Tuple[Pattern, str]] = {}  # rule_name -> (compiled_pattern, field)
        # For aggregate rules: (rule_name, source_ip) -> List[timestamps]
        self.aggregate_state: Dict[Tuple[str, str], List[datetime]] = {}
    
    def load_rules(self, rules_source) -> List[str]:
        """
        Load rules from YAML file, JSON file, or list of dicts.
        Returns list of error messages.
        """
        errors = []
        raw_rules = []
        
        # Parse input
        if isinstance(rules_source, str):
            # File path
            if rules_source.endswith('.yaml') or rules_source.endswith('.yml'):
                if HAS_YAML:
                    with open(rules_source, 'r') as f:
                        raw_rules = yaml.safe_load(f) or []
                else:
                    errors.append("PyYAML not installed, cannot parse YAML files")
                    return errors
            else:
                # Assume JSON
                import json
                with open(rules_source, 'r') as f:
                    raw_rules = json.load(f) or []
        elif isinstance(rules_source, list):
            raw_rules = rules_source
        else:
            errors.append(f"Unknown rules source type: {type(rules_source)}")
            return errors
        
        # Convert to Rule objects
        self.rules = []
        for i, raw in enumerate(raw_rules):
            try:
                rule = Rule(
                    name=raw.get('name', f'rule_{i}'),
                    description=raw.get('description', ''),
                    severity=raw.get('severity', 'medium'),
                    type=raw.get('type', 'single'),
                    pattern=raw.get('pattern'),
                    field=raw.get('field', 'raw_message'),
                    threshold=raw.get('threshold'),
                    timewindow=raw.get('timewindow'),
                )
                
                # Validate rule
                rule_errors = rule.validate()
                if rule_errors:
                    errors.extend([f"Rule '{rule.name}': {e}" for e in rule_errors])
                    continue
                
                # Compile pattern
                if rule.pattern:
                    try:
                        compiled = re.compile(rule.pattern)
                        self.compiled_patterns[rule.name] = (compiled, rule.field)
                    except re.error as e:
                        errors.append(f"Rule '{rule.name}': Invalid regex pattern - {e}")
                        continue
                
                self.rules.append(rule)
            except Exception as e:
                errors.append(f"Rule {i}: {e}")
        
        return errors
    
    def list_rules(self) -> List[dict]:
        """List all loaded rules."""
        return [
            {
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "type": r.type,
                "pattern": r.pattern,
                "threshold": r.threshold,
                "timewindow": r.timewindow,
            }
            for r in self.rules
        ]
    
    def validate_rules(self, rules_source) -> Tuple[bool, List[str]]:
        """
        Validate rules without loading them into the engine.
        Returns (is_valid, errors).
        """
        engine = RuleEngine()
        errors = engine.load_rules(rules_source)
        return len(errors) == 0, errors
    
    def _check_single_match(self, rule: Rule, entry: LogEntry) -> bool:
        """Check if entry matches a single-event rule."""
        if rule.name not in self.compiled_patterns:
            return False
        
        compiled, field = self.compiled_patterns[rule.name]
        
        # Get field value to match against
        if field == "raw_message":
            value = entry.raw_message
        elif field == "path":
            value = entry.path or ""
        elif field == "user_agent":
            value = entry.user_agent or ""
        elif field == "action":
            value = entry.action
        else:
            value = getattr(entry, field, "") or ""
        
        return bool(compiled.search(value))
    
    def _check_aggregate_match(self, rule: Rule, entry: LogEntry) -> bool:
        """Check if entry triggers an aggregate rule."""
        if not rule.threshold or not rule.timewindow:
            return False
        
        key = (rule.name, entry.source_ip)
        now = entry.timestamp
        
        # Initialize if not exists
        if key not in self.aggregate_state:
            self.aggregate_state[key] = []
        
        # Clean up old entries outside the timewindow
        window_start = now - timedelta(minutes=rule.timewindow)
        self.aggregate_state[key] = [
            t for t in self.aggregate_state[key] if t >= window_start
        ]
        
        # Add current timestamp
        self.aggregate_state[key].append(now)
        
        # Check if threshold is met
        return len(self.aggregate_state[key]) >= rule.threshold
    
    def check_entry(self, entry: LogEntry) -> List[str]:
        """
        Check if entry matches any rules.
        Returns list of matching rule names.
        """
        matches = []
        
        for rule in self.rules:
            if rule.type == "single":
                if self._check_single_match(rule, entry):
                    matches.append(rule.name)
            elif rule.type == "aggregate":
                if self._check_aggregate_match(rule, entry):
                    matches.append(rule.name)
        
        return matches
    
    def get_rule_by_name(self, name: str) -> Optional[Rule]:
        """Get a rule by name."""
        for rule in self.rules:
            if rule.name == name:
                return rule
        return None
    
    def reset_aggregate_state(self):
        """Reset all aggregate rule state."""
        self.aggregate_state.clear()
    
    def cleanup_expired_state(self, before: datetime):
        """Remove aggregate state entries older than specified time."""
        expired_keys = []
        for key, timestamps in self.aggregate_state.items():
            self.aggregate_state[key] = [t for t in timestamps if t >= before]
            if not self.aggregate_state[key]:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.aggregate_state[key]


# Built-in rules for easy loading
DEFAULT_RULES = [
    # SSH Brute Force
    {
        "name": "ssh_brute_force",
        "description": "SSH brute force attack detected",
        "severity": "critical",
        "type": "aggregate",
        "pattern": r"Failed password for.*from",
        "threshold": 5,
        "timewindow": 5,
    },
    # SQL Injection
    {
        "name": "sql_injection_union_select",
        "description": "SQL injection attempt (UNION SELECT)",
        "severity": "critical",
        "type": "single",
        "pattern": r"(?i)union\s+(?:all\s+)?select",
        "field": "raw_message",
    },
    {
        "name": "sql_injection_or_1_equals_1",
        "description": "SQL injection attempt (OR 1=1)",
        "severity": "critical",
        "type": "single",
        "pattern": r"(?i)or\s+1\s*=\s*1",
        "field": "raw_message",
    },
    # Directory Traversal
    {
        "name": "directory_traversal",
        "description": "Directory traversal attempt",
        "severity": "high",
        "type": "single",
        "pattern": r"\.\./",
    },
    # HTTP Error Aggregation
    {
        "name": "http_403_aggregation",
        "description": "Multiple 403 Forbidden responses",
        "severity": "medium",
        "type": "aggregate",
        "pattern": r"403",
        "field": "status",
        "threshold": 10,
        "timewindow": 1,
    },
    {
        "name": "http_404_aggregation",
        "description": "Multiple 404 Not Found responses",
        "severity": "medium",
        "type": "aggregate",
        "pattern": r"404",
        "field": "status",
        "threshold": 20,
        "timewindow": 1,
    },
    # Suspicious User-Agent
    {
        "name": "suspicious_useragent_sqlmap",
        "description": "sqlmap scanner detected",
        "severity": "critical",
        "type": "single",
        "pattern": r"(?i)sqlmap",
        "field": "user_agent",
    },
    {
        "name": "suspicious_useragent_nikto",
        "description": "nikto scanner detected",
        "severity": "high",
        "type": "single",
        "pattern": r"(?i)nikto",
        "field": "user_agent",
    },
    {
        "name": "suspicious_useragent_nmap",
        "description": "nmap scanner detected",
        "severity": "medium",
        "type": "single",
        "pattern": r"(?i)nmap",
        "field": "user_agent",
    },
    # Command Injection
    {
        "name": "command_injection",
        "description": "Command injection attempt",
        "severity": "critical",
        "type": "single",
        "pattern": r"[;&|\n]\s*(?:cat|ls|wget|curl|nc|bash|sh)",
        "field": "path",
    },
    # Large File Upload
    {
        "name": "large_file_upload",
        "description": "Abnormally large POST request",
        "severity": "medium",
        "type": "single",
        "pattern": r".{10000000}",  # Match if raw_message > 10MB (very rough)
        "field": "raw_message",
    },
    # Sensitive Path Access
    {
        "name": "sensitive_path_admin",
        "description": "Access to admin panel",
        "severity": "medium",
        "type": "single",
        "pattern": r"/admin(?:/|$)",
    },
    {
        "name": "sensitive_path_wp_login",
        "description": "WordPress login access",
        "severity": "high",
        "type": "single",
        "pattern": r"/wp-login\.php",
    },
    {
        "name": "sensitive_path_env",
        "description": "Access to .env file",
        "severity": "critical",
        "type": "single",
        "pattern": r"/\.env",
    },
    {
        "name": "sensitive_path_api_debug",
        "description": "Access to API debug endpoint",
        "severity": "high",
        "type": "single",
        "pattern": r"/api/debug",
    },
    # Off-hours Activity
    {
        "name": "off_hours_activity",
        "description": "Activity during non-working hours (02:00-05:00)",
        "severity": "low",
        "type": "single",
        "pattern": r".*",
    },
    # XSS Attempts
    {
        "name": "xss_script_tag",
        "description": "XSS attempt (<script>)",
        "severity": "high",
        "type": "single",
        "pattern": r"<script",
    },
    {
        "name": "xss_javascript_uri",
        "description": "XSS attempt (javascript: URI)",
        "severity": "high",
        "type": "single",
        "pattern": r"javascript:",
    },
]


def load_default_rules() -> List[Rule]:
    """Load the default built-in rules."""
    engine = RuleEngine()
    engine.load_rules(DEFAULT_RULES)
    return engine.rules

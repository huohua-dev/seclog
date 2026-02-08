"""
Unit tests for rules module.
"""

import unittest
import tempfile
import os
from datetime import datetime, timedelta

from seclog.rules import RuleEngine, load_default_rules, DEFAULT_RULES
from seclog.models import LogEntry, Rule


class TestRules(unittest.TestCase):
    """Test cases for rules engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = RuleEngine()
        self.sample_entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            action="GET",
            severity="info",
            raw_message='192.168.1.100 - - [09/Feb/2026:02:00:00 +0800] "GET /admin HTTP/1.1" 403 512 "-" "Mozilla/5.0"',
            path="/admin",
            status=403,
            user_agent="Mozilla/5.0",
        )
    
    def test_load_default_rules(self):
        """Test loading default rules."""
        rules = load_default_rules()
        self.assertGreater(len(rules), 10)
    
    def test_load_yaml_rules(self):
        """Test loading YAML rules file."""
        yaml_content = """
- name: test_rule
  description: A test rule
  severity: high
  type: single
  pattern: test_pattern
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            
            errors = self.engine.load_rules(f.name)
            self.assertEqual(len(errors), 0)
            self.assertEqual(len(self.engine.rules), 1)
            self.assertEqual(self.engine.rules[0].name, "test_rule")
            
            os.unlink(f.name)
    
    def test_load_json_rules(self):
        """Test loading JSON rules file."""
        json_content = '''[
    {
        "name": "test_rule",
        "description": "A test rule",
        "severity": "high",
        "type": "single",
        "pattern": "test_pattern"
    }
]'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json_content)
            f.flush()
            
            errors = self.engine.load_rules(f.name)
            self.assertEqual(len(errors), 0)
            self.assertEqual(len(self.engine.rules), 1)
            
            os.unlink(f.name)
    
    def test_single_match(self):
        """Test single event rule matching."""
        rules = [
            Rule(
                name="test_rule",
                description="Test",
                severity="high",
                type="single",
                pattern=r"/admin",
            )
        ]
        engine = RuleEngine()
        engine.rules = rules
        import re
        engine.compiled_patterns["test_rule"] = (re.compile(r"/admin"), "raw_message")
        
        entry = self.sample_entry
        matches = engine.check_entry(entry)
        self.assertIn("test_rule", matches)
    
    def test_single_no_match(self):
        """Test single event rule not matching."""
        rules = [
            Rule(
                name="test_rule",
                description="Test",
                severity="high",
                type="single",
                pattern=r"/api/secret",
            )
        ]
        engine = RuleEngine()
        engine.rules = rules
        import re
        engine.compiled_patterns["test_rule"] = (re.compile(r"/api/secret"), "raw_message")
        
        matches = engine.check_entry(self.sample_entry)
        self.assertNotIn("test_rule", matches)
    
    def test_aggregate_match(self):
        """Test aggregate rule matching."""
        rules = [
            Rule(
                name="brute_force",
                description="Test",
                severity="critical",
                type="aggregate",
                pattern=r"Failed password",
                threshold=3,
                timewindow=5,
            )
        ]
        engine = RuleEngine()
        engine.rules = rules
        
        base_time = datetime.now()
        for i in range(3):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i),
                source_ip="192.168.1.100",
                action="ssh",
                severity="info",
                raw_message="Failed password for root from 192.168.1.100",
            )
            matches = engine.check_entry(entry)
            if i < 2:
                self.assertNotIn("brute_force", matches)
            else:
                self.assertIn("brute_force", matches)
    
    def test_aggregate_different_ips(self):
        """Test aggregate rule with different source IPs."""
        rules = [
            Rule(
                name="brute_force",
                description="Test",
                severity="critical",
                type="aggregate",
                pattern=r"Failed password",
                threshold=3,
                timewindow=5,
            )
        ]
        engine = RuleEngine()
        engine.rules = rules
        # Compile pattern
        import re
        engine.compiled_patterns["brute_force"] = (re.compile(r"Failed password"), "raw_message")
        
        base_time = datetime.now()
        
        # Same IP - should trigger after 3 attempts
        for i in range(3):
            entry = LogEntry(
                timestamp=base_time + timedelta(minutes=i),
                source_ip="192.168.1.100",
                action="ssh",
                severity="info",
                raw_message="Failed password",
            )
            matches = engine.check_entry(entry)
            if i == 2:
                self.assertIn("brute_force", matches)
    
    def test_validate_valid_rules(self):
        """Test validation of valid rules."""
        is_valid, errors = RuleEngine().validate_rules(DEFAULT_RULES)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
    
    def test_validate_invalid_rule(self):
        """Test validation detects missing required fields."""
        # Missing name and pattern
        invalid_rules = [
            {
                "description": "Rule without name",
                "severity": "high",
                "type": "single",
            }
        ]
        engine = RuleEngine()
        errors = engine.load_rules(invalid_rules)
        # Should have errors (name missing or pattern missing)
        self.assertGreater(len(errors), 0)
    
    def test_validate_invalid_type(self):
        """Test validation detects invalid rule type."""
        invalid_rules = [
            {
                "name": "test",
                "description": "Test",
                "severity": "high",
                "type": "invalid_type",
                "pattern": "test",
            }
        ]
        engine = RuleEngine()
        errors = engine.load_rules(invalid_rules)
        self.assertGreater(len(errors), 0)
    
    def test_list_rules(self):
        """Test listing rules."""
        rules = load_default_rules()
        self.assertGreater(len(rules), 0)
        
        for rule in rules:
            self.assertIsNotNone(rule.name)
            self.assertIsNotNone(rule.description)
            self.assertIsNotNone(rule.severity)
    
    def test_get_rule_by_name(self):
        """Test getting rule by name."""
        engine = RuleEngine()
        engine.load_rules(DEFAULT_RULES)
        
        rule = engine.get_rule_by_name("ssh_brute_force")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "ssh_brute_force")
        self.assertEqual(rule.type, "aggregate")
    
    def test_get_nonexistent_rule(self):
        """Test getting nonexistent rule returns None."""
        engine = RuleEngine()
        rule = engine.get_rule_by_name("nonexistent_rule")
        self.assertIsNone(rule)


if __name__ == "__main__":
    unittest.main()

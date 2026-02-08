"""
Analysis engine for security log analysis.
"""

from datetime import datetime
from typing import List, Optional

from .models import Alert, AnalysisResult, LogEntry, Rule, Severity
from .parser import parse_file, parse_lines
from .rules import RuleEngine, load_default_rules


class SecurityAnalyzer:
    """Main analyzer for security log analysis."""
    
    def __init__(self, rules: Optional[List[Rule]] = None):
        """Initialize analyzer with rules."""
        self.engine = RuleEngine()
        if rules:
            self.engine.rules = rules
            for rule in rules:
                if rule.pattern:
                    import re
                    compiled = re.compile(rule.pattern)
                    self.engine.compiled_patterns[rule.name] = (compiled, rule.field)
    
    @classmethod
    def with_default_rules(cls) -> "SecurityAnalyzer":
        """Create analyzer with default built-in rules."""
        return cls(load_default_rules())
    
    def analyze_file(
        self,
        filepath: str,
        severity_filter: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """Analyze a log file."""
        entries = parse_file(filepath)
        return self.analyze_entries(entries, severity_filter)
    
    def analyze_lines(
        self,
        lines: List[str],
        severity_filter: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """Analyze a list of log lines."""
        entries = parse_lines(lines)
        return self.analyze_entries(entries, severity_filter)
    
    def analyze_entries(
        self,
        entries: List[LogEntry],
        severity_filter: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """Analyze a list of log entries."""
        result = AnalysisResult(total_logs=len(entries))
        
        # Severity order for filtering
        severity_order = ["critical", "high", "medium", "low", "info"]
        
        for entry in entries:
            # Check which rules match
            matched_rules = self.engine.check_entry(entry)
            
            for rule_name in matched_rules:
                rule = self.engine.get_rule_by_name(rule_name)
                if not rule:
                    continue
                
                # Severity filtering
                if severity_filter:
                    # Include only specified severities
                    if rule.severity not in severity_filter:
                        continue
                else:
                    # For aggregate rules, only include if threshold met
                    # (already handled in rule engine)
                    pass
                
                # Special handling for off-hours rule
                if rule.name == "off_hours_activity":
                    if 2 <= entry.timestamp.hour < 5:
                        alert = Alert(
                            rule_name=rule.name,
                            severity=rule.severity,
                            timestamp=entry.timestamp,
                            source_ip=entry.source_ip,
                            matched_log=entry.raw_message,
                            description=rule.description,
                        )
                        result.alerts.append(alert)
                else:
                    alert = Alert(
                        rule_name=rule.name,
                        severity=rule.severity,
                        timestamp=entry.timestamp,
                        source_ip=entry.source_ip,
                        matched_log=entry.raw_message,
                        description=rule.description,
                    )
                    result.alerts.append(alert)
        
        return result
    
    def analyze(
        self,
        log_source: str,
        is_file: bool = True,
        severity_filter: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """Analyze log source (file or raw string)."""
        if is_file:
            return self.analyze_file(log_source, severity_filter)
        else:
            return self.analyze_entries(parse_lines(log_source.splitlines()), severity_filter)
    
    def reset(self):
        """Reset analyzer state (aggregate counters, etc.)."""
        self.engine.reset_aggregate_state()

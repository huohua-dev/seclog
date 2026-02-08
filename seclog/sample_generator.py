"""
Sample log generator for testing and demonstration.
"""

import json
import random
from datetime import datetime, timedelta
from typing import IO, List, Optional


# Realistic IP addresses
PRIVATE_IPS = ["192.168.1.100", "192.168.1.101", "10.0.0.50", "172.16.0.25"]
PUBLIC_IPS = ["203.0.113.45", "198.51.100.12", "192.0.2.8", "185.220.101.35"]

# Common paths (normal)
NORMAL_PATHS = [
    "/", "/index.html", "/css/style.css", "/js/app.js", "/images/logo.png",
    "/api/users", "/api/products", "/api/search", "/health", "/robots.txt",
    "/favicon.ico", "/about", "/contact", "/blog", "/blog/post-1",
]

# Normal user agents
NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F)",
]

# Attack patterns
ATTACK_PATTERNS = [
    # SQL Injection
    {"path": "/api/users?id=1 OR 1=1", "type": "sql_injection", "severity": "critical"},
    {"path": "/api/search?q=UNION SELECT username,password FROM users", "type": "sql_injection", "severity": "critical"},
    {"path": "/products.php?id=-1 UNION ALL SELECT NULL--", "type": "sql_injection", "severity": "critical"},
    # XSS
    {"path": "/search?q=<script>alert(1)</script>", "type": "xss", "severity": "high"},
    {"path": "/comment?text=<img src=x onerror=alert(1)>", "type": "xss", "severity": "high"},
    {"path": "/api/feedback?url=javascript:alert(1)", "type": "xss", "severity": "high"},
    # Directory Traversal
    {"path": "/files/../../etc/passwd", "type": "traversal", "severity": "high"},
    {"path": "/images/..%2f..%2fconfig.yml", "type": "traversal", "severity": "high"},
    {"path": "/../../windows/system32/config/sam", "type": "traversal", "severity": "high"},
    # Command Injection
    {"path": "/api/ping?host=127.0.0.1;cat /etc/passwd", "type": "cmd_injection", "severity": "critical"},
    {"path": "/debug?cmd=ls -la /var/www", "type": "cmd_injection", "severity": "critical"},
    # Sensitive Paths
    {"path": "/admin", "type": "sensitive", "severity": "medium"},
    {"path": "/wp-login.php", "type": "sensitive", "severity": "high"},
    {"path": "/.env", "type": "sensitive", "severity": "critical"},
    {"path": "/api/debug", "type": "sensitive", "severity": "high"},
    # Suspicious User-Agent
    {"path": "/", "type": "scanner", "user_agent": "sqlmap/1.4.7#stable", "severity": "critical"},
    {"path": "/", "type": "scanner", "user_agent": "Nikto/2.1.6", "severity": "high"},
    {"path": "/", "type": "scanner", "user_agent": "Nmap/7.80", "severity": "medium"},
]


class SampleLogGenerator:
    """Generator for sample security logs."""
    
    def __init__(self, seed: Optional[int] = None):
        if seed:
            random.seed(seed)
        self.base_time = datetime.now().replace(hour=12, minute=0, second=0, microsecond=0)
    
    def _generate_timestamp(self, offset_minutes: int = 0) -> datetime:
        """Generate timestamp with random offset."""
        return self.base_time + timedelta(minutes=random.randint(-720, 720) + offset_minutes)
    
    def _generate_ip(self, is_attacker: bool = False) -> str:
        """Generate realistic IP address."""
        if is_attacker:
            return random.choice(PUBLIC_IPS)
        return random.choice(PRIVATE_IPS + PUBLIC_IPS)
    
    def _should_be_attack(self) -> bool:
        """Determine if current log should be an attack (30% chance)."""
        return random.random() < 0.3
    
    def generate_apache_log(self, is_attack: bool = False, offset_minutes: int = 0) -> str:
        """Generate Apache/Nginx access log line."""
        ip = self._generate_ip(is_attack)
        timestamp = self._generate_timestamp(offset_minutes)
        
        if is_attack:
            attack = random.choice(ATTACK_PATTERNS)
            path = attack["path"]
            method = random.choice(["GET", "POST"])
            status = random.choice([200, 403, 404, 500])
            ua = attack.get("user_agent", random.choice(NORMAL_USER_AGENTS))
        else:
            path = random.choice(NORMAL_PATHS)
            method = "GET" if random.random() < 0.8 else "POST"
            status = random.choice([200, 201, 204, 301, 302])
            ua = random.choice(NORMAL_USER_AGENTS)
        
        ts_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0800")
        size = random.randint(100, 10000)
        
        return f'{ip} - - [{ts_str}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    
    def generate_syslog(self, is_attack: bool = False, offset_minutes: int = 0) -> str:
        """Generate Syslog line."""
        timestamp = self._generate_timestamp(offset_minutes)
        ts_str = timestamp.strftime("%b %d %H:%M:%S")
        hostname = "webserver01"
        
        if is_attack:
            attack = random.choice(ATTACK_PATTERNS)
            if attack["type"] == "sql_injection":
                return f'{ts_str} {hostname} apache2[12345]: [client {self._generate_ip(True)}] AH01215: PHP Warning:  mysql_connect(): Access denied for user in /var/www/html/api.php on line 42'
            elif attack["type"] == "traversal":
                return f'{ts_str} {hostname} apache2[12345]: [error] [client {self._generate_ip(True)}] File does not exist: /var/www/../../../etc/passwd'
            else:
                return f'{ts_str} {hostname} sshd[1234]: Failed password for invalid user admin from {self._generate_ip(True)} port 22 ssh2'
        else:
            return f'{ts_str} {hostname} systemd[1]: Started Apache HTTP Server.'
    
    def generate_json_log(self, is_attack: bool = False, offset_minutes: int = 0) -> str:
        """Generate JSON format log line."""
        ip = self._generate_ip(is_attack)
        timestamp = self._generate_timestamp(offset_minutes)
        
        log_data = {
            "timestamp": timestamp.isoformat(),
            "source_ip": ip,
            "action": "http_request",
            "severity": "info",
        }
        
        if is_attack:
            attack = random.choice(ATTACK_PATTERNS)
            log_data["method"] = random.choice(["GET", "POST"])
            log_data["path"] = attack["path"]
            log_data["status"] = random.choice([200, 403, 404])
            log_data["user_agent"] = attack.get("user_agent", random.choice(NORMAL_USER_AGENTS))
            log_data["severity"] = attack["severity"]
        else:
            log_data["method"] = "GET" if random.random() < 0.8 else "POST"
            log_data["path"] = random.choice(NORMAL_PATHS)
            log_data["status"] = random.choice([200, 201, 204])
            log_data["user_agent"] = random.choice(NORMAL_USER_AGENTS)
        
        return json.dumps(log_data)
    
    def generate(
        self,
        count: int = 1000,
        format: str = "apache",
        attack_ratio: float = 0.3,
    ) -> List[str]:
        """Generate sample logs."""
        logs = []
        attack_count = int(count * attack_ratio)
        normal_count = count - attack_count
        
        # Generate attacks first
        for i in range(attack_count):
            if format == "apache":
                log = self.generate_apache_log(is_attack=True, offset_minutes=i)
            elif format == "syslog":
                log = self.generate_syslog(is_attack=True, offset_minutes=i)
            else:
                log = self.generate_json_log(is_attack=True, offset_minutes=i)
            logs.append(log)
        
        # Generate normal traffic
        for i in range(normal_count):
            if format == "apache":
                log = self.generate_apache_log(is_attack=False, offset_minutes=attack_count + i)
            elif format == "syslog":
                log = self.generate_syslog(is_attack=False, offset_minutes=attack_count + i)
            else:
                log = self.generate_json_log(is_attack=False, offset_minutes=attack_count + i)
            logs.append(log)
        
        # Shuffle to mix attacks with normal traffic
        random.shuffle(logs)
        
        return logs
    
    def generate_to_file(
        self,
        output: IO,
        count: int = 1000,
        format: str = "apache",
        attack_ratio: float = 0.3,
    ):
        """Generate sample logs directly to a file."""
        logs = self.generate(count, format, attack_ratio)
        for log in logs:
            output.write(log + "\n")


def generate_sample_logs(
    count: int = 1000,
    format: str = "apache",
    output: Optional[IO] = None,
    attack_ratio: float = 0.3,
    seed: Optional[int] = None,
) -> List[str]:
    """Convenience function to generate sample logs."""
    generator = SampleLogGenerator(seed)
    logs = generator.generate(count, format, attack_ratio)
    
    if output:
        for log in logs:
            output.write(log + "\n")
        return []
    
    return logs

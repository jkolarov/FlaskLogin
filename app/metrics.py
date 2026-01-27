"""
Prometheus metrics for the Flask Auth application.
"""
from prometheus_client import Counter, Gauge

# Auth metrics
login_counter = Counter('auth_logins_total', 'Total login attempts', ['method', 'status'])
registration_counter = Counter('auth_registrations_total', 'Total registration attempts', ['status'])

# IP tracking metrics
requests_by_ip = Counter('http_requests_by_ip_total', 'Total requests by IP address', ['ip'])
unique_ips = Gauge('http_unique_ips', 'Number of unique IP addresses seen')
seen_ips = set()

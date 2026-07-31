import re

# Threat patterns for SQLi, XSS, and Path Traversal
SQLI_PATTERNS = [
    r"SELECT", r"UNION", r"INSERT", r"DELETE", r"DROP", 
    r"--", r"OR '1'='1'", r"OR 1=1"
]

XSS_PATTERNS = [
    r"<script>", r"javascript:", r"onerror=", r"onload="
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"/etc/passwd"
]

def scan_text(input_string):
    if not input_string:
        return None
    
    input_upper = input_string.upper()

    # Check SQL Injection
    for pattern in SQLI_PATTERNS:
        if pattern.upper() in input_upper:
            return "SQL Injection"

    # Check XSS
    for pattern in XSS_PATTERNS:
        if pattern.lower() in input_string.lower():
            return "XSS Attack"

    # Check Path Traversal
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern in input_string:
            return "Path Traversal"

    return None

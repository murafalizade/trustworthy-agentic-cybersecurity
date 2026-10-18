"""Deterministic, regex-based attack-pattern signatures.

These exist so obvious attack payloads are caught even if the LLM gets
distracted or a log line is crafted to look harmless to a model — the
patterns are matched as plain strings, never executed or interpreted, so a
malicious log entry cannot use this module to do anything but get flagged.
"""

import ipaddress
import re
from typing import Dict, List

_PATTERNS: Dict[str, List[re.Pattern]] = {
    "sql_injection": [
        re.compile(r"(\bunion\b.{0,40}\bselect\b)", re.IGNORECASE | re.DOTALL),
        re.compile(r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", re.IGNORECASE),
        re.compile(r"(--|#|;)\s*$"),
        re.compile(r"(\bdrop\b\s+\btable\b|\bxp_cmdshell\b)", re.IGNORECASE),
        re.compile(r"(\bsleep\(|\bbenchmark\()", re.IGNORECASE),
    ],
    "xss": [
        re.compile(r"<\s*script\b", re.IGNORECASE),
        re.compile(r"on(error|load|mouseover|focus)\s*=", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
    ],
    "command_injection": [
        re.compile(r"[;&|`]\s*(cat|wget|curl|nc|bash|sh|python3?|perl|chmod|rm)\b", re.IGNORECASE),
        re.compile(r"\$\(.*\)"),
        re.compile(r"\|\s*base64"),
    ],
    "path_traversal": [
        re.compile(r"(\.\./){2,}|(\.\.\\){2,}"),
        re.compile(r"/etc/passwd|/etc/shadow|boot\.ini|win\.ini", re.IGNORECASE),
    ],
    "log4shell_style": [
        re.compile(r"\$\{jndi:(ldap|rmi|dns)://", re.IGNORECASE),
    ],
    "prompt_injection": [
        re.compile(r"ignore (all |any )?(previous|prior|above) instructions", re.IGNORECASE),
        re.compile(r"you are now (a|an|in) ", re.IGNORECASE),
        re.compile(r"system prompt", re.IGNORECASE),
        re.compile(r"\bact as\b.{0,30}\b(admin|root|system)\b", re.IGNORECASE),
    ],
}

_PRIVATE_RANGES = [
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
    )
]


def scan_patterns(text: str) -> Dict[str, List[str]]:
    """Returns {category: [matched substrings]} for every category with a hit.

    `text` is treated purely as data to pattern-match against — its content
    is never evaluated, formatted into a prompt without quoting, or acted on.
    """
    if not text:
        return {}
    matches: Dict[str, List[str]] = {}
    for category, patterns in _PATTERNS.items():
        found = []
        for pattern in patterns:
            for m in pattern.finditer(text):
                snippet = m.group(0)[:120]
                if snippet not in found:
                    found.append(snippet)
        if found:
            matches[category] = found
    return matches


def classify_ip(ip_str: str) -> Dict[str, object]:
    """Best-effort, dependency-free classification of an IP address."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"valid": False, "error": f"'{ip_str}' is not a valid IP address"}

    is_private = any(ip in net for net in _PRIVATE_RANGES)
    return {
        "valid": True,
        "ip": str(ip),
        "version": ip.version,
        "is_private": is_private,
        "is_public": not is_private and not ip.is_multicast and not ip.is_reserved,
        "is_loopback": ip.is_loopback,
        "is_multicast": ip.is_multicast,
    }

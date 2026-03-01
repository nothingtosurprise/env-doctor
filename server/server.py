#!/usr/bin/env python3
"""
.env Doctor MCP Server
Diagnoses .env files for missing vars, weak secrets, format issues, and exposed API keys.
"""

import json
import re
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(".env Doctor")

# ── Constants ────────────────────────────────────────────────────────────────

WEAK_VALUES = {
    "secret", "password", "123456", "test", "example", "changeme",
    "your_secret_here", "xxx", "abc123", "admin", "root", "qwerty",
    "placeholder", "replace_me", "todo", "fixme", "temp", "temporary",
    "default", "sample", "demo", "fake", "mock", "dummy"
}

SENSITIVE_KEY_PATTERNS = [
    r"(?i)(api[_-]?key|apikey)",
    r"(?i)(secret[_-]?key|secret)",
    r"(?i)(password|passwd|pwd)",
    r"(?i)(token|auth[_-]?token)",
    r"(?i)(private[_-]?key)",
    r"(?i)(access[_-]?key|access[_-]?secret)",
    r"(?i)(stripe|twilio|sendgrid|aws|gcp|azure|openai|anthropic|github)[_-]",
]

REAL_SECRET_PATTERNS = [
    r"sk-[a-zA-Z0-9]{20,}",           # OpenAI / Anthropic style
    r"pk_live_[a-zA-Z0-9]{20,}",      # Stripe live key
    r"sk_live_[a-zA-Z0-9]{20,}",      # Stripe live secret
    r"AKIA[0-9A-Z]{16}",              # AWS Access Key ID
    r"ghp_[a-zA-Z0-9]{36}",           # GitHub PAT
    r"xoxb-[0-9]+-[a-zA-Z0-9]+",     # Slack Bot Token
    r"AC[a-z0-9]{32}",                # Twilio Account SID
    r"[0-9a-f]{32}",                  # Generic 32-char hex (MD5-like)
    r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",  # JWT
]

FORMAT_RULES = {
    r"(?i)(url|endpoint|host|uri|base_url|webhook)": {
        "pattern": r"^https?://",
        "message": "Should be a valid URL starting with http:// or https://"
    },
    r"(?i)(port)$": {
        "pattern": r"^\d{1,5}$",
        "message": "Should be a numeric port number (1-65535)"
    },
    r"(?i)(debug|verbose|enabled|disabled|ssl|tls)$": {
        "pattern": r"^(true|false|0|1|yes|no)$",
        "message": "Should be a boolean: true/false, 0/1, or yes/no"
    },
    r"(?i)(email|mail_from|smtp_user)": {
        "pattern": r"^[^@]+@[^@]+\.[^@]+$",
        "message": "Should be a valid email address"
    },
    r"(?i)(timeout|ttl|max|limit|size|count|retry)$": {
        "pattern": r"^\d+$",
        "message": "Should be a numeric value"
    },
}

# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_env_file(content: str) -> dict[str, str]:
    """Parse .env file content into a dict of key=value pairs."""
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            result[key] = value
    return result


def is_sensitive_key(key: str) -> bool:
    return any(re.search(p, key) for p in SENSITIVE_KEY_PATTERNS)


def contains_real_secret(value: str) -> str | None:
    """Returns the matched pattern name if a real secret is detected."""
    for pattern in REAL_SECRET_PATTERNS:
        if re.search(pattern, value):
            return pattern
    return None


def check_format(key: str, value: str) -> str | None:
    for key_pattern, rule in FORMAT_RULES.items():
        if re.search(key_pattern, key):
            if value and not re.match(rule["pattern"], value, re.IGNORECASE):
                return rule["message"]
    return None


def mask_value(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:4] + "*" * (len(value) - 4)


def analyze_env(env: dict[str, str], example: dict[str, str] | None = None) -> dict:
    issues = []
    warnings = []
    info = []
    redacted_keys = []

    # 1. Missing vars from example
    if example:
        for key in example:
            if key not in env:
                issues.append({
                    "type": "missing",
                    "key": key,
                    "severity": "error",
                    "message": f"'{key}' is in .env.example but missing from your .env"
                })

    for key, value in env.items():
        # 2. Empty required values
        if value == "" or value is None:
            issues.append({
                "type": "empty",
                "key": key,
                "severity": "error",
                "message": f"'{key}' is empty — if required, this will cause runtime errors"
            })
            continue

        # 3. Exposed real API keys/secrets
        secret_match = contains_real_secret(value)
        if secret_match and is_sensitive_key(key):
            issues.append({
                "type": "exposed_secret",
                "key": key,
                "severity": "critical",
                "message": f"'{key}' appears to contain a REAL secret or API key — never commit this!",
                "masked_value": mask_value(value),
                "redacted": True
            })
            redacted_keys.append(key)
            continue

        # 4. Weak / insecure values
        if is_sensitive_key(key) and value.lower() in WEAK_VALUES:
            warnings.append({
                "type": "weak_secret",
                "key": key,
                "severity": "warning",
                "message": f"'{key}' has a weak/placeholder value '{value}' — use a strong random secret in production"
            })

        # 5. Format validation
        format_issue = check_format(key, value)
        if format_issue:
            warnings.append({
                "type": "format",
                "key": key,
                "severity": "warning",
                "message": f"'{key}': {format_issue}",
                "current_value": value if not is_sensitive_key(key) else mask_value(value)
            })

        # 6. Port range check
        if re.search(r"(?i)(port)$", key) and value.isdigit():
            port = int(value)
            if not (1 <= port <= 65535):
                issues.append({
                    "type": "invalid_port",
                    "key": key,
                    "severity": "error",
                    "message": f"'{key}' has invalid port {port} — must be between 1 and 65535"
                })

    # 7. Info: vars not in example (new vars)
    if example:
        for key in env:
            if key not in example:
                info.append({
                    "type": "undocumented",
                    "key": key,
                    "severity": "info",
                    "message": f"'{key}' exists in .env but is not documented in .env.example"
                })

    return {
        "total_vars": len(env),
        "issues": issues,
        "warnings": warnings,
        "info": info,
        "redacted_keys": redacted_keys,
        "score": _calculate_score(issues, warnings, len(env))
    }


def _calculate_score(issues: list, warnings: list, total: int) -> int:
    if total == 0:
        return 100
    criticals = sum(1 for i in issues if i.get("severity") == "critical")
    errors = sum(1 for i in issues if i.get("severity") == "error")
    score = 100 - (criticals * 30) - (errors * 10) - (len(warnings) * 5)
    return max(0, min(100, score))


# ── MCP Tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def diagnose_env(env_content: str, example_content: str = "") -> str:
    """
    Diagnose a .env file for issues.

    Args:
        env_content: The full contents of your .env file as a string
        example_content: (Optional) The full contents of your .env.example file
    
    Returns:
        A JSON report with all issues, warnings, and a health score
    """
    env = parse_env_file(env_content)
    example = parse_env_file(example_content) if example_content.strip() else None

    result = analyze_env(env, example)

    # Build human-friendly summary
    critical_count = sum(1 for i in result["issues"] if i.get("severity") == "critical")
    error_count = sum(1 for i in result["issues"] if i.get("severity") == "error")
    warning_count = len(result["warnings"])

    summary_lines = [
        f"🩺 .env Doctor Report",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"Health Score: {result['score']}/100",
        f"Total Variables: {result['total_vars']}",
        f"🚨 Critical: {critical_count}",
        f"❌ Errors: {error_count}",
        f"⚠️  Warnings: {warning_count}",
        f"ℹ️  Info: {len(result['info'])}",
        ""
    ]

    if result["redacted_keys"]:
        summary_lines.append(f"🔒 REDACTED from report (real secrets detected): {', '.join(result['redacted_keys'])}")
        summary_lines.append("")

    if result["issues"]:
        summary_lines.append("ISSUES:")
        for issue in result["issues"]:
            icon = "🚨" if issue["severity"] == "critical" else "❌"
            summary_lines.append(f"  {icon} [{issue['type'].upper()}] {issue['message']}")

    if result["warnings"]:
        summary_lines.append("\nWARNINGS:")
        for w in result["warnings"]:
            summary_lines.append(f"  ⚠️  [{w['type'].upper()}] {w['message']}")

    if result["info"]:
        summary_lines.append("\nINFO:")
        for item in result["info"]:
            summary_lines.append(f"  ℹ️  {item['message']}")

    if not result["issues"] and not result["warnings"]:
        summary_lines.append("✅ No issues found! Your .env looks healthy.")

    result["summary"] = "\n".join(summary_lines)
    return json.dumps(result, indent=2)


@mcp.tool()
def diagnose_env_file(env_path: str, example_path: str = "") -> str:
    """
    Diagnose .env files by file path on disk.

    Args:
        env_path: Absolute or relative path to your .env file
        example_path: (Optional) Path to your .env.example file
    
    Returns:
        A JSON report with all issues, warnings, and a health score
    """
    env_file = Path(env_path)
    if not env_file.exists():
        return json.dumps({"error": f"File not found: {env_path}"})

    env_content = env_file.read_text()
    example_content = ""

    if example_path:
        example_file = Path(example_path)
        if example_file.exists():
            example_content = example_file.read_text()

    return diagnose_env(env_content, example_content)


@mcp.tool()
def scan_project(project_path: str) -> str:
    """
    Scan an entire project directory for all .env variants and diagnose them.
    Detects: .env, .env.local, .env.development, .env.production, .env.staging, .env.test

    Args:
        project_path: Path to the root of your project
    
    Returns:
        A JSON report for each .env file found
    """
    root = Path(project_path)
    if not root.exists():
        return json.dumps({"error": f"Directory not found: {project_path}"})

    env_variants = [
        ".env", ".env.local", ".env.development",
        ".env.production", ".env.staging", ".env.test",
        ".env.dev", ".env.prod"
    ]

    example_files = [".env.example", ".env.sample", ".env.template"]

    # Find example file
    example_content = ""
    for ef in example_files:
        ep = root / ef
        if ep.exists():
            example_content = ep.read_text()
            break

    reports = {}
    found_any = False

    for variant in env_variants:
        env_file = root / variant
        if env_file.exists():
            found_any = True
            result = json.loads(diagnose_env(env_file.read_text(), example_content))
            reports[variant] = result

    if not found_any:
        return json.dumps({"error": "No .env files found in this directory"})

    # Overall project score
    all_scores = [r["score"] for r in reports.values()]
    project_score = sum(all_scores) // len(all_scores)

    return json.dumps({
        "project_path": str(root),
        "files_scanned": list(reports.keys()),
        "project_score": project_score,
        "reports": reports
    }, indent=2)


@mcp.tool()
def generate_example(env_content: str) -> str:
    """
    Generate a safe .env.example from an existing .env file.
    Strips all real values and replaces secrets with safe placeholders.

    Args:
        env_content: The full contents of your .env file
    
    Returns:
        A safe .env.example content string ready to commit to git
    """
    lines = []
    lines.append("# .env.example — Safe to commit. Never commit your real .env!")
    lines.append("# Copy this file to .env and fill in your values.")
    lines.append("")

    for line in env_content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue
        if "=" in stripped:
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if is_sensitive_key(key) or contains_real_secret(value):
                lines.append(f"{key}=your_{key.lower()}_here")
            elif value == "":
                lines.append(f"{key}=")
            elif value.lower() in ("true", "false", "0", "1"):
                lines.append(f"{key}={value}")
            elif value.isdigit():
                lines.append(f"{key}={value}")
            else:
                lines.append(f"{key}=example_{key.lower()}")
        else:
            lines.append(line)

    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")

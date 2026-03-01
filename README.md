# 🩺 .env Doctor

> Diagnose your .env files for missing variables, weak secrets, format issues, and exposed API keys.

A Python MCP server + clean web UI that protects developers from the most common `.env` mistakes before they become production incidents.

---

## What it checks

| Check | Severity |
|---|---|
| Missing vars from `.env.example` | ❌ Error |
| Empty values on required fields | ❌ Error |
| Real API keys / secrets detected | 🚨 Critical |
| Weak/placeholder values (`secret`, `123456`) | ⚠️ Warning |
| Wrong format (URLs, ports, booleans, emails) | ⚠️ Warning |
| Vars not documented in `.env.example` | ℹ️ Info |

---

## MCP Tools

| Tool | Description |
|---|---|
| `diagnose_env` | Diagnose `.env` content passed as a string |
| `diagnose_env_file` | Diagnose `.env` file(s) by path on disk |
| `scan_project` | Scan entire project for all `.env` variants |
| `generate_example` | Generate a safe `.env.example` from your real `.env` |

---

## Install MCP Server

```bash
pip install mcp
python server/server.py
```

### Claude Desktop config

```json
{
  "mcpServers": {
    "env-doctor": {
      "command": "python",
      "args": ["/path/to/env-doctor/server/server.py"]
    }
  }
}
```

### Via gitMCP (no install)

```json
{
  "mcpServers": {
    "env-doctor": {
      "command": "npx",
      "args": ["mcp-remote", "https://gitmcp.io/nothingtosurprise/env-doctor"]
    }
  }
}
```

---

## Web UI

Open `frontend/index.html` in any browser — no server needed, runs fully client-side.

**Features:**
- Paste your `.env` and `.env.example` for instant diagnosis
- Health score (0–100) with visual ring
- Grouped issues by severity
- Generate a safe `.env.example` with one click
- All secrets masked in the report — nothing leaves your browser

---

## Example Usage in Claude

```
"Diagnose my .env file" → paste content → instant report

"Scan my project at /home/user/myapp" → checks all .env variants

"Generate a safe .env.example from my .env" → strips all real values
```

---

## Supported .env variants

`.env` · `.env.local` · `.env.development` · `.env.production` · `.env.staging` · `.env.test` · `.env.dev` · `.env.prod`

---

## License

MIT

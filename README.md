# AWS Compliance MCP Server

A **Model Context Protocol (MCP)** server that connects an LLM (Claude, GPT-4, etc.) to real AWS infrastructure and performs automated compliance scanning against:

- **PCI-DSS v3.2.1** (18 controls across 8 requirements)
- **CIS AWS Foundations Benchmark v1.4** (19 controls across 5 sections)
- **AWS Well-Architected Framework** (14 checks across all 5 pillars)

---

## Architecture

```
Claude / Any MCP Client
        │  MCP Protocol (stdio)
        ▼
aws-compliance-mcp (FastMCP server)
    ├── ConfigTools        → AWS Config APIs
    ├── SecurityHubTools   → Security Hub APIs
    └── ComplianceScanner  → Rule mappings + scoring
```

---

## Prerequisites

- Python 3.10+
- AWS credentials with read access to Config and Security Hub
- AWS Config and Security Hub enabled in your target region

---

## Installation

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/aws-compliance-mcp.git
cd aws-compliance-mcp

# Create virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install the package
pip install -e ".[dev]"

# Or with pip from requirements
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

---

## Configuration

```bash
cp .env.example .env
# Edit .env with your AWS region and optional profile
```

`.env.example`:
```
AWS_REGION=us-east-1
# AWS_PROFILE=my-profile   # Uncomment to use a named profile
```

---

## Running the Server

```bash
# Run directly
python -m aws_compliance_mcp.server

# Or via installed script
aws-compliance-mcp
```

---

## Connect to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "aws-compliance": {
      "command": "/path/to/.venv/bin/python",
      "args": ["-m", "aws_compliance_mcp.server"],
      "env": {
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "your-profile"
      }
    }
  }
}
```

---

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `scan_pcidss_compliance` | Full PCI-DSS v3.2.1 scan |
| `scan_cis_compliance` | CIS Benchmark v1.4 scan |
| `scan_well_architected` | Well-Architected scan (all pillars or single) |
| `scan_all_frameworks` | Unified scan with overall risk score |
| `get_remediation_steps` | Step-by-step fix for a specific control |
| `generate_audit_report` | Audit-ready report with top-10 priorities |
| `get_config_compliance_summary` | Overall Config rule compliance % |
| `list_config_rules` | All Config rules + compliance state |
| `get_config_rule_status` | Single rule details + failing resources |
| `get_noncompliant_resources` | NON_COMPLIANT resources |
| `get_security_hub_summary` | Finding counts by severity |
| `get_security_hub_findings` | Filtered findings list |
| `get_security_hub_score` | Pass/fail ratio per standard |

### Example Claude prompts

```
"Run a full PCI-DSS compliance scan in us-east-1 and tell me what's failing."

"What are my top 10 remediation priorities across all frameworks?"

"Give me step-by-step remediation for PCI.10.1"

"What's my Security Hub score and how many CRITICAL findings do I have?"
```

---

## MCP Resources

| URI | Description |
|-----|-------------|
| `compliance://pcidss/controls` | Full PCI-DSS control catalog |
| `compliance://cis/controls` | Full CIS control catalog |
| `compliance://well-architected/pillars` | Well-Architected pillar checks |

---

## Running Tests

```bash
# All tests
make test

# With coverage
make coverage

# Lint
make lint

# Or directly
pytest tests/ -v
```

Tests use **moto** to mock all AWS API calls — no real AWS account needed.

---

## Project Structure

```
aws-compliance-mcp/
├── src/aws_compliance_mcp/
│   ├── server.py              # FastMCP server + all tool/resource definitions
│   ├── aws_client.py          # Shared boto3 client with retry config
│   ├── tools/
│   │   ├── config_tools.py    # AWS Config API wrapper
│   │   ├── securityhub_tools.py  # Security Hub API wrapper
│   │   └── compliance_scanner.py # Framework scanning + reporting
│   └── rules/
│       ├── pcidss.py          # PCI-DSS v3.2.1 control mappings
│       ├── cis.py             # CIS Benchmark v1.4 control mappings
│       └── well_architected.py  # Well-Architected checks
├── tests/
│   ├── conftest.py
│   ├── test_config_tools.py
│   ├── test_securityhub_tools.py
│   └── test_compliance_scanner.py
├── pyproject.toml
├── Makefile
└── .env.example
```

---

## Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "config:DescribeComplianceByConfigRule",
        "config:GetComplianceSummaryByConfigRule",
        "config:GetComplianceDetailsByConfigRule",
        "config:DescribeComplianceByResource",
        "config:DescribeConfigRules",
        "securityhub:GetFindings",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeStandardsControls"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## CI/CD

GitHub Actions runs tests on Python 3.10 and 3.12 on every push. See `.github/workflows/ci.yml`.

---

## License

MIT

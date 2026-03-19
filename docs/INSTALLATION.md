# Installation Guide

## Prerequisites

- Python 3.11 or higher
- pip package manager
- API keys for threat intelligence sources (optional but recommended)

## Step-by-Step Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/mcp-for-soc.git
cd mcp-for-soc
```

### 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv

# Activate on Linux/Mac
source venv/bin/activate

# Activate on Windows
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API Keys

```bash
# Copy example config
cp config.yaml.example config.yaml

# Edit with your favorite editor
nano config.yaml  # or vim, code, etc.
```

**Minimum Configuration** (Free tier):
- VirusTotal API key (get from https://www.virustotal.com/)
- AbuseIPDB API key (get from https://www.abuseipdb.com/)

**Recommended Configuration**:
- Add Anthropic API key for LLM analysis
- Add Shodan API key for infrastructure scanning

### 5. Test Installation

```bash
# Test CLI
python -m src.soc_agent --help

# Test IOC investigation
python -m src.soc_agent ioc 8.8.8.8
```

### 6. Configure Claude Desktop (Optional)

Add to Claude Desktop config file:
- **MacOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "mcp-for-soc": {
      "command": "python",
      "args": ["/absolute/path/to/mcp-for-soc/src/server.py"]
    }
  }
}
```

**Important**: Use absolute paths!

## Troubleshooting

### Issue: Import errors
**Solution**: Make sure you're in the virtual environment and all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Issue: API errors
**Solution**: Check your API keys in `config.yaml` and verify they're valid

### Issue: Permission denied
**Solution**: Ensure Python files are executable:
```bash
chmod +x src/server.py
chmod +x src/soc_agent.py
```

## Next Steps

- Read [Configuration Guide](CONFIGURATION.md)
- Check [Usage Examples](USAGE.md)
- Review [Architecture](ARCHITECTURE.md)

## Getting Help

- Open an issue on GitHub
- Check existing issues for solutions
- Read documentation thoroughly before asking

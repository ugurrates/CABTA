"""Blue Team Assistant - MCP Server Interface.

Author: Ugur Ates
Version: 1.0.0
"""

import asyncio
import json
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent
import logging

# Import tools
from .tools import IOCInvestigator, EmailAnalyzer, MalwareAnalyzer
from .utils import load_config, setup_logger

# Setup logging
logger = setup_logger('blue-team-assistant', 'INFO')

# Load configuration
config = load_config()

# Initialize tools
ioc_investigator = IOCInvestigator(config)
email_analyzer = EmailAnalyzer(config)
malware_analyzer = MalwareAnalyzer(config)

# Enable cross-tool integration
email_analyzer.ioc_investigator = ioc_investigator
email_analyzer.file_analyzer = malware_analyzer
malware_analyzer.ioc_investigator = ioc_investigator

# Create MCP server
app = Server("blue-team-assistant-ultimate")
@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools."""
    return [
        Tool(
            name="investigate_ioc",
            description="Investigate Indicators of Compromise (IOCs) using 20+ threat intelligence sources.\n\n"
                       "**Supported IOCs:** IP, domain, URL, file hash (MD5/SHA1/SHA256)\n\n"
                       "**Intelligence Sources (20+):**\n"
                       "✓ VirusTotal - Multi-AV scanning\n"
                       "✓ AbuseIPDB - IP reputation\n"
                       "✓ Abuse.ch Suite (URLhaus, MalwareBazaar, ThreatFox, Feodo)\n"
                       "✓ C2 Trackers (GitHub repos)\n"
                       "✓ Tor Exit Node check\n\n"
                       "**Features:**\n"
                       "• Normalized threat scoring (0-100)\n"
                       "• C2 infrastructure detection\n"
                       "• Malware family identification\n"
                       "• Local LLM analysis (Ollama)\n\n"
                       "**Perfect for SOC teams investigating IPs, domains, URLs, and hashes.**",
            inputSchema={
                "type": "object",
                "properties": {
                    "ioc": {
                        "type": "string",
                        "description": "Indicator: IP, domain, URL, or hash (MD5/SHA1/SHA256)"
                    }
                },
                "required": ["ioc"]
            }
        ),
        Tool(
            name="analyze_email",
            description="Comprehensive email security analysis for phishing detection.\n\n"
                       "**Process:**\n"
                       "1. Parse email headers and body (.eml file)\n"
                       "2. Validate SPF/DKIM/DMARC authentication\n"
                       "3. Detect phishing indicators and suspicious patterns\n"
                       "4. Extract and analyze URLs/attachments/IOCs\n"
                       "5. Local LLM analysis for verdict\n\n"
                       "**Supported File Types:** .eml (email message files)\n\n"
                       "**Features:**\n"
                       "• Phishing keyword detection\n"
                       "• Authentication validation (SPF/DKIM)\n"
                       "• URL and attachment analysis\n"
                       "• IOC extraction from email content\n"
                       "• Sender verification\n\n"
                       "**Perfect for investigating suspicious emails and phishing attempts.**",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to .eml email file"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="analyze_file",
            description="Comprehensive malware analysis using hash-based threat intelligence and static analysis.\n\n"
                       "**Process:**\n"
                       "1. Calculate file hashes (MD5, SHA1, SHA256)\n"
                       "2. Query 20+ threat intelligence sources\n"
                       "3. Perform static analysis (PE/PDF/Office/Scripts)\n"
                       "4. Local LLM analysis for verdict\n"
                       "5. Generate detection rules (YARA/KQL)\n\n"
                       "**Supported File Types:**\n"
                       "• Executables: .exe, .dll, .sys\n"
                       "• Documents: .pdf, .docx, .xlsx, .pptx\n"
                       "• Scripts: .js, .vbs, .ps1, .bat\n"
                       "• Archives: .zip, .rar, .7z\n\n"
                       "**Features:**\n"
                       "• Multi-source hash reputation\n"
                       "• Static analysis (imports, sections, strings)\n"
                       "• Malware family identification\n"
                       "• False positive filtering\n\n"
                       "**Note:** Hash-based lookup only. File is NOT submitted to sandboxes.\n"
                       "**Perfect for malware triage and threat assessment.**",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to file to analyze"
                    }
                },
                "required": ["file_path"]
            }
        )
    ]
@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    try:
        if name == "investigate_ioc":
            ioc = arguments.get("ioc")
            if not ioc:
                return [TextContent(type="text", text="Error: IOC parameter required")]
            
            result = await ioc_investigator.investigate(ioc)
            
            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]
        
        elif name == "analyze_email":
            file_path = arguments.get("file_path")
            if not file_path:
                return [TextContent(type="text", text="Error: file_path parameter required")]
            
            result = await email_analyzer.analyze(file_path)
            
            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]
        
        elif name == "analyze_file":
            file_path = arguments.get("file_path")
            if not file_path:
                return [TextContent(type="text", text="Error: file_path parameter required")]
            
            result = await malware_analyzer.analyze(file_path)
            
            return [TextContent(
                type="text",
                text=json.dumps(result, indent=2, ensure_ascii=False)
            )]
        
        else:
            return [TextContent(type="text", text=f"Error: Unknown tool '{name}'")]
    
    except Exception as e:
        logger.error(f"[SERVER] Tool call failed: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]
async def main():
    """Run MCP server."""
    from mcp.server.stdio import stdio_server
    
    async with stdio_server() as (read_stream, write_stream):
        logger.info("[SERVER] Blue Team Assistant started")
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )
if __name__ == "__main__":
    asyncio.run(main())

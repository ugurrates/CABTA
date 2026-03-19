# Local LLM Setup Guide (Ollama)

## Why Local LLM?

### 🔐 Security & Privacy
- **Data Sovereignty**: Threat intelligence data never leaves your infrastructure
- **Aviation Compliance**: Meets strict aviation cybersecurity requirements
- **No Data Leakage**: Sensitive IOCs, emails, files analyzed locally
- **Audit Trail**: Full control over what's processed where

### 💰 Cost Benefits
- **FREE**: No API costs, no usage limits
- **Unlimited**: Analyze thousands of samples without paying
- **No Rate Limits**: Process as fast as your hardware allows

### ⚡ Performance
- **Low Latency**: No network round-trip, instant results
- **Offline Capable**: Works without internet (after initial model download)
- **Predictable**: No API downtime or quota issues

## Installation

### 1. Install Ollama

**macOS:**
```bash
brew install ollama
```

**Linux:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Windows:**
Download from https://ollama.com/download

### 2. Pull Recommended Models

```bash
# Best all-around model (requires 8GB RAM)
ollama pull llama3.1:8b

# Alternative options:
ollama pull mistral:7b        # Faster, good for quick analysis
ollama pull qwen2.5:7b        # Excellent reasoning
ollama pull deepseek-r1:7b    # Strong at technical analysis
```

### 3. Verify Installation

```bash
# Check Ollama is running
ollama list

# Test a model
ollama run llama3.1:8b "Hello, test message"
```

## Model Recommendations

### For Different Hardware

**8GB RAM:**
- `llama3.1:8b` (Recommended)
- `mistral:7b`
- `qwen2.5:7b`

**16GB+ RAM:**
- `llama3.1:70b` (Best quality)
- `qwen2.5:14b`
- `deepseek-r1:14b`

**32GB+ RAM:**
- `llama3.1:70b` (Maximum accuracy)
- `qwen2.5:32b`

### For Different Use Cases

**General SOC Analysis:**
- `llama3.1:8b` - Best balance of speed and accuracy

**Fast Triage:**
- `mistral:7b` - Quick initial assessment

**Deep Analysis:**
- `qwen2.5:14b` - Better reasoning for complex threats

**Technical Code Analysis:**
- `deepseek-r1:7b` - Specialized for code/scripts

## Configuration

Edit `config.yaml`:

```yaml
llm:
  provider: ollama
  ollama_endpoint: http://localhost:11434
  ollama_model: llama3.1:8b  # Change to your preferred model
```

## Testing

### Test IOC Analysis

```bash
python -m src.soc_agent ioc 8.8.8.8
```

Expected output should include LLM analysis section with:
- Verdict
- Confidence score
- Analysis summary
- Recommendations

### Test Email Analysis

```bash
python -m src.soc_agent email sample.eml
```

LLM will analyze:
- Phishing indicators
- Authentication results
- Behavioral patterns

### Test File Analysis

```bash
python -m src.soc_agent file sample.exe
```

LLM will provide:
- Malware family assessment
- Behavioral analysis
- Threat level

## Performance Tuning

### Increase Context Window

For complex analysis, use larger context:

```yaml
llm:
  ollama_model: llama3.1:8b
  # Add context size parameter
  context_size: 8192  # Default: 2048
```

### GPU Acceleration

If you have NVIDIA GPU:

```bash
# Ollama automatically uses GPU if available
# Verify with:
nvidia-smi

# You should see Ollama process using GPU
```

### CPU Optimization

For CPU-only systems:

```yaml
llm:
  ollama_model: mistral:7b  # Faster on CPU
```

## Troubleshooting

### Ollama Not Running

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# If not, start it
ollama serve
```

### Model Not Found

```bash
# List available models
ollama list

# Pull missing model
ollama pull llama3.1:8b
```

### Slow Performance

**Solutions:**
1. Use smaller model: `mistral:7b` instead of `llama3.1:70b`
2. Enable GPU acceleration (NVIDIA only)
3. Increase system RAM
4. Close other applications

### Connection Timeout

Check endpoint in `config.yaml`:
```yaml
llm:
  ollama_endpoint: http://localhost:11434  # Verify port
```

## Advanced: Custom Models

You can use custom fine-tuned models:

```bash
# Create custom model from Modelfile
ollama create soc-analyzer -f Modelfile

# Use in config
llm:
  ollama_model: soc-analyzer
```

Example Modelfile:
```
FROM llama3.1:8b
SYSTEM You are a senior SOC analyst specializing in aviation cybersecurity.
PARAMETER temperature 0.3
```

## Cloud vs Local Comparison

| Feature | Local (Ollama) | Cloud (Anthropic) |
|---------|---------------|-------------------|
| Cost | FREE | $3-15 per million tokens |
| Privacy | ✅ 100% local | ❌ Data sent to cloud |
| Speed | ⚡ Fast (local) | 🌐 Network dependent |
| Compliance | ✅ Aviation-ready | ❌ May violate policies |
| Rate Limits | ✅ None | ❌ API quotas |
| Offline | ✅ Works offline | ❌ Requires internet |

## Recommended Setup for Aviation SOCs

```yaml
llm:
  provider: ollama  # ALWAYS use local
  ollama_endpoint: http://localhost:11434
  ollama_model: llama3.1:8b
  
  # DO NOT configure Anthropic API key
  # Keep data on-premises
```

## Support

- Ollama Documentation: https://github.com/ollama/ollama
- Model Library: https://ollama.com/library
- Community: https://discord.gg/ollama

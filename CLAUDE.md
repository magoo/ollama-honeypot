# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python honeypot that mimics an exposed Ollama LLM instance to capture and log malicious probes from internet scanners. It emulates the Ollama API on port 11434 (the default Ollama port) and logs all requests as single-line JSON to stdout.

## Running the Honeypot

```bash
# Activate virtual environment
source venv/bin/activate

# Run the honeypot
python ollama-honeypot.py
```

The honeypot outputs JSON logs to stdout and status messages to stderr. Logs can be captured with:
```bash
python ollama-honeypot.py > honeypot.log 2>&1
```

## Architecture

**Single-file design**: All honeypot logic is in `ollama-honeypot.py` using only Python standard library (no dependencies).

**Key components in `ollama-honeypot.py`**:
- `OllamaHoneypot` class (extends `http.server.BaseHTTPRequestHandler`) - handles GET/POST/PUT/DELETE requests and mimics Ollama API responses
- `sanitize_output()` - strips control characters and ANSI escapes to prevent log injection attacks
- `log_request_info()` - outputs request data as single-line JSON to stdout
- `get_response_for_query()` - matches incoming prompts against response patterns

**Configuration files**:
- `ollama-honeypot.conf` - INI format with `[honeypot]` section for host, port, max_log_length
- `ollama-honeypot.responses` - Pattern-response mappings in `pattern | response` or `pattern: response` format (case-insensitive, supports partial matching)

## Emulated API Endpoints

The honeypot responds to standard Ollama API routes:
- `GET /` - Returns "Ollama is running"
- `GET /api/tags` - Lists fake models (llama2, mistral)
- `GET /api/ps` - Shows running models
- `POST /api/generate` - Text completion
- `POST /api/chat` - Chat completion
- `POST /api/embed` - Embeddings
- `POST /api/pull`, `/api/push`, `/api/create`, `/api/copy`, `/api/show` - Model management
- `DELETE /api/delete` - Model deletion

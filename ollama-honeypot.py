#!/usr/bin/env python3
"""
Ollama Honeypot - Capture malicious probes targeting exposed Ollama LLM instances
"""

import http.server
import json
import sys
import datetime
import configparser
import random
import time
import os
import socket
import io
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Any, Optional, Tuple
import re


class ProxyProtocolSocket:
    """Wrapper socket that reads PROXY protocol header and provides real client IP"""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buffer = b""
        self.proxy_client_ip: Optional[str] = None
        self.proxy_client_port: Optional[int] = None
        self._parse_proxy_protocol()

    def _parse_proxy_protocol(self) -> None:
        """Parse PROXY protocol v1 header from the start of the connection"""
        # Read until we get \r\n (end of PROXY protocol v1 header)
        while b"\r\n" not in self._buffer:
            chunk = self._sock.recv(1024)
            if not chunk:
                break
            self._buffer += chunk

        if b"\r\n" in self._buffer:
            header_end = self._buffer.index(b"\r\n") + 2
            header = self._buffer[:header_end].decode("utf-8", errors="ignore")
            self._buffer = self._buffer[header_end:]

            # Parse: PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>
            parts = header.strip().split()
            if len(parts) >= 6 and parts[0] == "PROXY" and parts[1] in ("TCP4", "TCP6"):
                self.proxy_client_ip = parts[2]
                try:
                    self.proxy_client_port = int(parts[4])
                except ValueError:
                    pass

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        """Return buffered data first, then read from socket"""
        if self._buffer:
            data = self._buffer[:bufsize]
            self._buffer = self._buffer[bufsize:]
            return data
        return self._sock.recv(bufsize, flags)

    def makefile(self, mode: str = "r", buffering: int = -1) -> Any:
        """Create a file-like object, prepending any buffered data"""
        if self._buffer:
            # Create a combined stream with buffer + socket
            return _BufferedSocketFile(self._buffer, self._sock, mode, buffering)
        return self._sock.makefile(mode, buffering)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sock, name)


class _BufferedSocketFile:
    """File-like wrapper that serves buffered data before socket data"""

    def __init__(self, buffer: bytes, sock: socket.socket, mode: str, buffering: int):
        self._buffer = io.BytesIO(buffer)
        self._sockfile = sock.makefile(mode, buffering)
        self._buffer_exhausted = False

    def read(self, size: int = -1) -> bytes:
        if not self._buffer_exhausted:
            data = self._buffer.read(size)
            if data:
                return data
            self._buffer_exhausted = True
        return self._sockfile.read(size)

    def readline(self, size: int = -1) -> bytes:
        if not self._buffer_exhausted:
            line = self._buffer.readline(size)
            if line:
                return line
            self._buffer_exhausted = True
        return self._sockfile.readline(size)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._sockfile, name)


class ProxyProtocolHTTPServer(http.server.HTTPServer):
    """HTTP server that handles PROXY protocol connections"""

    def get_request(self) -> Tuple[socket.socket, Any]:
        """Accept connection and wrap with PROXY protocol parser"""
        sock, addr = self.socket.accept()
        proxy_sock = ProxyProtocolSocket(sock)

        # If we got a real client IP from PROXY protocol, use it
        if proxy_sock.proxy_client_ip:
            addr = (proxy_sock.proxy_client_ip, proxy_sock.proxy_client_port or addr[1])

        return proxy_sock, addr


class OllamaHoneypot(http.server.BaseHTTPRequestHandler):
    """HTTP handler that mimics Ollama API and logs malicious probes"""

    responses: Dict[str, str] = {}
    config: Dict[str, str] = {}

    def log_message(self, format: str, *args: Any) -> None:
        """Override to prevent default logging"""
        pass

    def sanitize_output(self, text: Any) -> str:
        """Sanitize output to prevent command injection or terminal escape sequences"""
        if not isinstance(text, str):
            text = str(text)

        # Remove control characters except newline/tab
        sanitized = re.sub(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]", "", text)

        # Remove ANSI escape sequences
        sanitized = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", sanitized)

        # Replace newlines with spaces for single-line output
        sanitized = sanitized.replace("\n", " ").replace("\r", " ")

        # Truncate if too long
        max_length = int(self.config.get("max_log_length", 1000))
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "...[truncated]"

        return sanitized

    def get_client_ip(self) -> str:
        """Get real client IP, checking proxy headers first (for fly.io)"""
        # Fly.io sets Fly-Client-IP header with the real client IP
        fly_client_ip = self.headers.get("Fly-Client-IP")
        if fly_client_ip:
            return fly_client_ip

        # Fallback to X-Forwarded-For (first IP in the chain is the client)
        x_forwarded_for = self.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()

        # Default to direct connection IP
        return self.client_address[0]

    def log_request_info(self, body: Optional[str] = None) -> None:
        """Log request details to STDOUT in single-line format"""
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        client_ip = self.get_client_ip()
        method = self.command
        path = self.path
        headers = dict(self.headers)

        # Sanitize all components
        log_entry = {
            "timestamp": timestamp,
            "client_ip": self.sanitize_output(client_ip),
            "method": self.sanitize_output(method),
            "path": self.sanitize_output(path),
            "user_agent": self.sanitize_output(headers.get("User-Agent", "")),
            "content_type": self.sanitize_output(headers.get("Content-Type", "")),
        }

        if body:
            try:
                body_json = json.loads(body) if isinstance(body, str) else body
                log_entry["body"] = self.sanitize_output(json.dumps(body_json))
            except:
                log_entry["body"] = self.sanitize_output(str(body))

        # Output single-line JSON
        print(json.dumps(log_entry), flush=True)

    # Generic LLM-style responses for unknown queries
    GENERIC_RESPONSES = [
        "I'd be happy to help you with that. Could you provide more details about what you're looking for?",
        "That's an interesting question. Let me think about this for a moment. Based on my understanding, I would suggest exploring this topic further by breaking it down into smaller components.",
        "I understand what you're asking. While I can provide some general guidance, I'd recommend being more specific about your particular use case.",
        "Thank you for your question. I'll do my best to assist you with this. The topic you've mentioned has several aspects worth considering.",
        "I appreciate you reaching out. This is something I can help with. Let me share some thoughts on the matter.",
        "That's a great question! There are multiple ways to approach this. Would you like me to elaborate on any specific aspect?",
        "I see what you're asking about. Let me provide some context that might be helpful for your situation.",
        "Interesting query! I'd be glad to assist. Could you clarify what specific outcome you're hoping to achieve?",
        "I'm here to help with that. Based on the information provided, here are some initial thoughts to consider.",
        "Thank you for bringing this up. This is an area where I can offer some guidance. Let me share my perspective.",
    ]

    def simulate_inference_delay(self) -> None:
        """Add realistic delay to simulate LLM inference time"""
        # Random delay between 0.5 and 2.5 seconds
        delay = random.uniform(0.5, 2.5)
        time.sleep(delay)

    def get_response_for_query(self, query: str) -> str:
        """Get response based on query pattern matching with realistic delays"""
        # Simulate LLM inference time
        self.simulate_inference_delay()

        if not query:
            return random.choice(self.GENERIC_RESPONSES)

        query_lower = query.lower().strip()

        # Check for exact matches first
        if query_lower in self.responses:
            return self.responses[query_lower]

        # Check for partial matches (pattern contains query or query contains pattern)
        for pattern, response in self.responses.items():
            if pattern in query_lower or query_lower in pattern:
                return response

        # Return a random generic LLM-style response
        return random.choice(self.GENERIC_RESPONSES)

    def send_json_response(self, status_code: int, data: Dict[str, Any]) -> None:
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_text_response(self, status_code: int, text: str) -> None:
        """Send plain text response"""
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(text)))
        self.end_headers()
        self.wfile.write(text.encode())

    def tokenize_response(self, text: str) -> List[str]:
        """Split response into tokens similar to LLM output"""
        # Split on word boundaries, keeping punctuation as separate tokens
        tokens = []
        current = ""
        for char in text:
            if char in " \t\n":
                if current:
                    tokens.append(current)
                    current = ""
                if char == " ":
                    # Add space to next token
                    current = " "
                elif char == "\n":
                    tokens.append("\n")
            elif char in ".,!?;:\"'()[]{}":
                if current and current != " ":
                    tokens.append(current)
                    current = ""
                tokens.append(char)
            else:
                current += char
        if current:
            tokens.append(current)
        return tokens

    def send_streaming_generate_response(self, model: str, response_text: str) -> None:
        """Send response as streaming tokens for /api/generate"""
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()

        tokens = self.tokenize_response(response_text)
        token_count = len(tokens)

        for token in tokens:
            chunk = {
                "model": model,
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                "response": token,
                "done": False,
            }
            self.wfile.write((json.dumps(chunk) + "\n").encode())
            self.wfile.flush()
            time.sleep(random.uniform(0.015, 0.025))

        # Final message with stats
        final = {
            "model": model,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "response": "",
            "done": True,
            "done_reason": "stop",
            "context": [random.randint(100, 30000) for _ in range(20)],
            "total_duration": random.randint(300000000, 500000000),
            "load_duration": random.randint(20000000, 50000000),
            "prompt_eval_count": random.randint(10, 30),
            "prompt_eval_duration": random.randint(100000000, 300000000),
            "eval_count": token_count,
            "eval_duration": random.randint(30000000, 100000000),
        }
        self.wfile.write((json.dumps(final) + "\n").encode())
        self.wfile.flush()

    def send_streaming_chat_response(self, model: str, response_text: str) -> None:
        """Send response as streaming tokens for /api/chat"""
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.end_headers()

        tokens = self.tokenize_response(response_text)
        token_count = len(tokens)

        for token in tokens:
            chunk = {
                "model": model,
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                "message": {"role": "assistant", "content": token},
                "done": False,
            }
            self.wfile.write((json.dumps(chunk) + "\n").encode())
            self.wfile.flush()
            time.sleep(random.uniform(0.015, 0.025))

        # Final message with stats
        final = {
            "model": model,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "message": {"role": "assistant", "content": ""},
            "done": True,
            "done_reason": "stop",
            "total_duration": random.randint(300000000, 500000000),
            "load_duration": random.randint(20000000, 50000000),
            "prompt_eval_count": random.randint(10, 30),
            "prompt_eval_duration": random.randint(100000000, 300000000),
            "eval_count": token_count,
            "eval_duration": random.randint(30000000, 100000000),
        }
        self.wfile.write((json.dumps(final) + "\n").encode())
        self.wfile.flush()

    def do_GET(self) -> None:
        """Handle GET requests"""
        self.log_request_info()

        # Mimic Ollama API endpoints
        if self.path == "/":
            # Root endpoint returns plain text
            self.send_text_response(200, "Ollama is running")
        elif self.path == "/api":
            # /api returns 404
            self.send_text_response(404, "404 page not found")
        elif self.path == "/api/tags":
            # List available models
            self.send_json_response(
                200,
                {
                    "models": [
                        {
                            "name": "llama2:latest",
                            "model": "llama2:latest",
                            "modified_at": "2024-12-15T10:30:00.000000Z",
                            "size": 3826793677,
                            "digest": "sha256:78e26419b4469263f75331927a00a0284ef6544c1975b826b15abdaef17bb962",
                            "details": {
                                "parent_model": "",
                                "format": "gguf",
                                "family": "llama",
                                "families": ["llama"],
                                "parameter_size": "7B",
                                "quantization_level": "Q4_0",
                            },
                        },
                        {
                            "name": "mistral:latest",
                            "model": "mistral:latest",
                            "modified_at": "2024-12-10T08:15:00.000000Z",
                            "size": 4109865159,
                            "digest": "sha256:f974a74358d686bdc92c40cfc2a5b6b66e6b14ec4fdec8fbeb7c2a85fcef80f6",
                            "details": {
                                "parent_model": "",
                                "format": "gguf",
                                "family": "mistral",
                                "families": ["mistral"],
                                "parameter_size": "7B",
                                "quantization_level": "Q4_0",
                            },
                        },
                    ]
                },
            )
        elif self.path == "/api/ps":
            # List running models
            # Set expiry 5 minutes in the future (realistic keepalive)
            expires = (
                datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
            ).isoformat() + "Z"
            self.send_json_response(
                200,
                {
                    "models": [
                        {
                            "name": "llama2:latest",
                            "model": "llama2:latest",
                            "size": 3826793677,
                            "digest": "sha256:78e26419b4469263f75331927a00a0284ef6544c1975b826b15abdaef17bb962",
                            "details": {
                                "parent_model": "",
                                "format": "gguf",
                                "family": "llama",
                                "families": ["llama"],
                                "parameter_size": "7B",
                                "quantization_level": "Q4_0",
                            },
                            "expires_at": expires,
                            "size_vram": 3826793677,
                        }
                    ]
                },
            )
        elif self.path == "/api/version":
            # Version endpoint - critical for scanner detection
            self.send_json_response(200, {"version": "0.5.4"})
        elif self.path == "/v1/models":
            # OpenAI-compatible models endpoint
            self.send_json_response(
                200,
                {
                    "object": "list",
                    "data": [
                        {
                            "id": "llama2:latest",
                            "object": "model",
                            "created": 1704067200,
                            "owned_by": "library",
                        },
                        {
                            "id": "mistral:latest",
                            "object": "model",
                            "created": 1704067200,
                            "owned_by": "library",
                        },
                    ],
                },
            )
        else:
            self.send_text_response(404, "404 page not found")

    def do_POST(self) -> None:
        """Handle POST requests"""
        content_length = int(self.headers.get("Content-Length", 0))
        body = (
            self.rfile.read(content_length).decode("utf-8", errors="ignore")
            if content_length > 0
            else ""
        )

        self.log_request_info(body)

        # Parse body for potential prompts
        try:
            data = json.loads(body) if body else {}
        except:
            data = {}

        # Mimic Ollama API endpoints
        if self.path == "/api/generate":
            # Generate completion
            prompt = data.get("prompt", "")
            model = data.get("model", "llama2:latest")
            stream = data.get("stream", True)

            response_text = self.get_response_for_query(prompt)

            if stream:
                # Streaming response (default)
                self.send_streaming_generate_response(model, response_text)
            else:
                # Non-streaming response
                self.send_json_response(
                    200,
                    {
                        "model": model,
                        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                        "response": response_text,
                        "done": True,
                        "done_reason": "stop",
                        "total_duration": 5000000000,
                        "load_duration": 1000000000,
                        "prompt_eval_count": 10,
                        "prompt_eval_duration": 2000000000,
                        "eval_count": 20,
                        "eval_duration": 2000000000,
                    },
                )

        elif self.path == "/api/chat":
            # Chat completion
            messages = data.get("messages", [])
            model = data.get("model", "llama2:latest")
            stream = data.get("stream", True)

            # Extract last user message as query
            query = ""
            if messages:
                for msg in reversed(messages):
                    if isinstance(msg, dict) and msg.get("role") == "user":
                        query = msg.get("content", "")
                        break

            response_text = self.get_response_for_query(query)

            if stream:
                self.send_streaming_chat_response(model, response_text)
            else:
                self.send_json_response(
                    200,
                    {
                        "model": model,
                        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                        "message": {"role": "assistant", "content": response_text},
                        "done": True,
                        "done_reason": "stop",
                        "total_duration": 5000000000,
                        "load_duration": 1000000000,
                        "prompt_eval_count": 15,
                        "prompt_eval_duration": 2000000000,
                        "eval_count": 25,
                        "eval_duration": 2000000000,
                    },
                )

        elif self.path == "/api/embed":
            # Generate embeddings
            input_text = data.get("input", "")
            model = data.get("model", "llama2:latest")

            # Return fake embeddings
            self.send_json_response(
                200,
                {
                    "model": model,
                    "embeddings": [
                        [
                            0.010071029,
                            -0.0017594862,
                            0.05007221,
                            0.04692972,
                            0.054916814,
                        ]
                    ],
                    "total_duration": 14143917,
                    "load_duration": 1019500,
                    "prompt_eval_count": 8,
                },
            )

        elif self.path == "/api/pull":
            # Pull model
            model = data.get("model", "")
            self.send_json_response(200, {"status": "success"})

        elif self.path == "/api/push":
            # Push model
            model = data.get("model", "")
            self.send_json_response(200, {"status": "success"})

        elif self.path == "/api/create":
            # Create model
            self.send_json_response(200, {"status": "success"})

        elif self.path == "/api/copy":
            # Copy model
            self.send_json_response(200, {"status": "success"})

        elif self.path == "/api/show":
            # Show model details - must include modelfile and model_info
            model = data.get("model", "llama2:latest")

            # Model-specific details
            if "mistral" in model.lower():
                family = "mistral"
                template = "[INST] {{ .Prompt }} [/INST]"
                modelfile = 'FROM mistral:latest\nPARAMETER temperature 0.7\nPARAMETER num_ctx 4096\nSYSTEM """You are a helpful AI assistant."""'
                model_info = {
                    "general.architecture": "mistral",
                    "general.file_type": 2,
                    "general.parameter_count": 7241732096,
                    "general.quantization_version": 2,
                    "mistral.attention.head_count": 32,
                    "mistral.attention.head_count_kv": 8,
                    "mistral.block_count": 32,
                    "mistral.context_length": 32768,
                    "mistral.embedding_length": 4096,
                    "mistral.feed_forward_length": 14336,
                }
            else:
                family = "llama"
                template = "[INST] <<SYS>>\n{{ .System }}\n<</SYS>>\n\n{{ .Prompt }} [/INST]"
                modelfile = 'FROM llama2:latest\nPARAMETER temperature 0.7\nPARAMETER num_ctx 4096\nSYSTEM """You are a helpful AI assistant."""'
                model_info = {
                    "general.architecture": "llama",
                    "general.file_type": 2,
                    "general.parameter_count": 6738415616,
                    "general.quantization_version": 2,
                    "llama.attention.head_count": 32,
                    "llama.attention.head_count_kv": 32,
                    "llama.block_count": 32,
                    "llama.context_length": 4096,
                    "llama.embedding_length": 4096,
                    "llama.feed_forward_length": 11008,
                }

            self.send_json_response(
                200,
                {
                    "modelfile": modelfile,
                    "parameters": "temperature 0.7\nnum_ctx 4096",
                    "template": template,
                    "details": {
                        "parent_model": "",
                        "format": "gguf",
                        "family": family,
                        "families": [family],
                        "parameter_size": "7B",
                        "quantization_level": "Q4_0",
                    },
                    "model_info": model_info,
                    "modified_at": "2024-12-15T10:30:00.000000Z",
                    "capabilities": ["completion"],
                },
            )

        elif self.path == "/v1/chat/completions":
            # OpenAI-compatible chat completions
            messages = data.get("messages", [])
            model = data.get("model", "llama2:latest")

            # Extract last user message as query
            query = ""
            if messages:
                for msg in reversed(messages):
                    if isinstance(msg, dict) and msg.get("role") == "user":
                        query = msg.get("content", "")
                        break

            response_text = self.get_response_for_query(query)
            timestamp = int(datetime.datetime.utcnow().timestamp())

            self.send_json_response(
                200,
                {
                    "id": f"chatcmpl-{timestamp}",
                    "object": "chat.completion",
                    "created": timestamp,
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": response_text},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 15,
                        "completion_tokens": 25,
                        "total_tokens": 40,
                    },
                },
            )

        elif self.path == "/v1/completions":
            # OpenAI-compatible text completions
            prompt = data.get("prompt", "")
            model = data.get("model", "llama2:latest")

            response_text = self.get_response_for_query(prompt)
            timestamp = int(datetime.datetime.utcnow().timestamp())

            self.send_json_response(
                200,
                {
                    "id": f"cmpl-{timestamp}",
                    "object": "text_completion",
                    "created": timestamp,
                    "model": model,
                    "choices": [
                        {
                            "text": response_text,
                            "index": 0,
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 20,
                        "total_tokens": 30,
                    },
                },
            )

        elif self.path == "/v1/embeddings":
            # OpenAI-compatible embeddings
            model = data.get("model", "llama2:latest")

            # Return fake 1536-dimensional embedding (OpenAI ada-002 size)
            fake_embedding = [0.001 * i for i in range(1536)]

            self.send_json_response(
                200,
                {
                    "object": "list",
                    "data": [
                        {
                            "object": "embedding",
                            "index": 0,
                            "embedding": fake_embedding,
                        }
                    ],
                    "model": model,
                    "usage": {"prompt_tokens": 8, "total_tokens": 8},
                },
            )

        else:
            self.send_json_response(200, {"status": "ok"})

    def do_DELETE(self) -> None:
        """Handle DELETE requests"""
        content_length = int(self.headers.get("Content-Length", 0))
        body = (
            self.rfile.read(content_length).decode("utf-8", errors="ignore")
            if content_length > 0
            else ""
        )
        self.log_request_info(body)

        # Mimic DELETE endpoints
        if self.path == "/api/delete":
            # Delete model - return 200 with no body
            self.send_response(200)
            self.end_headers()
        else:
            self.send_text_response(404, "404 page not found")

    def do_PUT(self) -> None:
        """Handle PUT requests"""
        content_length = int(self.headers.get("Content-Length", 0))
        body = (
            self.rfile.read(content_length).decode("utf-8", errors="ignore")
            if content_length > 0
            else ""
        )
        self.log_request_info(body)
        self.send_json_response(200, {"status": "ok"})


def get_script_dir() -> str:
    """Get directory where the script is located"""
    return os.path.dirname(os.path.abspath(__file__))


def load_config(config_file: str = "ollama-honeypot.conf") -> Dict[str, str]:
    """Load configuration from file and environment variables"""
    config = configparser.ConfigParser()

    # Defaults
    defaults = {"host": "0.0.0.0", "port": "11434", "max_log_length": "1000"}

    # Try config file in script directory first, then current directory
    script_dir = get_script_dir()
    config_paths = [
        os.path.join(script_dir, config_file),
        config_file,
    ]

    file_config = {}
    for path in config_paths:
        if os.path.exists(path):
            config.read(path)
            if "honeypot" in config:
                file_config = dict(config["honeypot"])
                break

    # Merge: defaults < file config < environment variables
    result = {**defaults, **file_config}

    # Environment variables override (useful for container deployments)
    if os.environ.get("HOST"):
        result["host"] = os.environ["HOST"]
    if os.environ.get("PORT"):
        result["port"] = os.environ["PORT"]
    if os.environ.get("MAX_LOG_LENGTH"):
        result["max_log_length"] = os.environ["MAX_LOG_LENGTH"]

    return result


def load_responses(responses_file: str = "ollama-honeypot.responses") -> Dict[str, str]:
    """Load responses from file as pattern -> response mapping"""
    responses: Dict[str, str] = {}

    # Try responses file in script directory first, then current directory
    script_dir = get_script_dir()
    responses_paths = [
        os.path.join(script_dir, responses_file),
        responses_file,
    ]

    file_path = None
    for path in responses_paths:
        if os.path.exists(path):
            file_path = path
            break

    if file_path:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Format: pattern|response or pattern: response
                    if "|" in line:
                        parts = line.split("|", 1)
                        if len(parts) == 2:
                            pattern = parts[0].strip().lower()
                            response = parts[1].strip()
                            responses[pattern] = response
                    elif ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            pattern = parts[0].strip().lower()
                            response = parts[1].strip()
                            responses[pattern] = response

    # Default responses if file doesn't exist or is empty
    if not responses:
        responses = {
            "hello": "I'm here to help you with your questions.",
            "help": "I can assist you with various tasks and information.",
        }

    return responses


def main() -> None:
    """Main entry point"""
    # Load configuration
    config = load_config()
    responses = load_responses()

    # Set class variables
    OllamaHoneypot.config = config
    OllamaHoneypot.responses = responses

    host = config.get("host", "0.0.0.0")
    port = int(config.get("port", 11434))

    # Start server with PROXY protocol support (for fly.io)
    server = ProxyProtocolHTTPServer((host, port), OllamaHoneypot)

    print(f"[HONEYPOT] Ollama Honeypot starting on {host}:{port}", file=sys.stderr)
    print(f"[HONEYPOT] Loaded {len(responses)} responses", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[HONEYPOT] Shutting down...", file=sys.stderr)
        server.shutdown()


if __name__ == "__main__":
    main()

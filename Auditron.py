#!/usr/bin/env python3
"""
Auditron - MITM Proxy Suite for Linux Parrot

A powerful interception proxy with Burp Suite‑like capabilities:
- Intercepts HTTP/HTTPS/WebSocket traffic
- Saves events to .txt files (customizable folder)
- Shows live events in mitmproxy's terminal UI
- Encode/decode data (Base64, Hex, URL, JWT, ROT13, etc.)
- Auto‑detect encoding types
- Custom encoder support via Python code injection
- Optional AI analysis (GPT‑5.2) via Emergent API key

Usage:
    mitmproxy -s Auditron.py
    mitmdump -s Auditron.py              # non‑interactive logging
    mitmweb -s Auditron.py               # web interface

Environment variables:
    AUDITRON_STORAGE_DIR   Directory for .txt files (default: ~/auditron_captures)
    EMERGENT_LLM_KEY       API key for GPT‑5.2 analysis (optional)
"""

import os
import re
import base64
import hashlib
import json
import urllib.parse
import html
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from mitmproxy import ctx, http, websocket

# ============================================================================
# Configuration
# ============================================================================
STORAGE_DIR = Path(os.environ.get('AUDITRON_STORAGE_DIR', Path.home() / 'auditron_captures'))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

EMERGENT_API_KEY = os.environ.get('EMERGENT_LLM_KEY')
AI_ENABLED = bool(EMERGENT_API_KEY)

# ============================================================================
# Encoder/Decoder Utilities
# ============================================================================
class EncoderDecoder:
    """Multi‑format encoder/decoder with auto‑detection"""

    HASH_PATTERNS = {
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$',
        'sha512': r'^[a-fA-F0-9]{128}$',
        'base64': r'^[A-Za-z0-9+/]+={0,2}$',
        'jwt': r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$',
        'hex': r'^[a-fA-F0-9]+$',
        'url_encoded': r'%[0-9A-Fa-f]{2}',
    }

    @staticmethod
    def identify(data: str) -> List[str]:
        matches = []
        for enc, pattern in EncoderDecoder.HASH_PATTERNS.items():
            if re.match(pattern, data):
                matches.append(enc)
        if data.startswith('0x'):
            matches.append('hex_prefixed')
        try:
            json.loads(data)
            matches.append('json')
        except:
            pass
        return matches or ['plaintext']

    @staticmethod
    def base64_encode(data: str) -> str:
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def base64_decode(data: str) -> Tuple[str, Optional[str]]:
        try:
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.b64decode(data).decode(), None
        except Exception as e:
            return '', str(e)

    @staticmethod
    def hex_encode(data: str) -> str:
        return data.encode().hex()

    @staticmethod
    def hex_decode(data: str) -> Tuple[str, Optional[str]]:
        try:
            clean = data.replace('0x', '').replace(' ', '')
            return bytes.fromhex(clean).decode(), None
        except Exception as e:
            return '', str(e)

    @staticmethod
    def url_encode(data: str) -> str:
        return urllib.parse.quote(data, safe='')

    @staticmethod
    def url_decode(data: str) -> Tuple[str, Optional[str]]:
        try:
            return urllib.parse.unquote(data), None
        except Exception as e:
            return '', str(e)

    @staticmethod
    def html_encode(data: str) -> str:
        return html.escape(data)

    @staticmethod
    def html_decode(data: str) -> Tuple[str, Optional[str]]:
        try:
            return html.unescape(data), None
        except Exception as e:
            return '', str(e)

    @staticmethod
    def rot13(data: str) -> str:
        result = []
        for c in data:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def jwt_decode(token: str) -> Tuple[Dict[str, Any], Optional[str]]:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {}, "Invalid JWT format"
            hdr = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(hdr))
            pay = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(pay))
            return {'header': header, 'payload': payload, 'signature': parts[2]}, None
        except Exception as e:
            return {}, str(e)

    @staticmethod
    def generate_hash(data: str, algorithm: str) -> Tuple[str, Optional[str]]:
        algos = {'md5': hashlib.md5, 'sha1': hashlib.sha1,
                 'sha256': hashlib.sha256, 'sha512': hashlib.sha512}
        if algorithm not in algos:
            return '', f"Unsupported algorithm: {algorithm}"
        try:
            return algos[algorithm](data.encode()).hexdigest(), None
        except Exception as e:
            return '', str(e)


# ============================================================================
# Custom Encoder Registry
# ============================================================================
_custom_encoders: Dict[str, str] = {}

def register_custom_encoder(name: str, code: str):
    _custom_encoders[name] = code

def execute_custom_encoder(name: str, data: str, operation: str = 'encode') -> Tuple[str, Optional[str]]:
    if name not in _custom_encoders:
        return '', f"Custom encoder '{name}' not found"
    try:
        safe_globals = {
            '__builtins__': {
                'str': str, 'int': int, 'float': float, 'list': list,
                'dict': dict, 'len': len, 'range': range, 'ord': ord,
                'chr': chr, 'hex': hex, 'bin': bin, 'oct': oct,
                'base64': base64, 'hashlib': hashlib, 'json': json,
            }
        }
        safe_locals = {'data': data, 'operation': operation, 'result': ''}
        exec(_custom_encoders[name], safe_globals, safe_locals)
        return safe_locals.get('result', ''), None
    except Exception as e:
        return '', str(e)


# ============================================================================
# AI Analysis (if enabled)
# ============================================================================
async def analyze_with_ai(flow, query: str = "") -> str:
    if not AI_ENABLED:
        return "AI analysis disabled (set EMERGENT_LLM_KEY)"
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        system = "You are Auditron AI, an expert in network security analysis."
        chat = LlmChat(api_key=EMERGENT_API_KEY, system_message=system).with_model("openai", "gpt-5.2")
        context = f"""
Intercepted request:
Method: {flow.request.method}
URL: {flow.request.url}
Headers: {dict(flow.request.headers)}
Body: {flow.request.text if flow.request.text else 'None'}
Response status: {flow.response.status_code if flow.response else 'N/A'}
User query: {query or 'Analyze this traffic for vulnerabilities.'}
"""
        response = await chat.send_message(UserMessage(text=context))
        return response
    except Exception as e:
        return f"AI error: {e}"


# ============================================================================
# mitmproxy Addon
# ============================================================================
class Auditron:
    """Main addon that intercepts, logs, and optionally modifies traffic."""

    def __init__(self):
        self.request_count = 0
        self.storage_dir = STORAGE_DIR
        self.encoder = EncoderDecoder()

    def load(self, loader):
        loader.add_option("auditron_storage", str, str(self.storage_dir),
                          "Directory to store .txt files")
        loader.add_option("auditron_ai", bool, AI_ENABLED,
                          "Enable AI analysis (requires API key)")

    def configure(self, updates):
        if "auditron_storage" in updates:
            # Get the new value from ctx.master.options
            new_path = ctx.master.options.auditron_storage
            self.storage_dir = Path(new_path)
            self.storage_dir.mkdir(parents=True, exist_ok=True)

    def request(self, flow: http.HTTPFlow):
        self.request_count += 1
        ctx.log.info(f"[{self.request_count}] {flow.request.method} {flow.request.url}")

    def response(self, flow: http.HTTPFlow):
        method = flow.request.method
        url = flow.request.url
        host = flow.request.host
        path = flow.request.path
        status = flow.response.status_code if flow.response else None

        req_headers = dict(flow.request.headers)
        resp_headers = dict(flow.response.headers) if flow.response else {}

        req_body = flow.request.text if flow.request.text else None
        if req_body and len(req_body) > 10000:
            req_body = req_body[:10000] + "...[TRUNCATED]"

        resp_body = flow.response.text if flow.response and flow.response.text else None
        if resp_body and len(resp_body) > 10000:
            resp_body = resp_body[:10000] + "...[TRUNCATED]"

        tokens = self.extract_tokens(req_headers, req_body, resp_headers, resp_body)
        ids = self.extract_ids(url, flow.request.query)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        ctx.log.info(
            f"Response: {method} {url} → {status} "
            f"(Tokens: {len(tokens)}, IDs: {len(ids)})"
        )

        filename = f"{host}_{method}_{self.request_count}.txt"
        filepath = self.storage_dir / filename
        content = self.format_event(
            request_count=self.request_count,
            timestamp=timestamp,
            method=method,
            url=url,
            host=host,
            path=path,
            status=status,
            req_headers=req_headers,
            resp_headers=resp_headers,
            req_body=req_body,
            resp_body=resp_body,
            tokens=tokens,
            ids=ids,
        )
        filepath.write_text(content, encoding='utf-8')
        ctx.log.debug(f"Saved to {filepath}")

    def websocket_message(self, flow: http.HTTPFlow, message: websocket.WebSocketMessage):
        ctx.log.info(
            f"WebSocket {flow.request.url}: "
            f"{'client' if message.from_client else 'server'} -> {message.content[:100]}"
        )

    def extract_tokens(self, req_headers, req_body, resp_headers, resp_body) -> List[str]:
        tokens = []
        jwt_pattern = r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
        for header, value in req_headers.items():
            if 'auth' in header.lower() or 'token' in header.lower():
                tokens.append(value)
            tokens.extend(re.findall(jwt_pattern, str(value)))
        for header, value in resp_headers.items():
            if 'auth' in header.lower() or 'token' in header.lower():
                tokens.append(value)
            tokens.extend(re.findall(jwt_pattern, str(value)))
        if req_body:
            tokens.extend(re.findall(jwt_pattern, req_body))
        if resp_body:
            tokens.extend(re.findall(jwt_pattern, resp_body))
        return list(set(tokens))

    def extract_ids(self, url: str, query: Dict) -> List[str]:
        ids = []
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        ids.extend(re.findall(uuid_pattern, url, re.IGNORECASE))
        for key, value in query.items():
            if 'id' in key.lower():
                ids.append(value)
        return list(set(ids))

    def format_event(self, **kwargs) -> str:
        lines = [
            "=" * 80,
            "AUDITRON - Intercepted Event",
            "=" * 80,
            f"# {kwargs['request_count']}",
            f"Time: {kwargs['timestamp']}",
            f"Method: {kwargs['method']}",
            f"URL: {kwargs['url']}",
            f"Host: {kwargs['host']}",
            f"Path: {kwargs['path']}",
            f"Status: {kwargs['status']}",
            "",
            "--- Request Headers ---"
        ]
        for k, v in kwargs['req_headers'].items():
            lines.append(f"  {k}: {v}")
        if kwargs['req_body']:
            lines.extend(["", "--- Request Body ---", kwargs['req_body']])
        lines.extend(["", "--- Response Headers ---"])
        for k, v in kwargs['resp_headers'].items():
            lines.append(f"  {k}: {v}")
        if kwargs['resp_body']:
            lines.extend(["", "--- Response Body ---", kwargs['resp_body']])
        if kwargs['tokens']:
            lines.extend(["", "--- Tokens Detected ---", *kwargs['tokens']])
        if kwargs['ids']:
            lines.extend(["", "--- IDs Detected ---", *kwargs['ids']])
        lines.extend(["", "=" * 80])
        return "\n".join(lines)


# ============================================================================
# Optional: Command‑line interface for encoding (standalone)
# ============================================================================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Auditron encoding utilities")
    parser.add_argument("--encode", help="Encoding type (base64, hex, url, html, rot13)")
    parser.add_argument("--decode", help="Decoding type")
    parser.add_argument("--data", required=True, help="Input data")
    parser.add_argument("--identify", action="store_true", help="Identify encoding")
    args = parser.parse_args()

    enc = EncoderDecoder()
    if args.identify:
        print("Possible encodings:", ", ".join(enc.identify(args.data)))
    elif args.encode:
        if args.encode == "base64":
            print(enc.base64_encode(args.data))
        elif args.encode == "hex":
            print(enc.hex_encode(args.data))
        elif args.encode == "url":
            print(enc.url_encode(args.data))
        elif args.encode == "html":
            print(enc.html_encode(args.data))
        elif args.encode == "rot13":
            print(enc.rot13(args.data))
        else:
            print(f"Unsupported encoding: {args.encode}")
    elif args.decode:
        if args.decode == "base64":
            res, err = enc.base64_decode(args.data)
        elif args.decode == "hex":
            res, err = enc.hex_decode(args.data)
        elif args.decode == "url":
            res, err = enc.url_decode(args.data)
        elif args.decode == "html":
            res, err = enc.html_decode(args.data)
        elif args.decode == "rot13":
            res = enc.rot13(args.data)
            err = None
        else:
            print(f"Unsupported decoding: {args.decode}")
            exit(1)
        if err:
            print(f"Error: {err}")
        else:
            print(res)
    else:
        parser.print_help()


# ============================================================================
# Entry point for mitmproxy
# ============================================================================
addons = [Auditron()]

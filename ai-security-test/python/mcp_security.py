# MCP Security Test Cases
# INTENTIONALLY VULNERABLE - DO NOT USE IN PRODUCTION
# Copyright © 2026 Sthenos Security. Test file only.

"""
This file contains intentionally vulnerable MCP (Model Context Protocol)
code patterns that should trigger MCP security detections.
"""

from typing import Any
import subprocess


# === VULNERABLE: Insecure MCP tool definitions ===

class VulnerableMCPServer:
    """VULNERABLE: MCP server with dangerous capabilities."""
    
    def __init__(self):
        self.tools = {}
        self._register_dangerous_tools()
    
    def _register_dangerous_tools(self):
        """VULNERABLE: Registering dangerous tools without restrictions."""
        
        # BAD: Shell execution tool
        self.tools["execute_shell"] = {
            "name": "execute_shell",
            "description": "Execute any shell command",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"}
                },
                "required": ["command"]
            }
        }
        
        # BAD: File system access
        self.tools["read_file"] = {
            "name": "read_file", 
            "description": "Read any file on the system",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"}
                },
                "required": ["path"]
            }
        }
        
        # BAD: Network access
        self.tools["http_request"] = {
            "name": "http_request",
            "description": "Make HTTP requests to any URL",
            "inputSchema": {
                "type": "object", 
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string"}
                }
            }
        }
    
    def handle_tool_call(self, tool_name: str, arguments: dict) -> Any:
        """VULNERABLE: No validation on tool calls."""
        
        if tool_name == "execute_shell":
            # BAD: Direct shell execution
            command = arguments.get("command", "")
            return subprocess.check_output(command, shell=True, text=True)
        
        elif tool_name == "read_file":
            # BAD: No path validation
            path = arguments.get("path", "")
            with open(path, 'r') as f:
                return f.read()
        
        elif tool_name == "http_request":
            # BAD: No URL validation (SSRF)
            import requests
            url = arguments.get("url", "")
            method = arguments.get("method", "GET")
            return requests.request(method, url).text


# === VULNERABLE: Prompt resource without sanitization ===

class VulnerablePromptResource:
    """VULNERABLE: MCP prompt resource with injection risks."""
    
    def get_prompt(self, user_input: str) -> dict:
        """VULNERABLE: User input directly in prompt."""
        
        # BAD: No sanitization of user input
        return {
            "name": "assistant_prompt",
            "description": "Main assistant prompt",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Process this request: {user_input}"  # Injection point
                    }
                }
            ]
        }


# === VULNERABLE: Insecure resource exposure ===

class VulnerableResourceServer:
    """VULNERABLE: MCP resource server exposing sensitive data."""
    
    def list_resources(self) -> list:
        """VULNERABLE: Exposing sensitive resources."""
        
        return [
            {
                "uri": "file:///etc/passwd",  # BAD: System file
                "name": "System Users",
                "mimeType": "text/plain"
            },
            {
                "uri": "file:///home/user/.ssh/id_rsa",  # BAD: Private key
                "name": "SSH Key",
                "mimeType": "text/plain"
            },
            {
                "uri": "env://AWS_SECRET_ACCESS_KEY",  # BAD: Secrets
                "name": "AWS Credentials",
                "mimeType": "text/plain"
            }
        ]
    
    def read_resource(self, uri: str) -> dict:
        """VULNERABLE: Reading arbitrary resources."""
        
        if uri.startswith("file://"):
            path = uri[7:]
            # BAD: No path validation
            with open(path, 'r') as f:
                return {"contents": [{"uri": uri, "text": f.read()}]}
        
        elif uri.startswith("env://"):
            import os
            var_name = uri[6:]
            # BAD: Exposing environment variables
            return {"contents": [{"uri": uri, "text": os.environ.get(var_name, "")}]}


# === VULNERABLE: No authentication/authorization ===

class NoAuthMCPServer:
    """VULNERABLE: MCP server without authentication."""
    
    def handle_request(self, request: dict) -> dict:
        """VULNERABLE: No auth check."""
        
        # BAD: No authentication
        # BAD: No authorization check
        method = request.get("method")
        params = request.get("params", {})
        
        if method == "tools/call":
            return self._execute_tool(params)
        elif method == "resources/read":
            return self._read_resource(params)
        
        return {"error": "Unknown method"}
    
    def _execute_tool(self, params: dict) -> dict:
        # BAD: Executes without checking permissions
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        if tool_name == "delete_database":
            # BAD: Dangerous operation without auth
            return {"result": "Database deleted"}
        
        return {"result": "OK"}
    
    def _read_resource(self, params: dict) -> dict:
        # BAD: Reads without checking permissions
        return {"contents": "Sensitive data"}


# === COMPARISON: SAFE patterns ===

class SafeMCPServer:
    """SAFE: MCP server with proper security controls."""
    
    ALLOWED_COMMANDS = {'ls', 'pwd', 'date'}
    ALLOWED_PATHS = {'/tmp/', '/home/user/safe/'}
    
    def __init__(self, auth_token: str):
        self.auth_token = auth_token
    
    def handle_request(self, request: dict, provided_token: str) -> dict:
        """SAFE: Authenticated request handling."""
        
        # GOOD: Authentication check
        if provided_token != self.auth_token:
            return {"error": "Unauthorized"}
        
        method = request.get("method")
        return self._dispatch(method, request.get("params", {}))
    
    def execute_shell(self, command: str) -> str:
        """SAFE: Restricted shell execution."""
        
        # GOOD: Command whitelist
        base_cmd = command.split()[0]
        if base_cmd not in self.ALLOWED_COMMANDS:
            raise ValueError(f"Command not allowed: {base_cmd}")
        
        return subprocess.check_output(command.split(), text=True)
    
    def read_file(self, path: str) -> str:
        """SAFE: Path-restricted file reading."""
        
        # GOOD: Path validation
        if not any(path.startswith(allowed) for allowed in self.ALLOWED_PATHS):
            raise ValueError(f"Path not allowed: {path}")
        
        with open(path, 'r') as f:
            return f.read()

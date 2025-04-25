# 🛡️ BurpSuite MCP Server

A powerful Model Context Protocol (MCP) server implementation for BurpSuite, providing programmatic access to Burp's core functionalities.
<a href="https://glama.ai/mcp/servers/@X3r0K/BurpSuite-MCP-Server">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@X3r0K/BurpSuite-MCP-Server/badge" />
</a>
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)


## 🚀 Features

### 🔄 Proxy Tool
- Intercept and modify HTTP/HTTPS traffic
- View and manipulate requests/responses
- Access proxy history
- Real-time request/response manipulation

```bash
# Intercept a request
curl -X POST "http://localhost:8000/proxy/intercept" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "method": "GET",
    "headers": {"User-Agent": "Custom"},
    "intercept": true
  }'

# View proxy history
curl "http://localhost:8000/proxy/history"
```

### 🔍 Scanner Tool
- Active and passive scanning
- Custom scan configurations
- Real-time issue tracking
- Scan status monitoring

```bash
# Start a new scan
curl -X POST "http://localhost:8000/scanner/start" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "scan_type": "active",
    "scan_configurations": {
      "scope": "strict",
      "audit_checks": ["xss", "sqli"]
    }
  }'

# Check scan status
curl "http://localhost:8000/scanner/status/scan_1"

# Stop a scan
curl -X DELETE "http://localhost:8000/scanner/stop/scan_1"
```

### 📝 Logger Tool
- Comprehensive HTTP traffic logging
- Advanced filtering and search
- Vulnerability detection
- Traffic analysis
- Suspicious pattern detection

```bash
# Get filtered logs
curl "http://localhost:8000/logger/logs?filter[method]=POST&filter[status_code]=200"

# Search logs
curl "http://localhost:8000/logger/logs?search=password"

# Get vulnerability analysis
curl "http://localhost:8000/logger/vulnerabilities"

# Get comprehensive analysis
curl "http://localhost:8000/logger/analysis"

# Clear logs
curl -X DELETE "http://localhost:8000/logger/clear"

curl "http://localhost:8000/logger/vulnerabilities/severity"
```

### 🎯 Vulnerability Detection
Automatically detects multiple types of vulnerabilities:
- 🔥 XSS (Cross-Site Scripting)
- 💉 SQL Injection
- 🗂️ Path Traversal
- 📁 File Inclusion
- 🌐 SSRF (Server-Side Request Forgery)
- 📄 XXE (XML External Entity)
- 🔒 CSRF (Cross-Site Request Forgery)
- 🔄 Open Redirect
- ⚡ Command Injection

## 🛠️ Setup

1. **Clone the repository**

```bash
git clone https://github.com/X3r0K/BurpSuite-MCP-Server.git
cd BurpSuite-MCP-Server
```

1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

2. **Configure Environment**
```bash
# Copy .env.example to .env
cp .env.example .env

# Update the values in .env
BURP_API_KEY=Your_API_KEY
BURP_API_HOST=localhost
BURP_API_PORT=1337
BURP_PROXY_HOST=127.0.0.1
BURP_PROXY_PORT=8080
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8000
```

3. **Start the Server**
```bash
python main.py
```

The server will start on http://localhost:8000

## 📊 Analysis Features

### Traffic Analysis
- Total requests count
- Unique URLs
- HTTP method distribution
- Status code distribution
- Content type analysis
- Average response time

### Vulnerability Analysis
- Vulnerability type summary
- Top vulnerable endpoints
- Suspicious patterns
- Real-time vulnerability detection

### Log Filtering
- By HTTP method
- By status code
- By URL pattern
- By content type
- By content length
- By time range
- By vulnerability type

## 🔒 Security Considerations

1. Run in a secure environment
2. Configure appropriate authentication
3. Use HTTPS in production
4. Keep BurpSuite API key secure
5. Monitor and audit access

## 📚 API Documentation

For detailed API documentation, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
![image](https://github.com/user-attachments/assets/a9af7fb9-b840-40ef-b8b7-b24a9bcbc72a)


## Cursor Integration

The MCP server is configured to work seamlessly with Cursor IDE. The `.cursor` directory contains all necessary configuration files:

### Configuration Files

1. `settings.json`: Contains MCP server configuration
   - Server host and port settings
   - Endpoint configurations
   - BurpSuite proxy settings
   - Logger settings
   - Python interpreter path

2. `tasks.json`: Defines common tasks
   - Start MCP Server
   - Run Vulnerability Tests
   - Check Vulnerabilities

3. `launch.json`: Contains debugging configurations
   - Debug MCP Server
   - Debug Vulnerability Tests

### Using in Cursor

1. Open the project in Cursor
2. The MCP server configuration will be automatically loaded
3. Access features through:
   - Command Palette (Ctrl+Shift+P) for running tasks
   - Debug menu for debugging sessions
   - Automatic Python interpreter configuration

The server will be accessible at `http://localhost:8000` with the following endpoints:
- `/proxy/intercept` for request interception
- `/logger` for logging functionality
- `/logger/vulnerabilities/severity` for vulnerability analysis

![image](https://github.com/user-attachments/assets/7e006b2a-a9f7-4d09-85da-fd6fea5d352c)


![image](https://github.com/user-attachments/assets/e3376c42-5966-4fe8-a1d0-08916bd60b06)


## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [BurpSuite](https://portswigger.net/burp) - The original security testing tool
- [FastAPI](https://fastapi.tiangolo.com/) - The web framework used
- [Python](https://www.python.org/) - The programming language used


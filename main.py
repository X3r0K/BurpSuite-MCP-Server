from fastapi import FastAPI, HTTPException, WebSocket, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, List, Any, Set
import uvicorn
import json
import asyncio
import aiohttp
from datetime import datetime
import os
from dotenv import load_dotenv
import logging
import requests
from urllib.parse import urlparse
import urllib3
import re
from collections import defaultdict

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# BurpSuite Configuration
BURP_PROXY_HOST = os.getenv("BURP_PROXY_HOST", "127.0.0.1")
BURP_PROXY_PORT = int(os.getenv("BURP_PROXY_PORT", "8080"))
BURP_PROXY_URL = f"http://{BURP_PROXY_HOST}:{BURP_PROXY_PORT}"

# Configure requests session with BurpSuite proxy
session = requests.Session()
session.proxies = {
    "http": BURP_PROXY_URL,
    "https": BURP_PROXY_URL
}
session.verify = False

app = FastAPI(title="BurpSuite MCP Server")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models for request/response
class ProxyRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[Any] = None
    intercept: bool = True

class ScanRequest(BaseModel):
    target_url: str
    scan_type: str = "active"  # active or passive
    scan_configurations: Optional[Dict[str, Any]] = None

class ProxyResponse(BaseModel):
    status_code: int
    headers: Dict[str, str]
    body: Any
    timestamp: str
    intercepted: bool

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    issues_found: List[Dict[str, Any]]
    scan_time: str

class LogEntry(BaseModel):
    id: str
    timestamp: str
    method: str
    url: str
    status_code: int
    request_headers: Dict[str, str]
    response_headers: Dict[str, str]
    request_body: Optional[Any]
    response_body: Any
    content_type: str
    content_length: int
    processing_time: float
    vulnerabilities: List[Dict[str, Any]]

class LogFilter(BaseModel):
    method: Optional[str] = None
    status_code: Optional[int] = None
    url_pattern: Optional[str] = None
    content_type: Optional[str] = None
    min_content_length: Optional[int] = None
    max_content_length: Optional[int] = None
    time_range: Optional[Dict[str, str]] = None
    vulnerabilities: Optional[List[str]] = None

class LogAnalysis(BaseModel):
    total_requests: int
    unique_urls: int
    unique_methods: Set[str]
    status_code_distribution: Dict[int, int]
    content_type_distribution: Dict[str, int]
    average_response_time: float
    vulnerability_summary: Dict[str, int]
    top_endpoints: List[Dict[str, Any]]
    suspicious_patterns: List[Dict[str, Any]]

# Global variables for storing proxy history, active scans, and logs
proxy_history = []
active_scans = {}
http_logs = []
vulnerability_patterns = {
    "xss": r"(?i)(<script>|javascript:|on\w+\s*=|eval\s*\()",
    "sqli": r"(?i)(union\s+select|or\s+1\s*=\s*1|--|;--|'|'--|' or '1'='1)",
    "path_traversal": r"(?i)(\.\.\/|\.\.\\|\.\.%2f|\.\.%5c)",
    "file_inclusion": r"(?i)(\.\.\/|\.\.\\|\.\.%2f|\.\.%5c|\.\.%252f|\.\.%255c)",
    "ssrf": r"(?i)(localhost|127\.0\.0\.1|internal|private|169\.254)",
    "xxe": r"(?i)(<!ENTITY|<!DOCTYPE|SYSTEM|PUBLIC)",
    "csrf": r"(?i)(csrf|xsrf|_token)",
    "open_redirect": r"(?i)(redirect|url=|next=|return=|returnTo=|redir=)",
    "xxs": r"(?i)(xss|cross-site|scripting)",
    "injection": r"(?i)(exec|system|cmd|eval|passthru|shell_exec)"
}

# Add this after the vulnerability_patterns dictionary
vulnerability_severity = {
    "xss": "high",
    "sqli": "high",
    "file_inclusion": "high",
    "ssrf": "high",
    "xxe": "high",
    "command_injection": "high",
    "path_traversal": "medium",
    "csrf": "medium",
    "open_redirect": "medium",
    "xxs": "low"
}

def analyze_vulnerabilities(request_body: str, response_body: str) -> List[Dict[str, Any]]:
    vulnerabilities = []
    
    # Combine request and response for analysis
    combined_text = f"{request_body} {response_body}"
    
    for vuln_type, pattern in vulnerability_patterns.items():
        matches = re.finditer(pattern, combined_text)
        for match in matches:
            vulnerabilities.append({
                "type": vuln_type,
                "pattern": pattern,
                "match": match.group(0),
                "position": match.start()
            })
    
    return vulnerabilities

def analyze_logs(logs: List[LogEntry]) -> LogAnalysis:
    if not logs:
        return LogAnalysis(
            total_requests=0,
            unique_urls=0,
            unique_methods=set(),
            status_code_distribution={},
            content_type_distribution={},
            average_response_time=0,
            vulnerability_summary={},
            top_endpoints=[],
            suspicious_patterns=[]
        )
    
    # Basic statistics
    unique_urls = len(set(log.url for log in logs))
    unique_methods = set(log.method for log in logs)
    status_codes = defaultdict(int)
    content_types = defaultdict(int)
    total_time = sum(log.processing_time for log in logs)
    vulnerability_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    
    for log in logs:
        status_codes[log.status_code] += 1
        content_types[log.content_type] += 1
        endpoint_counts[log.url] += 1
        
        for vuln in log.vulnerabilities:
            vulnerability_counts[vuln["type"]] += 1
    
    # Get top endpoints
    top_endpoints = [
        {"url": url, "count": count}
        for url, count in sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]
    
    # Find suspicious patterns
    suspicious_patterns = []
    for log in logs:
        if log.status_code >= 400:
            suspicious_patterns.append({
                "url": log.url,
                "status_code": log.status_code,
                "timestamp": log.timestamp
            })
    
    return LogAnalysis(
        total_requests=len(logs),
        unique_urls=unique_urls,
        unique_methods=unique_methods,
        status_code_distribution=dict(status_codes),
        content_type_distribution=dict(content_types),
        average_response_time=total_time / len(logs),
        vulnerability_summary=dict(vulnerability_counts),
        top_endpoints=top_endpoints,
        suspicious_patterns=suspicious_patterns
    )

@app.get("/")
async def root():
    return {"message": "BurpSuite MCP Server is running"}

# Proxy endpoints
@app.post("/proxy/intercept", response_model=ProxyResponse)
async def intercept_request(request: ProxyRequest):
    try:
        logger.info(f"Received proxy request for URL: {request.url}")
        
        # Prepare headers
        headers = request.headers or {}
        if "Host" not in headers:
            parsed_url = urlparse(request.url)
            headers["Host"] = parsed_url.netloc
        
        # Make request through BurpSuite proxy
        start_time = datetime.now()
        response = session.request(
            method=request.method,
            url=request.url,
            headers=headers,
            json=request.body if request.body else None,
            allow_redirects=True
        )
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Create log entry
        log_entry = LogEntry(
            id=f"log_{len(http_logs) + 1}",
            timestamp=start_time.isoformat(),
            method=request.method,
            url=request.url,
            status_code=response.status_code,
            request_headers=headers,
            response_headers=dict(response.headers),
            request_body=request.body,
            response_body=response.text,
            content_type=response.headers.get("Content-Type", "unknown"),
            content_length=len(response.text),
            processing_time=processing_time,
            vulnerabilities=analyze_vulnerabilities(
                str(request.body) if request.body else "",
                response.text
            )
        )
        
        http_logs.append(log_entry)
        
        proxy_response = ProxyResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=response.text,
            timestamp=datetime.now().isoformat(),
            intercepted=request.intercept
        )
        
        if request.intercept:
            proxy_history.append(proxy_response.dict())
        
        logger.info(f"Successfully processed proxy request for URL: {request.url}")
        return proxy_response
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Error in intercept_request: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/proxy/history")
async def get_proxy_history():
    return proxy_history

# Logger endpoints
@app.get("/logger/logs", response_model=List[LogEntry])
async def get_logs(
    filter: Optional[LogFilter] = None,
    search: Optional[str] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0
):
    filtered_logs = http_logs
    
    if filter:
        if filter.method:
            filtered_logs = [log for log in filtered_logs if log.method == filter.method]
        if filter.status_code:
            filtered_logs = [log for log in filtered_logs if log.status_code == filter.status_code]
        if filter.url_pattern:
            filtered_logs = [log for log in filtered_logs if re.search(filter.url_pattern, log.url)]
        if filter.content_type:
            filtered_logs = [log for log in filtered_logs if filter.content_type in log.content_type]
        if filter.min_content_length:
            filtered_logs = [log for log in filtered_logs if log.content_length >= filter.min_content_length]
        if filter.max_content_length:
            filtered_logs = [log for log in filtered_logs if log.content_length <= filter.max_content_length]
        if filter.time_range:
            start_time = datetime.fromisoformat(filter.time_range["start"])
            end_time = datetime.fromisoformat(filter.time_range["end"])
            filtered_logs = [
                log for log in filtered_logs
                if start_time <= datetime.fromisoformat(log.timestamp) <= end_time
            ]
        if filter.vulnerabilities:
            filtered_logs = [
                log for log in filtered_logs
                if any(vuln["type"] in filter.vulnerabilities for vuln in log.vulnerabilities)
            ]
    
    if search:
        search_pattern = re.compile(search, re.IGNORECASE)
        filtered_logs = [
            log for log in filtered_logs
            if search_pattern.search(log.url) or
               search_pattern.search(str(log.request_body)) or
               search_pattern.search(str(log.response_body))
        ]
    
    return filtered_logs[offset:offset + limit]

@app.get("/logger/analysis", response_model=LogAnalysis)
async def analyze_logs_endpoint():
    return analyze_logs(http_logs)

@app.get("/logger/vulnerabilities")
async def get_vulnerabilities():
    vulnerability_summary = defaultdict(int)
    for log in http_logs:
        for vuln in log.vulnerabilities:
            vulnerability_summary[vuln["type"]] += 1
    
    return {
        "total_vulnerabilities": sum(vulnerability_summary.values()),
        "vulnerability_types": dict(vulnerability_summary),
        "vulnerable_endpoints": [
            {
                "url": log.url,
                "method": log.method,
                "timestamp": log.timestamp,
                "vulnerabilities": log.vulnerabilities
            }
            for log in http_logs
            if log.vulnerabilities
        ]
    }

@app.get("/logger/vulnerabilities/severity")
async def get_vulnerabilities_by_severity():
    # Initialize vulnerability counters by severity
    severity_counts = {
        "high": defaultdict(int),
        "medium": defaultdict(int),
        "low": defaultdict(int)
    }
    
    # Track vulnerable endpoints by severity
    vulnerable_endpoints = {
        "high": [],
        "medium": [],
        "low": []
    }
    
    # Analyze logs for vulnerabilities
    for log in http_logs:
        for vuln in log.vulnerabilities:
            vuln_type = vuln["type"]
            severity = vulnerability_severity.get(vuln_type, "low")
            
            # Count vulnerabilities by severity
            severity_counts[severity][vuln_type] += 1
            
            # Track vulnerable endpoints
            endpoint_info = {
                "url": log.url,
                "method": log.method,
                "timestamp": log.timestamp,
                "vulnerability": vuln
            }
            vulnerable_endpoints[severity].append(endpoint_info)
    
    return {
        "summary": {
            "high": dict(severity_counts["high"]),
            "medium": dict(severity_counts["medium"]),
            "low": dict(severity_counts["low"])
        },
        "vulnerable_endpoints": vulnerable_endpoints,
        "total_counts": {
            "high": sum(severity_counts["high"].values()),
            "medium": sum(severity_counts["medium"].values()),
            "low": sum(severity_counts["low"].values())
        }
    }

@app.delete("/logger/clear")
async def clear_logs():
    http_logs.clear()
    return {"message": "Logs cleared successfully"}

# Scanner endpoints
@app.post("/scanner/start", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    try:
        logger.info(f"Starting scan for URL: {request.target_url}")
        
        # Create scan configuration
        scan_config = {
            "target_url": request.target_url,
            "scan_type": request.scan_type,
            "configurations": request.scan_configurations or {}
        }
        
        # Start scan by making initial request through proxy
        response = session.get(request.target_url)
        
        scan_id = f"scan_{len(active_scans) + 1}"
        scan_status = {
            "scan_id": scan_id,
            "status": "running",
            "issues_found": [],
            "scan_time": datetime.now().isoformat()
        }
        
        active_scans[scan_id] = scan_status
        logger.info(f"Successfully started scan with ID: {scan_id}")
        return ScanResponse(**scan_status)
    except Exception as e:
        logger.error(f"Error in start_scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scanner/status/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str):
    try:
        if scan_id not in active_scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get scan status from proxy history
        scan_status = active_scans[scan_id]
        scan_url = next((req["url"] for req in proxy_history if req["url"].startswith(scan_status.get("target_url", ""))), None)
        
        if scan_url:
            response = session.get(scan_url)
            scan_status["issues_found"].append({
                "url": scan_url,
                "status_code": response.status_code,
                "headers": dict(response.headers)
            })
        
        return scan_status
    except Exception as e:
        logger.error(f"Error in get_scan_status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/scanner/stop/{scan_id}")
async def stop_scan(scan_id: str):
    try:
        if scan_id not in active_scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        active_scans[scan_id]["status"] = "stopped"
        return {"message": f"Scan {scan_id} stopped"}
    except Exception as e:
        logger.error(f"Error in stop_scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("MCP_SERVER_PORT", 8000)), reload=True) 
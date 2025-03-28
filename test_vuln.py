import requests
import json

def test_vulnerabilities():
    url = "http://localhost:8000/proxy/intercept"
    headers = {
        "Content-Type": "application/json"
    }
    
    # Test cases with different vulnerabilities
    test_cases = [
        {
            "url": "https://target.com/v2/login",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "username": "' OR '1'='1",  # SQL Injection
                "password": "<script>alert('xss')</script>"  # XSS
            },
            "intercept": True
        },
        {
            "url": "https://target.com/v2/login",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "username": "admin",
                "password": "password",
                "redirect": "http://evil.com"  # Open Redirect
            },
            "intercept": True
        },
        {
            "url": "https://target.com/v2/login",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": {
                "username": "admin",
                "password": "password",
                "file": "../../../etc/passwd"  # Path Traversal
            },
            "intercept": True
        }
    ]
    
    for test_case in test_cases:
        try:
            response = requests.post(url, headers=headers, json=test_case)
            print(f"\nTest case response: {response.status_code}")
            print(f"Response: {response.text}")
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    test_vulnerabilities() 
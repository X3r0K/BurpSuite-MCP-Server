import requests
import json
import time

def start_scan():
    url = "http://localhost:8000/scanner/start"
    payload = {
        "target_url": "https://sso.8x8.com",
        "scan_type": "active",
        "scan_configurations": {
            "scope": "strict",
            "audit_checks": ["xss", "sqli", "ssrf", "file_inclusion"]
        }
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        scan_data = response.json()
        print("Scan started:", scan_data)
        return scan_data.get("scan_id")
    except Exception as e:
        print("Error starting scan:", e)
        return None

def check_scan_status(scan_id):
    url = f"http://localhost:8000/scanner/status/{scan_id}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print("Error checking scan status:", e)
        return None

def main():
    scan_id = start_scan()
    if not scan_id:
        return
    
    print(f"\nMonitoring scan {scan_id}...")
    while True:
        status = check_scan_status(scan_id)
        if not status:
            break
            
        print("\nCurrent scan status:", json.dumps(status, indent=2))
        
        if status["status"] in ["completed", "failed", "stopped"]:
            break
            
        time.sleep(5)

if __name__ == "__main__":
    main() 
import requests
import json

def make_request():
    url = "http://localhost:8000/proxy/intercept"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "url": "https://target.com/v2/login",
        "method": "GET",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        },
        "intercept": True
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        print("Status Code:", response.status_code)
        print("Response:", json.dumps(response.json(), indent=2))
    except Exception as e:
        print("Error:", str(e))

if __name__ == "__main__":
    make_request() 
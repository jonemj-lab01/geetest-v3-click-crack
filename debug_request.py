import httpx
import time

url = f"https://www.geetest.com/demo/gt/register-click-official?t={str(round(time.time()))}"
print(f"Requesting: {url}")

try:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    response = httpx.get(url, headers=headers, follow_redirects=True)
    print(f"Status Code: {response.status_code}")
    print(f"Content: {response.text}")
    print(f"JSON: {response.json()}")
except Exception as e:
    print(f"Error: {e}")

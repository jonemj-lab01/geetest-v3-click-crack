from curl_cffi import requests

# 使用 Chrome 指纹
response = requests.get(
    "https://httpbin.org/headers",
    impersonate="chrome124",
    timeout=10
)

print(response.json()["headers"]["User-Agent"])
from curl_cffi import requests

# 使用 Chrome 指纹,见 https://github.com/lexiforest/curl_cffi
response = requests.get(
    "https://tls.browserleaks.com/json",
    impersonate="chrome123",
    timeout=10
)

print(response.json())
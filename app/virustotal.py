import requests

VT_API_KEY = "e2a1e21dd316ff3f601ea9ea032c9e3a8d9a973a116c3f8c28e965e496cf3ca7"


def check_hash_virustotal(file_hash):

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return None

    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless
    }
def upload_file_virustotal(file_path):

    url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "x-apikey": VT_API_KEY
    }

    files = {
        "file": open(file_path, "rb")
    }

    response = requests.post(url, headers=headers, files=files)

    if response.status_code != 200:
        return None

    data = response.json()

    return data
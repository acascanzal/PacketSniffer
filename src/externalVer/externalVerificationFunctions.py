import requests

def makeGetRequest(url, headers):
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": str(e)}

def makePostRequest(url, headers, payload, params=None):
    try:
        response = requests.post(url, headers=headers, json=payload, params=params)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": str(e)}

def checkExternalDomain(domain, apiName, apiKey):
    headers = {
        'Content-Type': 'application/json'
    }

    if apiName == 'VirusTotal':
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers['x-apikey'] = apiKey
        return makeGetRequest(url, headers)

    elif apiName == 'GoogleSafeBrowsing':
        url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {
                "clientId": "yourcompany",
                "clientVersion": "1.5.2"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": f"http://{domain}"}
                ]
            }
        }
        return makePostRequest(url, headers, payload, params={'key': apiKey})

    elif apiName == 'PhishTank':
        url = "https://checkurl.phishtank.com/checkurl/"
        payload = {
            "url": f"http://{domain}",
            "format": "json",
            "app_key": apiKey
        }
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return makePostRequest(url, headers, payload)

    elif apiName == 'IBM_XForce':
        url = f"https://api.xforce.ibmcloud.com/url/{domain}"
        headers['Authorization'] = f"Bearer {apiKey}"
        return makeGetRequest(url, headers)

    elif apiName == 'URLScan':
        url = "https://urlscan.io/api/v1/scan/"
        payload = {"url": f"http://{domain}"}
        headers['API-Key'] = apiKey
        return makePostRequest(url, headers, payload)
    else:
        return {"error": "API name not recognized"}



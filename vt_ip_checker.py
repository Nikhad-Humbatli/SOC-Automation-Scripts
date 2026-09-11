import requests

def check_ip_reputation(ip_address, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        print(f"IP: {ip_address} | Malicious: {stats['malicious']} | Suspicious: {stats['suspicious']}")
    else:
        print(f"Error fetching data: {response.status_code}")

if __name__ == "__main__":
    API_KEY = "YOUR_API_KEY_HERE"
    check_ip_reputation("8.8.8.8", API_KEY)

#!/usr/bin/env python3
"""IntelBroker: automated reconnaissance and threat-intel enrichment tool.

Queries a local mock Threat Intelligence API (localhost:5000)
and returns the results as Python dictionaries.
"""
import requests

API_BASE_URL = "http://localhost:5000"
REQUEST_TIMEOUT = 5


def query_virustotal(ip: str) -> dict:
    """Ask the mock VirusTotal API for the reputation of an IP.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - JSON payload from the API, or an empty dict on error.
    """
    url = f"{API_BASE_URL}/virustotal/{ip}"
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            print(f"[ERROR] VirusTotal returned status "
                  f"{response.status_code}.")
            return {}
        return response.json()
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to the API. Is mock_api.py running?")
    except requests.exceptions.Timeout:
        print("[ERROR] VirusTotal request timed out.")
    except ValueError:
        print("[ERROR] Invalid JSON received from VirusTotal.")
    except requests.exceptions.RequestException as error:
        print(f"[ERROR] Request failed: {error}")
    return {}


if __name__ == "__main__":
    print(query_virustotal("1.2.3.4"))

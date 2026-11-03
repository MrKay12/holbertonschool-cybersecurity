#!/usr/bin/env python3
"""IntelBroker: automated reconnaissance and threat-intel enrichment tool.

Queries a local mock Threat Intelligence API (localhost:5000)
and returns the results as Python dictionaries.
"""
import requests

API_BASE_URL = "http://localhost:5000"
REQUEST_TIMEOUT = 5


def query_api(service: str, ip: str) -> dict:
    """Send a GET request to a mock Threat Intel service.

    Input: service (str) - API name (e.g. "virustotal", "abuseipdb").
           ip (str) - IP address or domain to look up.
    Output: dict - JSON payload from the API, or an empty dict on error.
    """
    url = f"{API_BASE_URL}/{service}/{ip}"
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            print(f"[ERROR] {service} returned status "
                  f"{response.status_code}.")
            return {}
        return response.json()
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to the API. Is mock_api.py running?")
    except requests.exceptions.Timeout:
        print(f"[ERROR] {service} request timed out.")
    except ValueError:
        print(f"[ERROR] Invalid JSON received from {service}.")
    except requests.exceptions.RequestException as error:
        print(f"[ERROR] Request failed: {error}")
    return {}


def query_virustotal(ip: str) -> dict:
    """Ask the mock VirusTotal API for the reputation of an IP.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - {'ip', 'reputation_score', 'malicious'}, or {} on error.
    """
    return query_api("virustotal", ip)


def query_abuseipdb(ip: str) -> dict:
    """Ask the mock AbuseIPDB API for the abuse score of an IP.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - {'ip', 'abuse_confidence_score', 'reports'},
            or {} on error.
    """
    return query_api("abuseipdb", ip)


if __name__ == "__main__":
    print(query_virustotal("1.2.3.4"))
    print(query_abuseipdb("1.2.3.4"))

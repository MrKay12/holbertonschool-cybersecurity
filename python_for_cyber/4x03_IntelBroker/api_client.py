#!/usr/bin/env python3
"""Async HTTP client for the mock Threat Intelligence APIs.

Talks to VirusTotal, Shodan and AbuseIPDB (mock server on localhost:5000)
with aiohttp, with a requests fallback, a 1-hour cache and a limit of
5 concurrent requests.
"""
import asyncio

from utils import (get_cached, is_valid_result, load_cache, log_status,
                   save_cache, set_cached, unavailable)

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import requests
except ImportError:
    requests = None

API_BASE_URL = "http://localhost:5000"
REQUEST_TIMEOUT = 5
SERVICE_NAMES = {"virustotal": "VirusTotal",
                 "shodan": "Shodan",
                 "abuseipdb": "AbuseIPDB"}


async def fetch_api(session, url: str) -> dict:
    """Send an asynchronous GET request and return the JSON payload.

    Any failure (HTTP 4xx/5xx, connection refused, timeout, invalid JSON)
    is caught so the rest of the script keeps running.

    Input: session (aiohttp.ClientSession) - open HTTP session.
           url (str) - full URL of the API endpoint.
    Output: dict - JSON payload from the API,
            or {"error": "Unavailable"} if the API failed.
    """
    try:
        if aiohttp is not None:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        else:
            timeout = REQUEST_TIMEOUT
        async with session.get(url, timeout=timeout) as response:
            if response.status != 200:
                return unavailable()
            data = await response.json()
    except Exception:
        # ClientError, TimeoutError, invalid JSON...: never stop the script
        return unavailable()
    return data if isinstance(data, dict) else unavailable()


async def fetch_api_limited(semaphore, session, url: str) -> dict:
    """Call fetch_api only when the semaphore grants a free slot.

    Input: semaphore (asyncio.Semaphore) - limits concurrent requests.
           session (aiohttp.ClientSession) - open HTTP session.
           url (str) - full URL of the API endpoint.
    Output: dict - JSON payload from the API,
            or {"error": "Unavailable"} if the API failed.
    """
    async with semaphore:
        return await fetch_api(session, url)


async def fetch_service(service: str, ip: str) -> dict:
    """Open a session and query one mock Threat Intel service.

    Input: service (str) - API name (e.g. "virustotal", "abuseipdb").
           ip (str) - IP address or domain to look up.
    Output: dict - JSON payload from the API,
            or {"error": "Unavailable"} if the API failed.
    """
    async with aiohttp.ClientSession() as session:
        return await fetch_api(session, f"{API_BASE_URL}/{service}/{ip}")


def fetch_api_sync(url: str) -> dict:
    """Fallback: send a blocking GET request with requests.

    Input: url (str) - full URL of the API endpoint.
    Output: dict - JSON payload from the API,
            or {"error": "Unavailable"} if the API failed.
    """
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return unavailable()
        data = response.json()
    except (requests.exceptions.RequestException, ValueError):
        return unavailable()
    return data if isinstance(data, dict) else unavailable()


def query_api(service: str, ip: str) -> dict:
    """Synchronous helper to query one mock Threat Intel service.

    Returns cached data if it is less than 1 hour old. Otherwise uses
    aiohttp (via asyncio.run) when available, or falls back to requests,
    and saves the fresh result to the cache.

    Input: service (str) - API name (e.g. "virustotal", "abuseipdb").
           ip (str) - IP address or domain to look up.
    Output: dict - JSON payload from the API,
            or {"error": "Unavailable"} if the API failed.
    """
    cache = load_cache()
    cached_data = get_cached(cache, service, ip)
    if cached_data is not None:
        return cached_data
    if aiohttp is not None:
        data = asyncio.run(fetch_service(service, ip))
    elif requests is not None:
        data = fetch_api_sync(f"{API_BASE_URL}/{service}/{ip}")
    else:
        return unavailable()
    if is_valid_result(data):
        set_cached(cache, service, ip, data)
        save_cache(cache)
    return data


def query_virustotal(ip: str) -> dict:
    """Ask the mock VirusTotal API for the reputation of an IP.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - {'ip', 'reputation_score', 'malicious'},
            or {"error": "Unavailable"} if the API failed.
    """
    return query_api("virustotal", ip)


def query_abuseipdb(ip: str) -> dict:
    """Ask the mock AbuseIPDB API for the abuse score of an IP.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - {'ip', 'abuse_confidence_score', 'reports'},
            or {"error": "Unavailable"} if the API failed.
    """
    return query_api("abuseipdb", ip)


def query_shodan(ip: str) -> dict:
    """Ask the mock Shodan API for historical data about an IP.

    Input: ip (str) - IP address or domain to look up.
    Output: dict - {'ip', 'ports', 'os', 'isp'},
            or {"error": "Unavailable"} if the API failed.
    """
    return query_api("shodan", ip)


async def gather_intel(ip: str, verbose: bool = False) -> dict:
    """Query VirusTotal, Shodan and AbuseIPDB in parallel (with cache).

    Results less than 1 hour old are read from the cache; only the
    missing or expired ones are fetched, then saved to the cache.
    An asyncio.Semaphore limits the API calls to 5 at the same time.

    Input: ip (str) - IP address or domain to look up.
           verbose (bool) - print status messages (default: False).
    Output: dict - {'virustotal': dict, 'shodan': dict, 'abuseipdb': dict};
            a source that failed is {"error": "Unavailable"}.
    """
    services = ["virustotal", "shodan", "abuseipdb"]
    cache = load_cache()
    intel = {}
    to_fetch = []
    for service in services:
        cached_data = get_cached(cache, service, ip)
        if cached_data is not None:
            log_status(f"[+] {SERVICE_NAMES[service]} loaded from cache.",
                       verbose)
            intel[service] = cached_data
        else:
            log_status(f"[+] Querying {SERVICE_NAMES[service]}...", verbose)
            to_fetch.append(service)
    if not to_fetch:
        return intel
    if aiohttp is None:
        for service in to_fetch:
            intel[service] = unavailable()
        return {service: intel[service] for service in services}
    semaphore = asyncio.Semaphore(5)
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_api_limited(semaphore, session,
                                   f"{API_BASE_URL}/{service}/{ip}")
                 for service in to_fetch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for service, result in zip(to_fetch, results):
        if isinstance(result, BaseException):
            result = unavailable()
        intel[service] = result
        if is_valid_result(result):
            set_cached(cache, service, ip, result)
    save_cache(cache)
    return {service: intel[service] for service in services}

#!/usr/bin/env python3
"""Shared helpers for IntelBroker: status messages, error payload, cache.

The cache (cache.json) stores API results for 1 hour, per IP and per API.
"""
import json
import time

CACHE_FILE = "cache.json"
CACHE_TTL = 3600
UNAVAILABLE_MESSAGE = "Unavailable"


def log_status(message: str, verbose: bool) -> None:
    """Print a status message only in verbose mode.

    Input: message (str) - text to print.
           verbose (bool) - True to print, False to stay silent.
    Output: None.
    """
    if verbose:
        print(message, flush=True)


def unavailable() -> dict:
    """Build the payload returned when an API source fails.

    Input: None.
    Output: dict - {"error": "Unavailable"} (a new dict on every call).
    """
    return {"error": UNAVAILABLE_MESSAGE}


def is_valid_result(data) -> bool:
    """Tell if an API result is real data (not empty, not an error).

    Input: data - value returned by an API helper.
    Output: bool - True if data is a non-empty dict without "error".
    """
    return isinstance(data, dict) and bool(data) and "error" not in data


def load_cache(cache_path: str = None) -> dict:
    """Load the JSON cache from disk.

    Input: cache_path (str) - cache file (default: CACHE_FILE).
    Output: dict - cache content, or an empty dict if the file is
            missing, unreadable or corrupted.
    """
    try:
        with open(cache_path or CACHE_FILE, "r", encoding="utf-8") as file:
            cache = json.load(file)
    except (OSError, ValueError):
        return {}
    return cache if isinstance(cache, dict) else {}


def save_cache(cache: dict, cache_path: str = None) -> bool:
    """Write the cache to disk (best effort, never raises).

    Input: cache (dict) - cache content to save.
           cache_path (str) - cache file (default: CACHE_FILE).
    Output: bool - True if the file was written, False otherwise.
    """
    try:
        with open(cache_path or CACHE_FILE, "w", encoding="utf-8") as file:
            json.dump(cache, file, indent=2)
            file.write("\n")
    except (OSError, TypeError, ValueError):
        return False
    return True


def get_cached(cache: dict, service: str, ip: str) -> dict:
    """Return cached data for a service/IP if it is less than 1 hour old.

    Input: cache (dict) - loaded cache.
           service (str) - API name (e.g. "virustotal").
           ip (str) - IP address or domain.
    Output: dict - cached payload, or None if missing or expired.
    """
    entry = cache.get(ip, {}).get(service)
    if not isinstance(entry, dict):
        return None
    try:
        age = time.time() - float(entry.get("timestamp", 0))
    except (TypeError, ValueError):
        return None
    if 0 <= age < CACHE_TTL and isinstance(entry.get("data"), dict):
        return entry["data"]
    return None


def set_cached(cache: dict, service: str, ip: str, data: dict) -> None:
    """Store a fresh API result in the cache (in memory).

    Input: cache (dict) - loaded cache, modified in place.
           service (str) - API name.
           ip (str) - IP address or domain.
           data (dict) - payload to store.
    Output: None.
    """
    cache.setdefault(ip, {})[service] = {"timestamp": time.time(),
                                         "data": data}

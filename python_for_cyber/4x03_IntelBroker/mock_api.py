#!/usr/bin/env python3
"""Mock API server simulating VirusTotal, Shodan and AbuseIPDB.

Listens on localhost:5000 and answers GET requests on:
    /virustotal/<ip>  -> {"ip", "reputation_score", "malicious"}
    /shodan/<ip>      -> {"ip", "ports", "os", "isp"}
    /abuseipdb/<ip>   -> {"ip", "abuse_confidence_score", "reports"}
Any other path returns {"error": "Unknown API"}.
"""
import json
import random
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockHandler(BaseHTTPRequestHandler):
    """HTTP handler returning random JSON threat-intel data."""

    def do_GET(self) -> None:
        """Answer a GET request with a JSON body built from the path.

        Input: request path (e.g. /virustotal/8.8.8.8).
        Output: HTTP 200 with a JSON payload written to the client.
        """
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        ip_address = self.path.split('/')[-1]

        if "virustotal" in self.path:
            score = random.randint(0, 10)
            data = {"ip": ip_address,
                    "reputation_score": score,
                    "malicious": score > 5}
        elif "shodan" in self.path:
            ports = [80, 443, 22, 8080]
            data = {"ip": ip_address,
                    "ports": random.sample(ports, k=random.randint(1, 3)),
                    "os": "Linux",
                    "isp": "CloudNet"}
        elif "abuseipdb" in self.path:
            data = {"ip": ip_address,
                    "abuse_confidence_score": random.randint(0, 100),
                    "reports": random.randint(0, 50)}
        else:
            data = {"error": "Unknown API"}

        self.wfile.write(json.dumps(data).encode())


if __name__ == "__main__":
    try:
        server = HTTPServer(('localhost', 5000), MockHandler)
        print("Mock API Server running on port 5000...")
        server.serve_forever()
    except OSError as error:
        print(f"[ERROR] Cannot start server: {error}")
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped.")

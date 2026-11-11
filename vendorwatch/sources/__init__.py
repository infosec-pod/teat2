"""Threat-intelligence sources.

Every source is free and works without an account. Optional keys raise rate limits:

* ``NVD_API_KEY``  - https://nvd.nist.gov/developers/request-an-api-key
* ``GITHUB_TOKEN`` - enables public-PoC hunting on GitHub
"""
import logging
import time

import requests

from .. import __version__

log = logging.getLogger("vendorwatch")

USER_AGENT = f"vendorwatch/{__version__} (+third-party risk monitor)"


class Http:
    def __init__(self, timeout: int = 30):
        self.s = requests.Session()
        self.s.headers["User-Agent"] = USER_AGENT
        self.timeout = timeout

    def get(self, url, *, params=None, headers=None, retries=3, backoff=6.0) -> requests.Response:
        last = None
        for attempt in range(retries):
            try:
                r = self.s.get(url, params=params, headers=headers, timeout=self.timeout)
                if r.status_code in (403, 429, 500, 502, 503, 504) and attempt < retries - 1:
                    log.debug("HTTP %s from %s, retrying", r.status_code, url)
                    time.sleep(backoff * (attempt + 1))
                    continue
                r.raise_for_status()
                return r
            except requests.RequestException as e:
                last = e
                if attempt < retries - 1:
                    time.sleep(backoff * (attempt + 1))
        raise last if last else RuntimeError(f"GET {url} failed")

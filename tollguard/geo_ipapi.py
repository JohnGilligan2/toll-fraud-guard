"""GeoLookup over the ip-api.com batch endpoint (stdlib only).

The free tier takes 100 addresses per request and about 45 requests a minute,
and is plain http; the paid tier is https and needs a key. A failed batch is
logged and its addresses come back missing, which `registrations.scan` reports
as unknown rather than clean.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
from typing import Any, Callable

from .registrations import Geo

logger = logging.getLogger("tollguard.geo")

FIELDS = "status,countryCode,isp,org,as,proxy,hosting,mobile,query"
BATCH = 100


def _post(url: str, payload: list[dict[str, str]], timeout: float) -> list[dict[str, Any]]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed URL from config
        return json.loads(r.read().decode())


class IpApiLookup:
    def __init__(self, url: str = "http://ip-api.com/batch", timeout: float = 30.0,
                 pause_s: float = 1.5, budget_s: float = 120.0,
                 post: Callable[[str, list[dict[str, str]], float], list[dict[str, Any]]] = _post):
        self.url, self.timeout, self.pause_s, self.budget_s = url, timeout, pause_s, budget_s
        self._post = post

    def lookup(self, ips: list[str]) -> dict[str, Geo]:
        out: dict[str, Geo] = {}
        deadline = time.monotonic() + self.budget_s
        for i in range(0, len(ips), BATCH):
            if time.monotonic() > deadline:
                logger.error("geo lookup ran out of time; %d address(es) not looked up",
                             len(ips) - i)
                break
            if i:
                time.sleep(self.pause_s)
            batch = ips[i:i + BATCH]
            try:
                rows = self._post(self.url, [{"query": ip, "fields": FIELDS} for ip in batch],
                                  self.timeout)
            except (OSError, ValueError) as e:
                # Network failure or a non-JSON reply: this batch is unknown, said loudly.
                logger.error("geo batch at %d failed (%s); %d address(es) unknown", i, e, len(batch))
                continue
            for row in rows:
                if row.get("status") != "success":
                    continue
                out[row["query"]] = Geo(country=row.get("countryCode", ""), isp=row.get("isp", ""),
                                        org=row.get("org", ""), asn=row.get("as", ""),
                                        hosting=bool(row.get("hosting")),
                                        proxy=bool(row.get("proxy")),
                                        mobile=bool(row.get("mobile")))
        return out

"""Structured vulnerability sources: CISA KEV, NVD, CVE.org, FIRST EPSS, GitHub PoCs."""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone

from . import Http, log

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVEORG_URL = "https://cveawg.mitre.org/api/cve/{}"
EPSS_URL = "https://api.first.org/data/v1/epss"
GITHUB_SEARCH = "https://api.github.com/search/repositories"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# --------------------------------------------------------------------- CISA KEV
def fetch_kev(http: Http) -> dict[str, dict]:
    """CISA Known Exploited Vulnerabilities catalog, keyed by CVE id."""
    data = http.get(KEV_URL).json()
    return {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}


def kev_for_asset(kev: dict[str, dict], asset) -> list[dict]:
    if not asset.vendor:
        return []
    v = _norm(asset.vendor)
    names = {_norm(asset.product)} | {_norm(k) for k in asset.keywords}
    names.discard("")
    out = []
    for item in kev.values():
        if not _norm(item.get("vendorProject", "")).startswith(v):
            continue
        prod = _norm(item.get("product", ""))
        if not names or any(n and (n in prod or prod in n) for n in names):
            out.append(item)
    return out


# --------------------------------------------------------------------- NVD
class Nvd:
    def __init__(self, http: Http, api_key: str = ""):
        self.http = http
        self.api_key = api_key
        self.delay = 0.8 if api_key else 6.5  # NVD public rate limit: 5 req / 30 s
        self._last = 0.0

    def _get(self, params: dict) -> dict:
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        headers = {"apiKey": self.api_key} if self.api_key else None
        try:
            return self.http.get(NVD_URL, params=params, headers=headers, retries=4, backoff=10).json()
        finally:
            self._last = time.time()

    def _paged(self, params: dict) -> list[dict]:
        out, start = [], 0
        while True:
            p = dict(params, resultsPerPage=2000, startIndex=start)
            d = self._get(p)
            out += [v["cve"] for v in d.get("vulnerabilities", [])]
            start += d.get("resultsPerPage", 0) or 2000
            if start >= d.get("totalResults", 0):
                return out

    def for_cpe(self, cpe_prefix: str, since: datetime | None, until: datetime | None = None) -> list[dict]:
        """CVEs touching a vendor:product, optionally modified in a window (chunks of <=120 days)."""
        if since is None:
            return self._paged({"virtualMatchString": cpe_prefix})
        until = until or datetime.now(timezone.utc)
        out, start = [], since
        while start < until:
            end = min(start + timedelta(days=119), until)
            out += self._paged(
                {
                    "virtualMatchString": cpe_prefix,
                    "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                }
            )
            start = end
        return out

    def by_id(self, cve_id: str) -> dict | None:
        d = self._get({"cveId": cve_id})
        v = d.get("vulnerabilities") or []
        return v[0]["cve"] if v else None


def nvd_summary(cve: dict) -> dict:
    """Flatten the interesting bits of an NVD CVE object."""
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss, vector, sev = None, "", ""
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        ms = metrics.get(key) or []
        if ms:
            primary = next((m for m in ms if m.get("type") == "Primary"), ms[0])
            data = primary.get("cvssData", {})
            cvss = data.get("baseScore")
            vector = data.get("vectorString", "")
            sev = data.get("baseSeverity") or primary.get("baseSeverity", "")
            break
    refs = cve.get("references", []) or []
    patches = [r["url"] for r in refs if {"Patch", "Vendor Advisory", "Release Notes"} & set(r.get("tags") or [])]
    exploits = [r["url"] for r in refs if "Exploit" in (r.get("tags") or [])]
    return {
        "id": cve["id"],
        "description": desc,
        "cvss": cvss,
        "cvss_vector": vector,
        "severity": (sev or "").upper(),
        "published": cve.get("published", ""),
        "modified": cve.get("lastModified", ""),
        "status": cve.get("vulnStatus", ""),
        "cwe": sorted({d["value"] for w in cve.get("weaknesses", []) or [] for d in w.get("description", []) if d.get("value", "").startswith("CWE-")}),
        "patch_refs": list(dict.fromkeys(patches))[:8],
        "exploit_refs": list(dict.fromkeys(exploits))[:8],
        "refs": [r["url"] for r in refs][:15],
        "cisa_kev_date": cve.get("cisaExploitAdd"),
    }


def cveorg_summary(rec: dict) -> dict:
    """Summary from a CVE.org record (used when NVD hasn't analysed the CVE yet)."""
    meta = rec.get("cveMetadata", {})
    cna = (rec.get("containers") or {}).get("cna") or {}
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "en").startswith("en")), "")
    cvss, vector, sev = None, "", ""
    for m in cna.get("metrics", []) or []:
        for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if k in m:
                cvss = m[k].get("baseScore")
                vector = m[k].get("vectorString", "")
                sev = m[k].get("baseSeverity", "")
                break
        if cvss is not None:
            break
    refs = [r.get("url") for r in cna.get("references", []) or [] if r.get("url")]
    return {
        "id": meta.get("cveId", ""),
        "description": desc,
        "cvss": cvss,
        "cvss_vector": vector,
        "severity": (sev or "").upper(),
        "published": meta.get("datePublished", ""),
        "modified": meta.get("dateUpdated", ""),
        "status": "CNA only (awaiting NVD analysis)",
        "cwe": [],
        "patch_refs": refs[:8],
        "exploit_refs": [],
        "refs": refs[:15],
        "cisa_kev_date": None,
    }


def fetch_cveorg(http: Http, cve_id: str) -> dict | None:
    try:
        return http.get(CVEORG_URL.format(cve_id), retries=2, backoff=2).json()
    except Exception as e:  # noqa: BLE001
        log.debug("CVE.org lookup failed for %s: %s", cve_id, e)
        return None


# --------------------------------------------------------------------- EPSS
def fetch_epss(http: Http, cve_ids: list[str]) -> dict[str, dict]:
    """FIRST EPSS: probability a CVE is exploited in the next 30 days."""
    out: dict[str, dict] = {}
    ids = sorted(set(cve_ids))
    for i in range(0, len(ids), 80):
        chunk = ids[i : i + 80]
        try:
            d = http.get(EPSS_URL, params={"cve": ",".join(chunk)}).json()
        except Exception as e:  # noqa: BLE001
            log.warning("EPSS lookup failed: %s", e)
            continue
        for row in d.get("data", []):
            out[row["cve"].upper()] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
    return out


# --------------------------------------------------------------------- GitHub PoCs
def github_pocs(http: Http, cve_id: str, token: str) -> list[dict]:
    """Public repos named after the CVE - a strong signal that exploit code is circulating."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    try:
        d = http.get(GITHUB_SEARCH, params={"q": f"{cve_id} in:name,description", "sort": "stars", "per_page": 5},
                     headers=headers, retries=2, backoff=5).json()
    except Exception as e:  # noqa: BLE001
        log.debug("GitHub search failed for %s: %s", cve_id, e)
        return []
    return [
        {"url": r["html_url"], "name": r["full_name"], "stars": r.get("stargazers_count", 0), "created": r.get("created_at", "")}
        for r in d.get("items", [])
        if cve_id.lower() in (r.get("name", "") + " " + (r.get("description") or "")).lower()
    ]

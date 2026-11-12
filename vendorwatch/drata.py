"""Sync the watchlist with your vendor inventory in Drata.

Drata is the source of truth for WHICH vendors are monitored and HOW critical
they are; the YAML watchlist still fine-tunes each vendor (better keywords,
domains, SEC ids) and adds technologies Drata doesn't track (e.g. firewalls).

    Drata vendor  --matched to-->  YAML asset with the same name / domain / keyword
         |                               |
         | status, risk, critical flag   | keywords, domains, sec_cik, versions...
         v                               v
                  merged asset that gets monitored

* A Drata vendor with no YAML entry is added automatically (news, ransomware leak
  sites, breach monitoring) using its name and website domain.
* A vendor whose Drata status is not in `drata.statuses` (e.g. OFFBOARDED,
  ARCHIVED) is dropped, even if it's in the YAML.
* YAML assets that don't match any Drata vendor are kept (e.g. FortiGate).

API: GET {base}/vendors (Drata Public API v2), Bearer API key with the
"Vendors: List Vendors" permission. Requires Drata's TPRM feature tier.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import replace
from pathlib import Path

from .config import Asset, Config
from .sources import Http

log = logging.getLogger("vendorwatch")

BASES = {
    "us": "https://public-api.drata.com/public/v2",
    "eu": "https://public-api.eu.drata.com/public/v2",
    "apac": "https://public-api.apac.drata.com/public/v2",
}
DEFAULT_STATUSES = ["ACTIVE", "APPROVED", "UNDER_REVIEW", "FLAGGED", "ON_HOLD"]

_RISK = {"HIGH": "high", "MODERATE": "medium", "LOW": "low", "NONE": "low"}
_IMPACT = {"CRITICAL": "critical", "MAJOR": "high", "MODERATE": "medium", "MINOR": "low", "INSIGNIFICANT": "low"}
_ORDER = ["low", "medium", "high", "critical"]
_SUFFIX = re.compile(r"[,\s]+(inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|plc|gmbh|s\.?a|ag)\.?$", re.I)


class DrataError(RuntimeError):
    pass


# --------------------------------------------------------------------- API
def fetch_vendors(http: Http, api_key: str, region: str = "us", base_url: str = "") -> list[dict]:
    base = (base_url or BASES.get(region.lower(), BASES["us"])).rstrip("/")
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    out, cursor = [], None
    for _ in range(200):  # safety stop: 200 pages x 500 vendors
        params = {"size": 500, "expand[]": "vendorUser"}
        if cursor:
            params["cursor"] = cursor
        r = http.s.get(f"{base}/vendors", params=params, headers=headers, timeout=60)
        if r.status_code == 401:
            raise DrataError("Drata rejected the API key (401). Check DRATA_API_KEY and its region.")
        if r.status_code == 402:
            raise DrataError("Drata says your plan doesn't include the vendor API (402) - it needs a TPRM tier.")
        if r.status_code == 403:
            raise DrataError("The Drata API key lacks the 'Vendors: List Vendors' permission (403).")
        if r.status_code == 412:
            raise DrataError("Drata requires the API terms to be accepted in the Drata app first (412).")
        r.raise_for_status()
        body = r.json()
        out += body.get("data", [])
        cursor = (body.get("pagination") or {}).get("cursor")
        if not cursor:
            return out
    return out


# --------------------------------------------------------------------- mapping
def clean_name(name: str) -> str:
    """'Salesforce, Inc' -> 'Salesforce', 'Zapier.com' -> 'Zapier', 'AG Grid Ltd' -> 'AG Grid'."""
    n = (name or "").strip()
    n = re.sub(r"\.(com|io|ai|net|org|co|app)$", "", n, flags=re.I)
    prev = None
    while prev != n:
        prev, n = n, _SUFFIX.sub("", n).strip()
    return n


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", clean_name(s).lower())


def _words(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", clean_name(s).lower()))


def domain_of(url: str) -> str:
    d = re.sub(r"^[a-z]+://", "", (url or "").strip().lower()).split("/")[0].split(":")[0]
    return d[4:] if d.startswith("www.") else d


def criticality_of(v: dict) -> str:
    levels = [_RISK.get(str(v.get("risk") or "").upper(), "low"),
              _IMPACT.get(str(v.get("impactLevel") or "").upper(), "low")]
    if v.get("critical") or str(v.get("operationalImpact") or "").upper() == "CRITICAL":
        levels.append("critical")
    if v.get("hasPii") and max(levels, key=_ORDER.index) == "low":
        levels.append("medium")  # holds PII: never below medium
    return max(levels, key=_ORDER.index)


def to_asset(v: dict) -> Asset:
    name = clean_name(v.get("name", "")) or v.get("name", "")
    dom = domain_of(v.get("url", ""))
    notes = "; ".join(x for x in (
        v.get("servicesProvided"),
        f"data: {v['dataStored']}" if v.get("dataStored") else "",
        "stores PII" if v.get("hasPii") else "",
        "sub-processor" if v.get("isSubProcessor") else "",
    ) if x)
    owner = ((v.get("user") or {}).get("email")) or ""
    return Asset(
        name=name,
        keywords=[name],
        domains=[dom] if dom else [],
        criticality=criticality_of(v),
        owner=owner,
        usage=notes[:500],
    )


def match(v: dict, assets: list[Asset]) -> Asset | None:
    """Find the YAML asset describing this Drata vendor: domain > exact name > keyword > word subset."""
    dom = domain_of(v.get("url", ""))
    if dom:
        for a in assets:
            if any(dom == domain_of(d) or dom.endswith("." + domain_of(d)) or domain_of(d).endswith("." + dom)
                   for d in a.domains):
                return a
    n = _norm(v.get("name", ""))
    if not n:
        return None
    for a in assets:
        if _norm(a.name) == n:
            return a
    for a in assets:
        if any(_norm(k) == n for k in a.keywords):
            return a
    w = _words(v.get("name", ""))
    cands = [a for a in assets if w and (w <= _words(a.name) or any(w <= _words(k) for k in a.keywords))]
    return cands[0] if len(cands) == 1 else None


# --------------------------------------------------------------------- merge
def merge(cfg: Config, vendors: list[dict]) -> tuple[Config, list[dict]]:
    """Return (config with Drata applied, report rows for `vendorwatch drata`)."""
    d = cfg.drata
    statuses = {s.upper() for s in (d.get("statuses") or DEFAULT_STATUSES)}
    excluded_names = {_norm(x) for x in d.get("exclude") or []}
    crit_from_drata = str(d.get("criticality_source", "drata")).lower() == "drata"
    keep_unmatched = d.get("keep_unmatched_yaml", True)

    yaml_assets = list(cfg.assets)
    used: dict[int, Asset] = {}   # id(yaml asset) -> merged asset
    dropped: set[int] = set()
    added: list[Asset] = []
    rows = []
    seen_names: set[str] = set()

    for v in vendors:
        status = str(v.get("status") or "NONE").upper()
        y = match(v, yaml_assets)
        row = {"drata": v.get("name", ""), "status": status, "risk": v.get("risk"), "critical": v.get("critical"),
               "yaml": y.name if y else "", "action": ""}
        rows.append(row)
        if _norm(v.get("name", "")) in excluded_names:
            row["action"] = "excluded (drata.exclude)"
            if y:
                dropped.add(id(y))
            continue
        if status not in statuses:
            row["action"] = f"not monitored (status {status})"
            if y and id(y) not in used:
                dropped.add(id(y))
            continue
        base = to_asset(v)
        if y:
            merged = replace(
                y,
                domains=y.domains or base.domains,
                owner=y.owner or base.owner,
                usage=y.usage or base.usage,
                criticality=_max_crit(base.criticality, used[id(y)].criticality) if id(y) in used and crit_from_drata
                else (base.criticality if crit_from_drata else y.criticality),
            )
            used[id(y)] = merged
            dropped.discard(id(y))
            row["action"] = f"monitored as '{y.name}' (criticality {merged.criticality})"
        else:
            key = _norm(base.name)
            if key in seen_names:
                row["action"] = "duplicate of another Drata vendor"
                continue
            seen_names.add(key)
            added.append(base)
            row["action"] = f"added (criticality {base.criticality}, domain {base.domains[0] if base.domains else '-'})"

    final: list[Asset] = []
    for a in yaml_assets:
        if id(a) in used:
            final.append(used[id(a)])
        elif id(a) in dropped:
            continue
        elif keep_unmatched:
            final.append(a)
    names = {x.id for x in final}
    final += [a for a in added if a.id not in names]
    return replace(cfg, assets=final), rows


def _max_crit(a: str, b: str) -> str:
    return max(a, b, key=_ORDER.index)


# --------------------------------------------------------------------- entry point
def apply(cfg: Config, http: Http | None = None, live: bool = True) -> tuple[Config, list[dict], str]:
    """Apply Drata to the config. Uses the live API when `live`, else (or on failure) the
    cached copy from the last successful sync. Returns (config, rows, note)."""
    d = cfg.drata or {}
    if not d.get("enabled"):
        return cfg, [], ""
    cache = Path(cfg.settings.db_path).with_name("drata_vendors.json") if cfg.settings.db_path != ":memory:" else None
    vendors, note = None, ""
    if live:
        key = d.get("api_key", "")
        if not key:
            note = "drata.enabled is true but no API key (set DRATA_API_KEY); "
        else:
            try:
                vendors = fetch_vendors(http or Http(), key, d.get("region", "us"), d.get("base_url", ""))
                if cache:
                    cache.parent.mkdir(parents=True, exist_ok=True)
                    cache.write_text(json.dumps(vendors))
                note = f"Drata: {len(vendors)} vendors synced"
            except Exception as e:  # noqa: BLE001
                note = f"Drata sync failed ({e}); "
    if vendors is None:
        if cache and cache.exists():
            vendors = json.loads(cache.read_text())
            note += f"using cached Drata inventory ({len(vendors)} vendors)"
        else:
            note += "no cached Drata inventory - using the YAML watchlist only"
            return cfg, [], note
    merged, rows = merge(cfg, vendors)
    return merged, rows, note

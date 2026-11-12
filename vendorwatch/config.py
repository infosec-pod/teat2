"""Watchlist / configuration loading.

The watchlist is a YAML file describing the vendors and technologies you care
about. Strings of the form ``${ENV_VAR}`` are expanded from the environment so
secrets (webhook URLs, SMTP passwords) never need to live in the file.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

CRITICALITY_WEIGHT = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


@dataclass
class Asset:
    """A vendor or technology you depend on."""

    name: str
    vendor: str = ""                 # CPE vendor, e.g. "fortinet"
    product: str = ""                # CPE product, e.g. "fortios" (empty = vendor-level / news only)
    part: str = "*"                  # CPE part: a (app), o (os), h (hardware), * (any)
    versions: list[str] = field(default_factory=list)   # versions YOU run
    keywords: list[str] = field(default_factory=list)   # used for news / feed matching
    criticality: str = "medium"      # low | medium | high | critical
    feeds: list[str] = field(default_factory=list)      # extra RSS/Atom feeds (e.g. vendor PSIRT)
    feed_filter: bool = True         # filter the asset's own feeds by keywords
    exclude_keywords: list[str] = field(default_factory=list)  # drop news/feed items mentioning these
    domains: list[str] = field(default_factory=list)  # vendor domains, e.g. salesforce.com (ransomware matching)
    sec_ticker: str = ""             # stock ticker for SEC 8-K monitoring, e.g. CRM
    sec_cik: str = ""                # or the SEC CIK number directly
    owner: str = ""
    notes: str = ""
    usage: str = ""                  # how YOUR org uses this vendor and what data it shares (for threat briefs)

    @property
    def id(self) -> str:
        return slugify(self.name)

    @property
    def cpe_prefix(self) -> str | None:
        if not (self.vendor and self.product):
            return None
        return f"cpe:2.3:{self.part or '*'}:{self.vendor.lower()}:{self.product.lower()}"

    @property
    def weight(self) -> float:
        return CRITICALITY_WEIGHT.get(self.criticality.lower(), 1.0)

    @property
    def search_terms(self) -> list[str]:
        terms = list(self.keywords)
        if not terms:
            terms = [t for t in (self.product, self.vendor, self.name) if t]
        # de-dup, keep order
        seen, out = set(), []
        for t in terms:
            if t.lower() not in seen:
                seen.add(t.lower())
                out.append(t)
        return out


@dataclass
class Settings:
    db_path: str = "data/vendorwatch.db"
    report_path: str = "report.html"
    lookback_days: int = 30          # first-run window for NVD / news
    news_days: int = 7               # Google News "when:" window
    alert_min_priority: str = "P2"   # P1 | P2 | P3 | P4 - alert threshold
    alert_on_news: bool = True
    news_title_match: bool = True    # keep Google News items only if the headline names the asset
    cluster_days: int = 14           # group duplicate coverage of a story seen within this many days
    sec_user_agent: str = ""         # SEC asks for "Company contact@example.com"; env SEC_USER_AGENT
    sec_lookback_days: int = 365     # first-run window for SEC 8-K filings
    ransomware_lookback_days: int = 365  # first-run window for leak-site listings
    nvd_api_key: str = ""
    github_token: str = ""
    max_cveorg_lookups: int = 40
    max_github_lookups: int = 20
    global_feeds: list[str] = field(default_factory=list)
    sources: dict[str, bool] = field(default_factory=dict)

    def source_enabled(self, name: str) -> bool:
        return self.sources.get(name, True)


@dataclass
class Config:
    assets: list[Asset]
    settings: Settings
    notify: dict[str, Any]
    path: str = ""
    drata: dict[str, Any] = field(default_factory=dict)
    organization: dict[str, Any] = field(default_factory=dict)
    briefs: dict[str, Any] = field(default_factory=dict)

    def asset(self, asset_id: str) -> Asset | None:
        for a in self.assets:
            if a.id == asset_id:
                return a
        return None


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (str, int, float)):
        return [str(v)]
    return [str(x) for x in v]


def load_config(path: str | os.PathLike) -> Config:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    raw = _expand_env(raw)

    assets = []
    for i, a in enumerate(raw.get("assets") or []):
        if "name" not in a:
            raise ValueError(f"asset #{i + 1} is missing 'name'")
        assets.append(
            Asset(
                name=a["name"],
                vendor=str(a.get("vendor", "")).lower(),
                product=str(a.get("product", "")).lower(),
                part=str(a.get("part", "*")).lower(),
                versions=_as_list(a.get("versions")),
                keywords=_as_list(a.get("keywords")),
                criticality=str(a.get("criticality", "medium")).lower(),
                feeds=_as_list(a.get("feeds")),
                feed_filter=bool(a.get("feed_filter", True)),
                exclude_keywords=_as_list(a.get("exclude_keywords")),
                domains=_as_list(a.get("domains")),
                sec_ticker=str(a.get("sec_ticker", "") or "").upper(),
                sec_cik=str(a.get("sec_cik", "") or ""),
                owner=str(a.get("owner", "")),
                notes=str(a.get("notes", "")),
                usage=str(a.get("usage", "") or ""),
            )
        )
    ids = [a.id for a in assets]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate asset names: {', '.join(sorted(dupes))}")

    s = raw.get("settings") or {}
    settings = Settings(
        db_path=s.get("db_path", Settings.db_path),
        report_path=s.get("report_path", Settings.report_path),
        lookback_days=int(s.get("lookback_days", Settings.lookback_days)),
        news_days=int(s.get("news_days", Settings.news_days)),
        alert_min_priority=str(s.get("alert_min_priority", Settings.alert_min_priority)).upper(),
        alert_on_news=bool(s.get("alert_on_news", True)),
        news_title_match=bool(s.get("news_title_match", True)),
        cluster_days=int(s.get("cluster_days", Settings.cluster_days)),
        sec_user_agent=s.get("sec_user_agent") or os.environ.get("SEC_USER_AGENT", ""),
        sec_lookback_days=int(s.get("sec_lookback_days", Settings.sec_lookback_days)),
        ransomware_lookback_days=int(s.get("ransomware_lookback_days", Settings.ransomware_lookback_days)),
        nvd_api_key=s.get("nvd_api_key") or os.environ.get("NVD_API_KEY", ""),
        github_token=s.get("github_token") or os.environ.get("GITHUB_TOKEN", ""),
        max_cveorg_lookups=int(s.get("max_cveorg_lookups", Settings.max_cveorg_lookups)),
        max_github_lookups=int(s.get("max_github_lookups", Settings.max_github_lookups)),
        global_feeds=_as_list(s.get("global_feeds")),
        sources=dict(s.get("sources") or {}),
    )
    drata = dict(raw.get("drata") or {})
    if drata.get("enabled") and not drata.get("api_key"):
        drata["api_key"] = os.environ.get("DRATA_API_KEY", "")
    return Config(assets=assets, settings=settings, notify=raw.get("notify") or {}, path=str(path), drata=drata,
                  organization=dict(raw.get("organization") or {}), briefs=dict(raw.get("briefs") or {}))

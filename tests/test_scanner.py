"""End-to-end scan with every network source stubbed out."""
import json
from pathlib import Path

import yaml

from vendorwatch import notify
from vendorwatch.config import load_config
from vendorwatch.scanner import Scanner
from vendorwatch.sources import feeds as F
from vendorwatch.sources import incidents as I
from vendorwatch.sources import vulns as V
from vendorwatch.store import Store

FX = Path(__file__).parent / "fixtures"
NVD = json.loads((FX / "nvd_CVE-2024-21762.json").read_text())


def _cfg(tmp_path, versions):
    p = tmp_path / "w.yaml"
    p.write_text(yaml.safe_dump({
        "assets": [{"name": "FortiGate", "vendor": "fortinet", "product": "fortios", "part": "o",
                    "versions": versions, "criticality": "critical", "keywords": ["FortiOS"]},
                   {"name": "Snowflake", "keywords": ["Snowflake"]}],
        "settings": {"db_path": ":memory:", "sources": {"github_poc": False}},
    }))
    return load_config(p)


def _stub(monkeypatch):
    monkeypatch.setattr(V, "fetch_kev", lambda http: {"CVE-2024-21762": {
        "cveID": "CVE-2024-21762", "vendorProject": "Fortinet", "product": "FortiOS", "dateAdded": "2024-02-09",
        "dueDate": "2024-02-16", "requiredAction": "Apply updates", "knownRansomwareCampaignUse": "Unknown"}})
    monkeypatch.setattr(V.Nvd, "for_cpe", lambda self, cpe, since, until=None: [NVD])
    monkeypatch.setattr(V.Nvd, "by_id", lambda self, cid: None)
    monkeypatch.setattr(V, "fetch_epss", lambda http, ids: {"CVE-2024-21762": {"epss": 0.85, "percentile": 0.99}})
    monkeypatch.setattr(V, "fetch_cveorg", lambda http, cid: None)
    monkeypatch.setattr(I, "ransomware_recent", lambda http: [])
    monkeypatch.setattr(I, "ransomware_months", lambda http, months: ([], True))
    monkeypatch.setattr(I.Sec, "filings_8k", lambda self, cik, start: [])
    monkeypatch.setattr(I.Sec, "mentions_cyber", lambda self, url: False)
    monkeypatch.setattr(I.Sec, "resolve_cik", lambda self, t, name="": "0000000001")
    monkeypatch.setattr(F, "exploitdb", lambda http: [])
    monkeypatch.setattr(F, "fetch_feed", lambda http, url: [])
    monkeypatch.setattr(F, "google_news", lambda http, terms, days: [
        {"title": "Snowflake customers hit by data breach - Wired", "url": "https://x/1", "published": "",
         "summary": "", "source": "Wired"}] if "Snowflake" in terms else [])


def test_scan_alerts_then_dedups_then_reassesses(tmp_path, monkeypatch):
    _stub(monkeypatch)
    cfg = _cfg(tmp_path, ["7.4.2"])
    store = Store(":memory:")
    res = Scanner(cfg, store).run()
    keys = {a.finding["key"]: a for a in res.alerts}
    cve = keys["cve:fortigate:CVE-2024-21762"].finding
    assert cve["priority"] == "P1"
    assert cve["data"]["impact"]["fixed_versions"] == ["7.4.3"]
    assert any(k.startswith("news:snowflake:") for k in keys)
    assert res.scores["fortigate"][1] in ("C", "D", "B")
    text = notify.render_text(res.alerts, {"fortigate": "FortiGate"}, res.scores)
    assert "Upgrade to: 7.4.3" in text and "CISA KEV" in text
    for a in res.alerts:
        store.mark_notified(a.finding["key"], a.finding["priority"])

    # second scan: nothing new
    assert Scanner(cfg, store).run().alerts == []

    # upgrade -> CVE no longer affects us, score recovers
    cfg2 = _cfg(tmp_path, ["7.4.3"])
    res3 = Scanner(cfg2, store).run()
    f = store.get("cve:fortigate:CVE-2024-21762")
    assert f["priority"] == "P4" and f["data"]["impact"]["affected"] is False
    assert res3.scores["fortigate"][0] == 100


def test_news_title_match_and_excludes(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.setattr(F, "google_news", lambda http, terms, days: [
        {"title": "Snowflake customers hit by data breach - Wired", "url": "https://x/1", "published": "", "summary": "", "source": "Wired"},
        {"title": "Big retailer breached - Wired", "url": "https://x/2", "published": "", "summary": "snowflake mentioned in body", "source": "Wired"},
        {"title": "Snowflake phishing scam warning - Blog", "url": "https://x/3", "published": "", "summary": "", "source": "Blog"},
    ] if "Snowflake" in terms else [])
    p = tmp_path / "w.yaml"
    p.write_text(yaml.safe_dump({"assets": [{"name": "Snowflake", "keywords": ["Snowflake"], "exclude_keywords": ["scam"]}],
                                 "settings": {"db_path": ":memory:"}}))
    store = Store(":memory:")
    Scanner(load_config(p), store).run()
    assert [f["url"] for f in store.findings("snowflake")] == ["https://x/1"]


def _news(title, url, source="X"):
    return {"title": f"{title} - {source}", "url": url, "published": "", "summary": "", "source": source}


def test_duplicate_stories_are_grouped(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.setattr(F, "google_news", lambda http, terms, days: [
        _news("AU Small Finance Bank data leak: Salesforce says no platform vulnerability identified", "https://a/1", "CNBC"),
        _news("Salesforce denies vulnerability in AU Small Finance Bank data breach", "https://a/2", "NewsBytes"),
        _news("AU Small Finance Bank investigates suspected Salesforce data breach", "https://a/3", "BusinessLine"),
        _news("Infinite Campus: Salesforce Breach Exposed 137,000 Staff Records", "https://a/4", "TechRepublic"),
    ])
    p = tmp_path / "w.yaml"
    p.write_text(yaml.safe_dump({"assets": [{"name": "Salesforce", "keywords": ["Salesforce"]}],
                                 "settings": {"db_path": ":memory:"}}))
    cfg, store = load_config(p), Store(":memory:")
    res = Scanner(cfg, store).run()
    news = store.findings("salesforce", types=["news"])
    assert len(news) == 2
    au = next(f for f in news if "AU Small" in f["title"])
    assert [c["url"] for c in au["data"]["coverage"]] == ["https://a/2", "https://a/3"]
    assert len(res.alerts) == 2  # one alert per story, not per article
    text = notify.render_text(res.alerts, {"salesforce": "Salesforce"})
    assert "Also reported by 2 more source(s): NewsBytes, BusinessLine" in text
    # next run: same articles again -> nothing new, nothing duplicated
    for a in res.alerts:
        store.mark_notified(a.finding["key"], a.finding["priority"])
    assert Scanner(cfg, store).run().alerts == []
    assert len(store.get(au["key"])["data"]["coverage"]) == 2


def test_ransomware_and_sec_findings(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.setattr(I, "ransomware_recent", lambda http: [
        {"victim": "HawkSoft", "domain": "hawksoft.com", "group": "akira", "attackdate": "", "discovered": "",
         "description": "uses Salesforce"},
        {"victim": "Solutis", "domain": "solutis.com.br", "group": "x", "description": "Salesforce partner"},
    ])
    monkeypatch.setattr(I.Sec, "mentions_cyber", lambda self, url: url == "https://sec/3")
    monkeypatch.setattr(I.Sec, "filings_8k", lambda self, cik, start: [
        {"adsh": "0001-26-1", "form": "8-K", "file_date": "2026-11-01", "items": ["1.05", "9.01"],
         "company": "Salesforce, Inc. (CRM)", "url": "https://sec/1"},
        {"adsh": "0001-26-2", "form": "8-K", "file_date": "2026-10-01", "items": ["2.02", "9.01"],
         "company": "Salesforce, Inc. (CRM)", "url": "https://sec/2"},
        {"adsh": "0001-26-3", "form": "8-K", "file_date": "2026-09-01", "items": ["8.01"],
         "company": "Salesforce, Inc.", "url": "https://sec/3"},
        {"adsh": "0001-26-4", "form": "8-K", "file_date": "2026-08-01", "items": ["8.01"],
         "company": "Salesforce, Inc.", "url": "https://sec/4"},
    ])
    p = tmp_path / "w.yaml"
    p.write_text(yaml.safe_dump({"assets": [
        {"name": "Salesforce", "keywords": ["Salesforce"], "domains": ["salesforce.com"], "sec_ticker": "CRM",
         "criticality": "critical"},
        {"name": "HawkSoft", "keywords": ["HawkSoft"], "domains": ["hawksoft.com"], "criticality": "medium"}],
        "settings": {"db_path": ":memory:", "sources": {"google_news": False}}}))
    store = Store(":memory:")
    res = Scanner(load_config(p), store).run()
    by_type = {(a.finding["asset_id"], a.finding["type"]): a.finding for a in res.alerts}
    secs = {f["data"]["adsh"]: f for f in store.findings("salesforce", types=["sec"])}
    assert set(secs) == {"0001-26-1", "0001-26-3"}     # earnings 8-K and non-cyber 8.01 ignored
    assert secs["0001-26-1"]["priority"] == "P1"       # Item 1.05 at a critical vendor
    assert secs["0001-26-3"]["priority"] == "P2"       # 8.01 cyber disclosure
    assert store.findings("salesforce", types=["ransomware"]) == []       # description match ignored
    assert by_type[("hawksoft", "ransomware")]["priority"] == "P2"        # medium vendor
    assert res.scores["hawksoft"][0] == 70 and res.scores["salesforce"][0] == 67

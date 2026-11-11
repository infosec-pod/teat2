"""End-to-end scan with every network source stubbed out."""
import json
from pathlib import Path

import yaml

from vendorwatch import notify
from vendorwatch.config import load_config
from vendorwatch.scanner import Scanner
from vendorwatch.sources import feeds as F
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

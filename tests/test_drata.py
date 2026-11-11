from pathlib import Path

import pytest

from vendorwatch import drata
from vendorwatch.config import load_config

ROOT = Path(__file__).resolve().parent.parent


def V(name, url="", status="ACTIVE", risk="MODERATE", critical=False, **kw):
    return {"name": name, "url": url, "status": status, "risk": risk, "critical": critical, **kw}


# the vendor names exactly as they appear in the user's Drata inventory
USER_LIST = [
    V("Salesforce", "https://www.salesforce.com", risk="HIGH", critical=True),
    V("NetSuite", "https://www.netsuite.com", risk="HIGH"),
    V("Snowflake", "https://www.snowflake.com"),
    V("Claude", "https://claude.ai"),
    V("Snowflake"),
    V("DOMO"), V("TitanDXP"), V("Badger"), V("Proposify"), V("SurveyMonkey"),
    V("Hawk soft", hasPii=True, risk="LOW"),
    V("Salesforce, Inc"), V("ATLASSIAN"), V("AG Grid Ltd"), V("Docker"),
    V("Zapier.com"), V("Userguiding.com"), V("Docusign"), V("Godaddy.com"),
    V("Loom Inc"), V("Adobe, Inc"), V("Amazon Web Services"),
]


def test_clean_name_and_domain():
    assert drata.clean_name("Salesforce, Inc") == "Salesforce"
    assert drata.clean_name("Zapier.com") == "Zapier"
    assert drata.clean_name("AG Grid Ltd") == "AG Grid"
    assert drata.clean_name("Loom Inc") == "Loom"
    assert drata.domain_of("https://www.salesforce.com/about") == "salesforce.com"


def test_criticality_mapping():
    assert drata.criticality_of(V("x", risk="LOW", critical=True)) == "critical"
    assert drata.criticality_of(V("x", risk="HIGH")) == "high"
    assert drata.criticality_of(V("x", risk="LOW", impactLevel="MAJOR")) == "high"
    assert drata.criticality_of(V("x", risk="LOW", hasPii=True)) == "medium"
    assert drata.criticality_of(V("x", risk="NONE")) == "low"


def test_user_inventory_maps_onto_existing_watchlist():
    cfg = load_config(ROOT / "watchlist.yaml")
    cfg.drata = {"enabled": True}
    merged, rows = drata.merge(cfg, USER_LIST)
    by = {r["drata"]: r for r in rows}
    expect = {"Salesforce, Inc": "Salesforce", "Claude": "Anthropic Claude", "DOMO": "Domo", "Hawk soft": "HawkSoft",
              "ATLASSIAN": "Atlassian", "AG Grid Ltd": "AG Grid", "Zapier.com": "Zapier",
              "Userguiding.com": "UserGuiding", "Godaddy.com": "GoDaddy", "Loom Inc": "Loom",
              "Adobe, Inc": "Adobe", "Badger": "Badger", "Docusign": "DocuSign"}
    for d, y in expect.items():
        assert by[d]["yaml"] == y, (d, by[d])
    names = [a.name for a in merged.assets]
    assert len(names) == len(set(names)) == 20          # nothing duplicated, nothing extra
    sf = merged.asset("salesforce")
    assert sf.criticality == "critical" and sf.sec_cik == "1108524"   # Drata risk + YAML tuning
    assert merged.asset("hawksoft").criticality == "medium"           # LOW risk but holds PII


def test_new_offboarded_and_yaml_only(tmp_path):
    p = tmp_path / "w.yaml"
    p.write_text("""
assets:
  - name: FortiGate
    vendor: fortinet
    product: fortios
    versions: ["7.4.3"]
  - name: Zapier
    keywords: [Zapier]
    domains: [zapier.com]
  - name: OldVendor
    keywords: [OldVendor]
drata:
  enabled: true
  exclude: [Internal Tool]
settings: {db_path: ":memory:"}
""")
    cfg = load_config(p)
    merged, rows = drata.merge(cfg, [
        V("Zapier.com", "https://zapier.com", risk="HIGH"),
        V("OldVendor", status="OFFBOARDED"),
        V("Gusto", "https://gusto.com", risk="HIGH", hasPii=True, servicesProvided="Payroll", user={"email": "hr@x.com"}),
        V("Internal Tool"),
        V("Prospect Co", status="PROSPECTIVE"),
    ])
    names = {a.name: a for a in merged.assets}
    assert set(names) == {"FortiGate", "Zapier", "Gusto"}
    assert names["Zapier"].criticality == "high"
    g = names["Gusto"]
    assert g.domains == ["gusto.com"] and g.keywords == ["Gusto"] and g.owner == "hr@x.com" and "Payroll" in g.notes


class _Resp:
    def __init__(self, code, body=None):
        self.status_code, self._b = code, body or {}

    def json(self):
        return self._b

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


class _Sess:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, dict(params), headers))
        return self.pages.pop(0)


def test_fetch_paginates_and_reports_errors():
    http = drata.Http()
    http.s = _Sess([_Resp(200, {"data": [{"name": "A"}], "pagination": {"cursor": "abc"}}),
                    _Resp(200, {"data": [{"name": "B"}], "pagination": {"cursor": None}})])
    out = drata.fetch_vendors(http, "k", "eu")
    assert [v["name"] for v in out] == ["A", "B"]
    assert http.s.calls[0][0] == "https://public-api.eu.drata.com/public/v2/vendors"
    assert http.s.calls[1][1]["cursor"] == "abc"
    assert http.s.calls[0][2]["Authorization"] == "Bearer k"
    http.s = _Sess([_Resp(402)])
    with pytest.raises(drata.DrataError, match="TPRM"):
        drata.fetch_vendors(http, "k")


def test_apply_falls_back_to_cache(tmp_path, monkeypatch):
    p = tmp_path / "w.yaml"
    p.write_text(f"assets: []\ndrata: {{enabled: true, api_key: k}}\nsettings: {{db_path: '{tmp_path}/data/vw.db'}}\n")
    cfg = load_config(p)
    monkeypatch.setattr(drata, "fetch_vendors", lambda *a, **k: [V("Gusto", "https://gusto.com")])
    merged, _, note = drata.apply(cfg)
    assert [a.name for a in merged.assets] == ["Gusto"] and "1 vendors synced" in note

    def boom(*a, **k):
        raise drata.DrataError("down")
    monkeypatch.setattr(drata, "fetch_vendors", boom)
    merged, _, note = drata.apply(cfg)
    assert [a.name for a in merged.assets] == ["Gusto"] and "cached" in note

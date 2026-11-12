import json
from types import SimpleNamespace as NS

import yaml

from vendorwatch import briefs, notify
from vendorwatch.config import load_config
from vendorwatch.scanner import Alert
from vendorwatch.store import Store

BRIEF = {
    "headline": "Salesforce-linked leak at AU SFB; no SIAA tenant indicated",
    "threat_level": "medium", "confidence": "medium",
    "bottom_line": "A customer's Salesforce data leaked; Salesforce denies a platform flaw.",
    "what_happened": "REPORTED: data from AU SFB's Salesforce instance was posted.",
    "relevance": "SIAA stores agency client PII in Salesforce.",
    "potential_impacts": ["Exposure of client PII if the same technique is used against SIAA"],
    "unknowns": ["Was the access via a third-party connected app?"],
    "recommended_actions": [
        {"action": "Review connected apps and OAuth tokens in SIAA's Salesforce org", "owner": "IT", "urgency": "this_week"},
        {"action": "Confirm MFA is enforced for all Salesforce users", "owner": "Security", "urgency": "immediate"}],
    "vendor_questions": ["Is any SIAA tenant affected?"],
    "regulatory_notes": "",
    "sources": [{"title": "CNBC", "url": "https://a/1"}],
}


class FakeMessages:
    def __init__(self):
        self.calls = []

    def create(self, **kw):
        self.calls.append(kw)
        if "tools" in kw:  # research call
            search = NS(type="web_search_tool_result", content=[NS(url="https://a/9", title="Vendor statement")])
            return NS(stop_reason="end_turn", model=kw["model"],
                      content=[search, NS(type="text", text="CONFIRMED: Salesforce statement ...")])
        return NS(stop_reason="end_turn", model=kw["model"], content=[NS(type="text", text=json.dumps(BRIEF))])


class FakeClient:
    def __init__(self):
        self.beta = NS(messages=FakeMessages())


def _setup(tmp_path, **brief_cfg):
    p = tmp_path / "w.yaml"
    p.write_text(yaml.safe_dump({
        "organization": {"name": "SIAA", "description": "Insurance agency alliance", "data_handled": ["client PII"]},
        "briefs": {"enabled": True, "dir": str(tmp_path / "briefs"), **brief_cfg},
        "assets": [{"name": "Salesforce", "keywords": ["Salesforce"], "criticality": "critical",
                    "usage": "CRM holding agency client PII"}],
        "settings": {"db_path": ":memory:"}}))
    cfg, store = load_config(p), Store(":memory:")
    store.upsert({"key": "news:salesforce:1", "asset_id": "salesforce", "type": "news", "priority": "P2",
                  "title": "AU SFB data leak: Salesforce says no vulnerability", "url": "https://a/1",
                  "published": "2026-11-10", "data": {"category": "breach", "coverage": [{"title": "x", "url": "https://a/2"}]}})
    return cfg, store


def test_brief_is_researched_written_stored_and_rendered(tmp_path):
    cfg, store = _setup(tmp_path)
    client = FakeClient()
    done, errors = briefs.brief_findings(cfg, store, [store.get("news:salesforce:1")], client=client)
    assert (done, errors) == (1, [])
    research, write = client.beta.messages.calls
    assert research["tools"][0]["type"] == "web_search_20260209" and research["fallbacks"] == "default"
    assert "CRM holding agency client PII" in research["messages"][0]["content"]
    assert "SIAA" in write["system"] and "Insurance agency alliance" in write["system"]
    assert write["output_config"]["format"]["schema"] == briefs.BRIEF_SCHEMA
    assert "https://a/9" in write["messages"][0]["content"]  # searched URLs passed on for citing
    f = store.get("news:salesforce:1")
    b = f["data"]["brief"]
    assert b["threat_level"] == "medium" and b["org"] == "SIAA" and b["for_priority"] == "P2"
    md = open(b["file"]).read()
    assert "## Relevance to SIAA" in md
    assert md.index("| Immediately | Confirm MFA") < md.index("| This week | Review connected apps")
    text = notify.render_text([Alert(f, "new")], {"salesforce": "Salesforce"})
    assert "Threat to SIAA: MEDIUM" in text and "[immediate] Confirm MFA" in text


def test_brief_survives_rescan_and_is_not_regenerated(tmp_path):
    cfg, store = _setup(tmp_path)
    briefs.brief_findings(cfg, store, [store.get("news:salesforce:1")], client=FakeClient())
    # a rescan rebuilds the finding's data from scratch
    store.upsert({"key": "news:salesforce:1", "asset_id": "salesforce", "type": "news", "priority": "P2",
                  "title": "t", "url": "https://a/1", "data": {"category": "breach"}})
    f = store.get("news:salesforce:1")
    assert f["data"]["brief"]["headline"] and f["data"]["coverage"]
    client = FakeClient()
    assert briefs.brief_findings(cfg, store, [f], client=client) == (0, [])
    assert client.beta.messages.calls == []
    # escalation to P1 -> re-briefed
    f["priority"] = "P1"
    assert briefs.brief_findings(cfg, store, [f], client=client)[0] == 1


def test_cap_refusal_and_no_usage(tmp_path):
    cfg, store = _setup(tmp_path, max_per_run=0, research=False)
    done, errors = briefs.brief_findings(cfg, store, [store.get("news:salesforce:1")], client=FakeClient())
    assert done == 0 and "max_per_run" in errors[0]

    cfg, store = _setup(tmp_path, research=False)
    client = FakeClient()
    client.beta.messages.create = lambda **kw: NS(stop_reason="refusal", stop_details=NS(category="cyber"), content=[])
    done, errors = briefs.brief_findings(cfg, store, [store.get("news:salesforce:1")], client=client)
    assert done == 0 and "declined" in errors[0]

    cfg.assets[0].usage = ""
    text = briefs._finding_text(store.get("news:salesforce:1"), cfg.assets[0])
    assert "NOT DOCUMENTED" in text

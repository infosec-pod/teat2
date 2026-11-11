from vendorwatch.scoring import asset_score, cve_priority, grade_for
from vendorwatch.sources.feeds import categorize, extract_cves, matches_terms, parse_feed

RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Fortinet warns of FortiOS SSL VPN flaw CVE-2024-21762 exploited in attacks - BleepingComputer</title>
<link>https://example.com/a</link><pubDate>Fri, 09 Feb 2024 10:00:00 GMT</pubDate>
<description>&lt;p&gt;Critical &lt;b&gt;RCE&lt;/b&gt;&lt;/p&gt;</description></item>
<item><title>Unrelated</title><link>https://example.com/b</link></item></channel></rss>"""

ATOM = """<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>x</title>
<entry><title>PAN-OS advisory</title><link href="https://example.com/c"/><updated>2026-01-02T03:04:05Z</updated>
<summary>GlobalProtect issue</summary></entry></feed>"""


def test_parse_rss_and_atom():
    items = parse_feed(RSS)
    assert items[0]["url"] == "https://example.com/a"
    assert items[0]["summary"] == "Critical RCE"
    assert items[0]["published"].startswith("2024-02-09")
    atom = parse_feed(ATOM)
    assert atom[0]["url"] == "https://example.com/c" and atom[0]["title"] == "PAN-OS advisory"


def test_extract_categorize_match():
    t = parse_feed(RSS)[0]["title"]
    assert extract_cves(t) == ["CVE-2024-21762"]
    assert categorize(t) == "exploit"
    assert categorize("Okta confirms data breach") == "breach"
    assert matches_terms(t, ["FortiOS"]) and not matches_terms("FortiOSX", ["FortiOS"])


def test_cve_priority():
    kw = dict(impact_source="nvd", cvss=9.8, epss=0.9, kev=True, exploit_public=False, kev_vendor_match=True, criticality="high")
    assert cve_priority(affected=True, **kw)[0] == "P1"
    assert cve_priority(affected=False, **kw)[0] == "P4"
    assert cve_priority(affected=None, **kw)[0] == "P2"
    low = dict(kw, cvss=5.0, epss=0.0, kev=False)
    assert cve_priority(affected=True, **low)[0] == "P3"
    assert cve_priority(affected=True, **dict(low, criticality="critical"))[0] == "P3"
    assert cve_priority(affected=True, **dict(low, cvss=6.5, criticality="critical"))[0] == "P2"


def test_asset_score():
    f = lambda p, aff: {"type": "cve", "priority": p, "status": "open", "data": {"impact": {"affected": aff}}}
    assert asset_score([])[:2] == (100, "A")
    score, grade, drivers = asset_score([f("P1", True), f("P2", True), f("P4", False)])
    assert score == 65 and grade == "D" and drivers
    assert grade_for(59) == "F"

from vendorwatch.config import Asset
from vendorwatch.sources.incidents import classify_8k, victim_matches


def test_victim_matching():
    adobe = Asset(name="Adobe", keywords=["Adobe"], domains=["adobe.com"])
    assert victim_matches({"victim": "Adobe Inc.", "domain": ""}, adobe)
    assert victim_matches({"victim": "x", "domain": "www.adobe.com"}, adobe)
    assert victim_matches({"victim": "adobe.com", "domain": ""}, adobe)
    assert not victim_matches({"victim": "Adobe Dental Clinic", "domain": "adobedental.com"}, adobe)
    assert not victim_matches({"victim": "Acme", "domain": "acme.com", "description": "Adobe partner"}, adobe)
    nodomain = Asset(name="HawkSoft", keywords=["HawkSoft"])
    assert victim_matches({"victim": "HawkSoft LLC"}, nodomain)
    assert not victim_matches({"victim": "Hawk Logistics"}, nodomain)


def test_classify_8k():
    assert classify_8k(["1.05", "9.01"]) == "material"
    assert classify_8k(["8.01"]) == "voluntary"
    assert classify_8k(["2.02", "8.01", "9.01"]) is None   # earnings release boilerplate
    assert classify_8k(["7.01", "9.01"]) is None


def test_months_back():
    from datetime import datetime, timezone
    from vendorwatch.sources.incidents import months_back
    now = datetime(2026, 11, 11, tzinfo=timezone.utc)
    assert months_back(now, 7) == [(2026, 11)]
    assert months_back(now, 15) == [(2026, 11), (2026, 10)]
    assert len(months_back(now, 365)) == 13 and months_back(now, 365)[-1] == (2025, 11)

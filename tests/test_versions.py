import json
from pathlib import Path

import pytest

from vendorwatch.versions import Range, assess, compare, description_ranges, reassess

FX = Path(__file__).parent / "fixtures"
NVD = json.loads((FX / "nvd_CVE-2024-21762.json").read_text())
CNA = json.loads((FX / "cveorg_CVE-2024-21762.json").read_text())


@pytest.mark.parametrize("a,b,expected", [
    ("7.4.2", "7.4.3", -1),
    ("7.4", "7.4.0", 0),
    ("7.10.0", "7.9.9", 1),
    ("7.4.3a", "7.4.3", 1),
    ("1.0rc1", "1.0", -1),
    ("22.7r2.3", "22.7r2.4", -1),
    ("v2.0", "2.0", 0),
])
def test_compare(a, b, expected):
    assert compare(a, b) == expected


def test_range_contains():
    r = Range(start_incl="7.4.0", end_excl="7.4.3")
    assert r.contains("7.4.2") and not r.contains("7.4.3") and not r.contains("7.2.9")
    assert r.fixed_in == "7.4.3"


def test_nvd_affected_with_fix_version():
    imp = assess(NVD, None, "fortinet", "fortios", "o", ["7.4.2", "7.2.8"])
    assert imp.affected is True and imp.source == "nvd"
    assert imp.affected_versions == ["7.4.2"]
    assert imp.fixed_versions == ["7.4.3"]


def test_nvd_not_affected():
    imp = assess(NVD, None, "fortinet", "fortios", "o", ["7.4.3", "7.6.0"])
    assert imp.affected is False


def test_nvd_other_product_is_not_affected():
    imp = assess(NVD, None, "fortinet", "fortiweb", "*", ["7.4.0"])
    assert imp.affected is False and imp.source == "nvd-other-product"


def test_no_versions_is_unknown():
    imp = assess(NVD, None, "fortinet", "fortios", "o", [])
    assert imp.affected is None and imp.product_match


def test_cna_fallback_when_nvd_unanalysed():
    nvd = dict(NVD, configurations=[])
    imp = assess(nvd, CNA, "fortinet", "fortios", "o", ["7.4.2", "7.4.3"], ["FortiOS"])
    assert imp.source == "cna"
    assert imp.affected is True and imp.affected_versions == ["7.4.2"]


def test_description_fallback_never_says_not_affected():
    r = description_ranges("FortiOS version 7.4.0 through 7.4.2 and 7.2.0 through 7.2.6 allows ...")
    assert len(r) == 2
    rec = {"id": "CVE-X", "descriptions": [{"lang": "en", "value": "FortiOS version 7.4.0 through 7.4.2 allows"}]}
    assert assess(rec, None, "fortinet", "fortios", "o", ["7.4.1"]).affected is True
    assert assess(rec, None, "fortinet", "fortios", "o", ["7.6.0"]).affected is None


def test_reassess_after_upgrade():
    imp = assess(NVD, None, "fortinet", "fortios", "o", ["7.4.2"])
    stored = imp.to_dict()
    assert reassess(stored, ["7.4.2"]).affected is True
    assert reassess(stored, ["7.4.3"]).affected is False


def test_fix_version_recovered_from_description_for_exact_cpes():
    cve = {"id": "CVE-2025-0282",
           "descriptions": [{"lang": "en", "value": "A stack-based buffer overflow in Ivanti Connect Secure before version "
                             "22.7R2.5, Ivanti Policy Secure before version 22.7R1.2 allows RCE."}],
           "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
               {"vulnerable": True, "criteria": f"cpe:2.3:a:ivanti:connect_secure:22.7:r2.{i}:*:*:*:*:*:*"} for i in range(5)]}]}]}
    imp = assess(cve, None, "ivanti", "connect_secure", "a", ["22.7r2.3"])
    assert imp.affected is True and imp.fixed_versions == ["22.7R2.5"]


def test_description_before_list():
    r = description_ranges("Ivanti Connect Secure before versions 25.1.1.3 and 22.8R2.6 allows")
    assert sorted(x.end_excl for x in r) == ["22.8R2.6", "25.1.1.3"]

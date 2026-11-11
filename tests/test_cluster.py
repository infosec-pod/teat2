from vendorwatch.cluster import same_story, tokens

V = ["Salesforce"]


def t(s):
    return tokens(s, V)


def test_same_story_across_outlets():
    a = t("AU Small Finance Bank data leak: Salesforce says no platform vulnerability identified - CNBC")
    b = t("Salesforce denies vulnerability in AU Small Finance Bank data breach - NewsBytes")
    assert same_story(a, b)


def test_different_stories_stay_apart():
    a = t("AU Small Finance Bank investigates suspected Salesforce data breach")
    b = t("Infinite Campus: Salesforce Breach Exposed 137,000 Staff Records")
    assert not same_story(a, b)
    # generic words alone never link two stories
    assert not same_story(t("Salesforce data breach hits customers"), t("Customers hit by Salesforce data breach claims"))


def test_shared_cve_links_stories():
    assert same_story(t("Patch now"), t("Exploit released"), ["CVE-2026-1"], ["CVE-2026-1"])

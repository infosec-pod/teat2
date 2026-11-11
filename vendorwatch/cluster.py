"""Group duplicate coverage of the same story into one finding.

Ten outlets reporting the same breach should produce one alert with ten
sources, not ten alerts. Two headlines are treated as the same story when,
after dropping the vendor's own name, publisher suffixes and filler words,
they share enough distinctive words (overlap coefficient), or they cite the
same CVE.
"""
from __future__ import annotations

import re

STOPWORDS = set("""
a an the and or of to in on for with by from at as is are was were be been has have had it its this that these
those after before over under amid into about against says said say report reports reported new latest
update updates how why what who when where week weekly could may might can will would should not no
""".split())

# generic risk words: they count, but on their own aren't enough to link two stories
GENERIC = set("""
data breach breaches breached hack hacked hacker hackers attack attacks cyberattack cyber security
vulnerability vulnerabilities flaw flaws bug exploit exploited leak leaked incident ransomware outage
customer customers users accounts patch patches critical
""".split())

_PUBLISHER = re.compile(r"\s[-|–—]\s[^-|–—]{2,60}$")


def tokens(title: str, vendor_terms: list[str]) -> set[str]:
    t = _PUBLISHER.sub("", title or "").lower()
    words = set(re.findall(r"[a-z0-9][a-z0-9.\-']*[a-z0-9]|[a-z0-9]", t))
    vendor_words = {w for term in vendor_terms for w in re.findall(r"[a-z0-9]+", term.lower())}
    words = {w.strip(".'") for w in words}
    words = {(w[:-2] if w.endswith("'s") else w) for w in words}
    return {w for w in words if w and w not in STOPWORDS and w not in vendor_words and len(w) > 1}


def same_story(a: set[str], b: set[str], cves_a: list[str] | None = None, cves_b: list[str] | None = None,
               threshold: float = 0.6, min_shared: int = 3) -> bool:
    if cves_a and cves_b and set(cves_a) & set(cves_b):
        return True
    if not a or not b:
        return False
    shared = a & b
    if len(shared) < min_shared:
        return False
    if not (shared - GENERIC):  # must share at least one distinctive word (a name, a place...)
        return False
    return len(shared) / min(len(a), len(b)) >= threshold

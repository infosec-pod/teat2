"""Prioritisation of individual findings and an A-F risk grade per vendor/technology."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

PRIORITY_LABEL = {
    "P1": "Act now",
    "P2": "Patch / investigate soon",
    "P3": "Track",
    "P4": "Informational",
}


def cve_priority(*, affected, impact_source: str, cvss, epss: float, kev: bool, exploit_public: bool,
                 kev_vendor_match: bool, criticality: str) -> tuple[str, list[str]]:
    """Return (priority, reasons)."""
    reasons = []
    if kev:
        reasons.append("CISA KEV: actively exploited")
    if exploit_public:
        reasons.append("public exploit / PoC available")
    if epss >= 0.1:
        reasons.append(f"EPSS {epss:.0%} chance of exploitation in 30 days")
    hot = kev or exploit_public or epss >= 0.3
    high = cvss is None or cvss >= 7.0

    if affected is True:
        reasons.insert(0, "affects a version you run")
        if hot:
            p = "P1"
        elif high:
            p = "P2"
        else:
            p = "P3"
        if p == "P3" and criticality == "critical" and (cvss or 0) >= 6.0:
            p = "P2"
        return p, reasons

    if affected is False:
        reasons.insert(0, "your versions are not affected" if impact_source != "nvd-other-product"
                       else "your product is not in the vulnerable configuration")
        return "P4", reasons

    # unknown impact
    if impact_source == "cna-other-product" and not (kev and kev_vendor_match):
        reasons.insert(0, "mentions this vendor, but a different product is listed")
        return "P4", reasons
    reasons.insert(0, "impact on your versions unknown - verify")
    if hot:
        return "P2", reasons
    if high:
        return "P3", reasons
    return "P4", reasons


def news_priority(category: str, mentions_hot_cve: bool) -> str:
    if mentions_hot_cve:
        return "P1"
    if category in ("exploit", "breach"):
        return "P2"
    if category in ("vulnerability", "patch"):
        return "P3"
    return "P4"


def _recent(f: dict, days: int) -> bool:
    ts = f.get("published") or f.get("first_seen") or ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return True
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt >= datetime.now(timezone.utc) - timedelta(days=days)


def grade_for(score: int) -> str:
    for g, floor in (("A", 90), ("B", 80), ("C", 70), ("D", 60)):
        if score >= floor:
            return g
    return "F"


def asset_score(findings: list[dict]) -> tuple[int, str, list[str]]:
    """Score 0-100 (higher is better) from open findings. Returns (score, grade, drivers)."""
    penalty = 0.0
    drivers: dict[str, float] = {}

    def hit(reason, pts):
        nonlocal penalty
        penalty += pts
        drivers[reason] = drivers.get(reason, 0) + pts

    news_pen = 0.0
    for f in findings:
        if f.get("status") != "open":
            continue
        d = f.get("data", {})
        p = f["priority"]
        if f["type"] == "cve":
            aff = d.get("impact", {}).get("affected")
            if aff is True:
                hit("exploitable CVEs in your versions" if p == "P1" else "unpatched CVEs in your versions",
                    {"P1": 25, "P2": 10, "P3": 3}.get(p, 0))
            elif aff is None and p in ("P2", "P3"):
                hit("CVEs with unverified impact", 4 if p == "P2" else 1)
        elif f["type"] in ("news", "advisory", "exploit") and _recent(f, 30):
            cat = d.get("category", "")
            pts = 0.0
            if cat == "breach":
                pts = 8
            elif f["type"] == "exploit" or cat == "exploit":
                pts = 4
            if pts and news_pen < 30:
                pts = min(pts, 30 - news_pen)
                news_pen += pts
                hit("recent breach / attack news" if cat == "breach" else "exploit activity in the news", pts)

    score = max(0, int(round(100 - penalty)))
    top = [f"{k} (-{int(v)})" for k, v in sorted(drivers.items(), key=lambda kv: -kv[1])]
    return score, grade_for(score), top

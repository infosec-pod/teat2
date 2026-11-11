"""The scan engine: pull every source, correlate by asset + CVE, prioritise, persist, collect alerts."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .cluster import same_story, tokens
from .config import Asset, Config
from .scoring import PRIORITY_LABEL, asset_score, cve_priority, news_priority
from .sources import Http
from .sources import feeds as F
from .sources import incidents as I
from .sources import vulns as V
from .store import PRIORITY_RANK, Store
from .versions import assess, reassess

log = logging.getLogger("vendorwatch")


@dataclass
class Alert:
    finding: dict
    change: str                      # new | escalated
    previous_priority: str | None = None


@dataclass
class ScanResult:
    alerts: list[Alert] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    scores: dict[str, tuple[int, str, list[str]]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    first_run: bool = False


def _h(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:12]


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class Scanner:
    def __init__(self, cfg: Config, store: Store, http: Http | None = None):
        self.cfg = cfg
        self.s = cfg.settings
        self.store = store
        self.http = http or Http()
        self.nvd = V.Nvd(self.http, self.s.nvd_api_key)
        self._nvd_cache: dict[str, dict | None] = {}
        self._cna_cache: dict[str, dict | None] = {}
        self._cveorg_budget = self.s.max_cveorg_lookups
        self._github_budget = self.s.max_github_lookups if self.s.github_token else 0

    # ----------------------------------------------------------------- helpers
    def _nvd_by_id(self, cve_id: str) -> dict | None:
        if cve_id not in self._nvd_cache:
            try:
                self._nvd_cache[cve_id] = self.nvd.by_id(cve_id)
            except Exception as e:  # noqa: BLE001
                log.warning("NVD lookup %s failed: %s", cve_id, e)
                self._nvd_cache[cve_id] = None
        return self._nvd_cache[cve_id]

    def _cna(self, cve_id: str) -> dict | None:
        if cve_id not in self._cna_cache:
            if self._cveorg_budget <= 0 or not self.s.source_enabled("cveorg"):
                return None
            self._cveorg_budget -= 1
            self._cna_cache[cve_id] = V.fetch_cveorg(self.http, cve_id)
        return self._cna_cache[cve_id]

    def _alert_threshold(self) -> int:
        return PRIORITY_RANK.get(self.s.alert_min_priority, 2)

    def _record(self, f: dict, result: ScanResult) -> None:
        change, prev = self.store.upsert(f)
        result.counts[f["type"]] = result.counts.get(f["type"], 0) + 1
        stored = self.store.get(f["key"])
        if stored["status"] != "open":
            return
        if f["type"] in ("news", "advisory") and not self.s.alert_on_news:
            return
        if PRIORITY_RANK[f["priority"]] > self._alert_threshold():
            return
        notified = stored.get("notified_priority")
        if notified and PRIORITY_RANK[notified] <= PRIORITY_RANK[f["priority"]]:
            return  # already told you at this level or higher
        result.alerts = [a for a in result.alerts if a.finding["key"] != f["key"]]
        result.alerts.append(Alert(stored, "new" if not notified and change == "new" else "escalated",
                                   notified or (prev or {}).get("priority")))

    # ----------------------------------------------------------------- main
    def run(self, full: bool = False, only: list[str] | None = None) -> ScanResult:
        result = ScanResult()
        now = datetime.now(timezone.utc)
        result.first_run = self.store.get_state("last_run") is None

        kev: dict[str, dict] = {}
        if self.s.source_enabled("kev"):
            try:
                kev = V.fetch_kev(self.http)
                log.info("CISA KEV: %d entries", len(kev))
            except Exception as e:  # noqa: BLE001
                result.errors.append(f"CISA KEV: {e}")

        edb: list[dict] = []
        if self.s.source_enabled("exploitdb"):
            edb = F.exploitdb(self.http)
            log.info("Exploit-DB: %d recent entries", len(edb))

        global_items: list[dict] = []
        for url in self.s.global_feeds:
            for it in F.fetch_feed(self.http, url):
                it["feed"] = url
                global_items.append(it)

        assets = [a for a in self.cfg.assets if not only or a.id in only or a.name in only]

        # Ransomware leak sites: latest victims every run; whole months for a new vendor's
        # baseline, and once a day to fill any gap left by missed runs.
        self._ransom: list[dict] = []
        self._ransom_complete = True
        if self.s.source_enabled("ransomware"):
            self._ransom = I.ransomware_recent(self.http)
            last_month_pull = _parse_ts(self.store.get_state("rw_months"))
            if any(not self.store.get_state(f"rw_baseline:{a.id}") for a in assets):
                months = I.months_back(now, self.s.ransomware_lookback_days)
            elif not last_month_pull or now - last_month_pull > timedelta(hours=20):
                months = I.months_back(now, 7)
            else:
                months = []
            if months:
                more, self._ransom_complete = I.ransomware_months(self.http, months)
                self._ransom += more
                if self._ransom_complete:
                    self.store.set_state("rw_months", now.isoformat())
            log.info("ransomware.live: %d leak-site victims to check", len(self._ransom))
        self._sec = I.Sec(self.http, self.s.sec_user_agent)

        for asset in assets:
            log.info("== %s", asset.name)
            try:
                self._scan_asset(asset, now, full, kev, edb, global_items, result)
                self._scan_incidents(asset, now, result)
                self.store.set_state(f"last:{asset.id}", now.isoformat())
                self.store.set_state(f"versions:{asset.id}", json.dumps(sorted(asset.versions)))
            except Exception as e:  # noqa: BLE001
                log.exception("scan of %s failed", asset.name)
                result.errors.append(f"{asset.name}: {e}")
            score = asset_score(self.store.findings(asset.id))
            result.scores[asset.id] = score
            self.store.record_score(asset.id, score[0], score[1])

        self.store.set_state("last_run", now.isoformat())
        # alerts hold a snapshot; refresh so grouped coverage added later in the run is included
        for a in result.alerts:
            a.finding = self.store.get(a.finding["key"]) or a.finding
        result.alerts.sort(key=lambda a: (PRIORITY_RANK[a.finding["priority"]], a.finding["asset_id"]))
        return result

    def _scan_asset(self, asset: Asset, now, full, kev, edb, global_items, result: ScanResult) -> None:
        last = _parse_ts(self.store.get_state(f"last:{asset.id}"))
        since = (last - timedelta(days=1)) if last else now - timedelta(days=self.s.lookback_days)
        news_days = min(30, max(1, (now - since).days + 1)) if last else self.s.news_days

        # if you changed the versions you run, re-evaluate CVEs we already know about
        prev_versions = self.store.get_state(f"versions:{asset.id}")
        if prev_versions is not None and json.loads(prev_versions) != sorted(asset.versions):
            log.info("versions changed for %s - re-assessing stored CVEs", asset.name)
            self._reassess_stored(asset, result)

        nvd_cves: dict[str, dict] = {}
        wanted: set[str] = set()       # CVE ids referenced by other sources
        exploit_cves: set[str] = set()
        news_cves: dict[str, list[dict]] = {}

        # 1. NVD: CVEs for this exact product
        if asset.cpe_prefix and self.s.source_enabled("nvd"):
            try:
                for c in self.nvd.for_cpe(asset.cpe_prefix, None if full else since):
                    nvd_cves[c["id"]] = c
                    self._nvd_cache[c["id"]] = c
                log.info("  NVD: %d CVEs %s", len(nvd_cves), "(full history)" if full else f"modified since {since:%Y-%m-%d}")
            except Exception as e:  # noqa: BLE001
                result.errors.append(f"NVD {asset.name}: {e}")

        # 2. CISA KEV entries for this vendor/product
        asset_kev = {k["cveID"].upper(): k for k in V.kev_for_asset(kev, asset)}
        for cid, k in asset_kev.items():
            added = _parse_ts(k.get("dateAdded"))
            if cid not in nvd_cves and (not self.store.has(f"cve:{asset.id}:{cid}") or (added and added >= since)):
                wanted.add(cid)

        # 3. Exploit-DB
        for it in edb:
            text = f"{it['title']} {it['summary']}"
            if not F.matches_terms(text, asset.search_terms):
                continue
            if asset.exclude_keywords and F.matches_terms(text, asset.exclude_keywords):
                continue
            cves = F.extract_cves(text)
            exploit_cves.update(cves)
            wanted.update(cves)
            self._record({
                "key": f"exploit:{asset.id}:{_h(it['url'] or it['title'])}",
                "asset_id": asset.id, "type": "exploit", "priority": "P2",
                "title": it["title"], "url": it["url"], "published": it["published"],
                "data": {"source": "Exploit-DB", "summary": it["summary"], "cves": cves, "category": "exploit"},
            }, result)

        # 4. News (Google News) + vendor / global feeds
        items: list[tuple[str, dict]] = []
        if self.s.source_enabled("google_news"):
            for it in F.google_news(self.http, asset.search_terms, news_days):
                headline = it["title"].rsplit(" - ", 1)[0] if it.get("source") else it["title"]
                if self.s.news_title_match and not F.matches_terms(headline, asset.search_terms):
                    continue  # Google matched the article body only - usually noise
                items.append(("news", it))
        for url in asset.feeds:
            for it in F.fetch_feed(self.http, url):
                if asset.feed_filter and not F.matches_terms(f"{it['title']} {it['summary']}", asset.search_terms):
                    continue
                it["feed"] = url
                items.append(("advisory", it))
        for it in global_items:
            if F.matches_terms(f"{it['title']} {it['summary']}", asset.search_terms):
                items.append(("news", it))

        cutoff = since if last else now - timedelta(days=max(self.s.news_days, 1))
        news_records = []
        for kind, it in items:
            pub = _parse_ts(it.get("published"))
            if pub and pub < cutoff and not full:
                continue
            text = f"{it['title']} {it['summary']}"
            if asset.exclude_keywords and F.matches_terms(text, asset.exclude_keywords):
                continue
            cves = F.extract_cves(text)
            cat = F.categorize(text)
            if cat == "exploit":
                exploit_cves.update(cves)
            for c in cves:
                news_cves.setdefault(c, []).append({"title": it["title"], "url": it["url"]})
            wanted.update(cves)
            news_records.append((kind, it, cves, cat))

        # 5. Resolve every referenced CVE we don't have yet
        for cid in sorted(wanted - set(nvd_cves)):
            if self.store.has(f"cve:{asset.id}:{cid}") and cid not in asset_kev and cid not in exploit_cves:
                continue  # known already and nothing new about it
            c = self._nvd_by_id(cid) if self.s.source_enabled("nvd") else None
            nvd_cves[cid] = c  # may be None -> CVE.org fallback below

        # 6. EPSS for everything
        epss = V.fetch_epss(self.http, list(nvd_cves)) if (nvd_cves and self.s.source_enabled("epss")) else {}

        # 7. Build CVE findings
        hot_cves: set[str] = set()
        for cid, cve in nvd_cves.items():
            cna = None
            if cve is None or not cve.get("configurations"):
                cna = self._cna(cid)
            if cve is None and cna is None:
                continue
            impact = assess(cve, cna, asset.vendor, asset.product, asset.part, asset.versions, asset.keywords)
            summ = V.nvd_summary(cve) if cve else V.cveorg_summary(cna)
            k = kev.get(cid)
            ep = epss.get(cid, {})
            pocs: list[dict] = []
            exploit_public = cid in exploit_cves or bool(summ["exploit_refs"])
            if (self._github_budget > 0 and self.s.source_enabled("github_poc") and impact.affected is not False
                    and (summ["cvss"] or 0) >= 7):
                prev = self.store.get(f"cve:{asset.id}:{cid}")
                prev_pocs = (prev or {}).get("data", {}).get("github_pocs")
                if prev_pocs:
                    pocs = prev_pocs
                else:
                    self._github_budget -= 1
                    pocs = V.github_pocs(self.http, cid, self.s.github_token)
                exploit_public = exploit_public or bool(pocs)

            prio, reasons = cve_priority(
                affected=impact.affected, impact_source=impact.source, cvss=summ["cvss"],
                epss=ep.get("epss", 0.0), kev=bool(k), exploit_public=exploit_public,
                kev_vendor_match=cid in asset_kev, criticality=asset.criticality,
            )
            if prio == "P1":
                hot_cves.add(cid)
            fix = f" - fixed in {', '.join(impact.fixed_versions)}" if impact.fixed_versions else ""
            sev = f"{summ['severity']} {summ['cvss']}" if summ["cvss"] is not None else "unscored"
            self._record({
                "key": f"cve:{asset.id}:{cid}",
                "asset_id": asset.id, "type": "cve", "priority": prio,
                "title": f"{cid} ({sev}){fix}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                "published": summ["published"],
                "data": {
                    **summ,
                    "impact": impact.to_dict(),
                    "kev": {"dateAdded": k.get("dateAdded"), "dueDate": k.get("dueDate"),
                            "requiredAction": k.get("requiredAction"),
                            "ransomware": k.get("knownRansomwareCampaignUse"),
                            "name": k.get("vulnerabilityName")} if k else None,
                    "epss": ep.get("epss"), "epss_percentile": ep.get("percentile"),
                    "exploit_public": exploit_public,
                    "github_pocs": pocs,
                    "news": news_cves.get(cid, [])[:5],
                    "reasons": reasons,
                    "priority_label": PRIORITY_LABEL[prio],
                },
            }, result)

        # 8. News / advisory findings (after CVEs so we can link "hot" CVEs)
        for kind, it, cves, cat in news_records:
            linked_hot = any(c in hot_cves or self._stored_priority(asset, c) == "P1" for c in cves)
            prio = news_priority(cat, linked_hot)
            if kind == "advisory" and prio == "P3" and "critical" in it["title"].lower():
                prio = "P2"
            if self._merge_into_story(asset, kind, it, cves, cat, prio, result):
                continue
            self._record({
                "key": f"{kind}:{asset.id}:{_h(it['url'] or it['title'])}",
                "asset_id": asset.id, "type": kind, "priority": prio,
                "title": it["title"], "url": it["url"], "published": it.get("published", ""),
                "data": {"source": it.get("source") or it.get("feed", "Google News"), "summary": it["summary"],
                         "cves": cves, "category": cat},
            }, result)

    # ----------------------------------------------------------------- duplicate stories
    def _merge_into_story(self, asset: Asset, kind: str, it: dict, cves: list[str], cat: str, prio: str,
                          result: ScanResult) -> bool:
        """Attach this item to an existing finding about the same story. Returns True if merged."""
        key = f"{kind}:{asset.id}:{_h(it['url'] or it['title'])}"
        if self.store.has(key):
            return False  # it's the story's own lead item - normal update path
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.s.cluster_days)
        mine = tokens(it["title"], asset.search_terms + [asset.name])
        for f in self.store.findings(asset.id, types=["news", "advisory"]):
            seen = _parse_ts(f.get("published")) or _parse_ts(f.get("first_seen"))
            if seen and seen < cutoff:
                continue
            d = f["data"]
            coverage = d.get("coverage") or []
            if it["url"] and (it["url"] == f.get("url") or any(c.get("url") == it["url"] for c in coverage)):
                return True  # already have this exact article
            members = [(f["title"], d.get("cves") or [])] + [(c.get("title", ""), c.get("cves") or []) for c in coverage]
            if not any(same_story(mine, tokens(t, asset.search_terms + [asset.name]), cves, mc) for t, mc in members):
                continue
            coverage.append({"title": it["title"], "url": it["url"], "published": it.get("published", ""),
                             "source": it.get("source") or it.get("feed", ""), "cves": cves})
            d["coverage"] = coverage[-50:]
            d["cves"] = sorted(set(d.get("cves") or []) | set(cves))
            new_prio = prio if PRIORITY_RANK[prio] < PRIORITY_RANK[f["priority"]] else f["priority"]
            if new_prio != f["priority"]:
                d["category"] = cat
            self._record({**f, "priority": new_prio, "data": d}, result)
            return True
        return False

    # ----------------------------------------------------------------- incidents
    def _scan_incidents(self, asset: Asset, now: datetime, result: ScanResult) -> None:
        last = _parse_ts(self.store.get_state(f"incidents:{asset.id}"))
        high = asset.criticality in ("high", "critical")

        # Ransomware leak sites
        if self.s.source_enabled("ransomware") and (asset.domains or asset.keywords):
            victims = [v for v in self._ransom if I.victim_matches(v, asset)]
            if self._ransom_complete:
                self.store.set_state(f"rw_baseline:{asset.id}", now.isoformat())
            window = now - timedelta(days=self.s.ransomware_lookback_days)
            for v in victims:
                rec = I.victim_record(v)
                when = _parse_ts(rec["discovered"]) or _parse_ts(rec["attackdate"])
                if when and when < window:
                    continue
                self._record({
                    "key": f"ransomware:{asset.id}:{_h((rec['group'] + '|' + rec['victim']).lower())}",
                    "asset_id": asset.id, "type": "ransomware", "priority": "P1" if high else "P2",
                    "title": f"Ransomware leak site: '{rec['victim']}' listed by {rec['group'] or 'unknown group'}",
                    "url": rec["url"], "published": rec["discovered"] or rec["attackdate"],
                    "data": {**rec, "category": "breach", "source": "ransomware.live",
                             "summary": rec["description"],
                             "reasons": ["vendor named as a victim on a ransomware group's leak site - "
                                         "ask the vendor whether your data is affected"]},
                }, result)

        # SEC 8-K cybersecurity disclosures
        if self.s.source_enabled("sec") and (asset.sec_cik or asset.sec_ticker):
            try:
                cik = asset.sec_cik
                if not cik:
                    cik = self.store.get_state(f"cik:{asset.sec_ticker}")
                    if not cik:
                        cik = self._sec.resolve_cik(asset.sec_ticker, asset.name)
                        if not cik:
                            raise LookupError(f"ticker {asset.sec_ticker} not found on EDGAR")
                        self.store.set_state(f"cik:{asset.sec_ticker}", cik)
                start = (last - timedelta(days=2)) if last else now - timedelta(days=self.s.sec_lookback_days)
                for fl in self._sec.filings_8k(cik, start):
                    kind = I.classify_8k(fl["items"])
                    if not kind:
                        continue
                    if kind == "voluntary":
                        # Item 8.01 is "other events" - only keep it if the filing is about a cyber incident
                        if not self.store.has(f"sec:{asset.id}:{fl['adsh']}") and not self._sec.mentions_cyber(fl["url"]):
                            continue
                    material = kind == "material"
                    label = ("Item 1.05 MATERIAL cybersecurity incident" if material
                             else "Item 8.01 cybersecurity-related disclosure")
                    self._record({
                        "key": f"sec:{asset.id}:{fl['adsh']}",
                        "asset_id": asset.id, "type": "sec",
                        "priority": "P1" if (material and high) else "P2",
                        "title": f"SEC {fl['form']} {label}: {fl['company']}",
                        "url": fl["url"], "published": fl["file_date"],
                        "data": {"category": "breach", "source": "SEC EDGAR", "form": fl["form"],
                                 "items": fl["items"], "adsh": fl["adsh"], "cik": cik, "kind": kind,
                                 "reasons": ["vendor formally disclosed a material cybersecurity incident to the SEC"
                                             if material else
                                             "vendor 8-K mentions a cybersecurity incident - read it to confirm"]},
                    }, result)
            except Exception as e:  # noqa: BLE001
                result.errors.append(f"SEC {asset.name}: {e}")
        self.store.set_state(f"incidents:{asset.id}", now.isoformat())

    def _stored_priority(self, asset: Asset, cid: str) -> str | None:
        f = self.store.get(f"cve:{asset.id}:{cid}")
        return f["priority"] if f else None

    def _reassess_stored(self, asset: Asset, result: ScanResult) -> None:
        for f in self.store.findings(asset.id, types=["cve"]):
            d = f["data"]
            impact = reassess(d.get("impact", {}), asset.versions, d.get("description", ""))
            prio, reasons = cve_priority(
                affected=impact.affected, impact_source=impact.source, cvss=d.get("cvss"),
                epss=d.get("epss") or 0.0, kev=bool(d.get("kev")), exploit_public=bool(d.get("exploit_public")),
                kev_vendor_match=bool(d.get("kev")), criticality=asset.criticality,
            )
            d["impact"] = impact.to_dict()
            d["reasons"] = reasons
            d["priority_label"] = PRIORITY_LABEL[prio]
            title = f["title"].split(" - fixed in")[0]
            if impact.fixed_versions:
                title += f" - fixed in {', '.join(impact.fixed_versions)}"
            self._record({**f, "priority": prio, "title": title, "data": d}, result)


def check_cve(cfg: Config, cve_id: str, http: Http | None = None) -> list[dict]:
    """Ad-hoc: does CVE-XXXX-YYYY affect any of my assets?"""
    http = http or Http()
    cve_id = cve_id.upper()
    nvd = V.Nvd(http, cfg.settings.nvd_api_key)
    cve = nvd.by_id(cve_id)
    cna = V.fetch_cveorg(http, cve_id) if (cve is None or not cve.get("configurations")) else None
    if cve is None and cna is None:
        raise LookupError(f"{cve_id} not found in NVD or CVE.org")
    summ = V.nvd_summary(cve) if cve else V.cveorg_summary(cna)
    kev = V.fetch_kev(http).get(cve_id)
    ep = V.fetch_epss(http, [cve_id]).get(cve_id, {})
    out = []
    for a in cfg.assets:
        if not a.vendor:
            continue
        imp = assess(cve, cna, a.vendor, a.product, a.part, a.versions, a.keywords)
        if imp.source in ("none", "nvd-other-product", "cna-other-product") and imp.affected is not True:
            continue
        prio, reasons = cve_priority(affected=imp.affected, impact_source=imp.source, cvss=summ["cvss"],
                                     epss=ep.get("epss", 0.0), kev=bool(kev), exploit_public=bool(summ["exploit_refs"]),
                                     kev_vendor_match=bool(kev), criticality=a.criticality)
        out.append({"asset": a.name, "priority": prio, "impact": imp.to_dict(), "reasons": reasons})
    return [{"summary": summ, "kev": kev, "epss": ep, "assets": out}]

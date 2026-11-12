# vendorwatch: continuous third-party & technology risk monitoring

`vendorwatch` is a self-hosted, free tool in the spirit TPRM products. You give it the vendors and technologies you depend on and **the versions you run**. It watches vulnerability databases, exploit sources and the news, and tells you when something **affects you**, how urgent it is, and **which version fixes it**.

Example: you watch FortiGate on FortiOS 7.4.2. A new FortiOS CVE lands, CISA adds it to KEV, and a PoC appears on GitHub. You get:

```
### FortiGate firewalls  [risk grade D / 65]
🔴 [P1 Act now] (NEW) CVE-2024-21762 (CRITICAL 9.8) - fixed in 7.4.3
    Your affected versions: 7.4.2
    Upgrade to: 7.4.3 or later
    CISA KEV since 2024-02-09 (federal due date 2024-02-16)
    EPSS: 84.6% (percentile 100%)
    Public PoC: https://github.com/...
    Why: affects a version you run; CISA KEV: actively exploited; public exploit / PoC available
    Advisory/patch: https://fortiguard.com/psirt/FG-IR-24-015
```

Alerts go to the console, Slack, Teams, email or any webhook. A self-contained HTML dashboard gives an A–F grade for each vendor.

## What it monitors

| Source | What it tells you | Key needed? |
|---|---|---|
| **NVD** (CVE API 2.0) | New/updated CVEs for each product's CPE, CVSS, vulnerable version ranges, patch & exploit references | No (free key is ~10× faster) |
| **CVE.org** (CNA records) | Vendor-supplied affected versions, often **days before NVD** has analysed a CVE | No |
| **CISA KEV** | Confirmed exploitation in the wild, ransomware use, federal due dates | No |
| **FIRST EPSS** | Probability a CVE gets exploited in the next 30 days | No |
| **Exploit-DB** | Newly published public exploits matching your keywords | No |
| **GitHub** | PoC repos for CVEs that affect you | `GITHUB_TOKEN` |
| **Ransomware leak sites** (via ransomware.live) | Vendor named as a victim by a ransomware group, often days or weeks before any news | No |
| **SEC EDGAR 8-Ks** | Item 1.05 material cybersecurity incident disclosures (and cyber-related 8.01s) from public vendors | No |
| **Claude** (threat briefs) | Researches each alert and assesses the threat to your organisation | `ANTHROPIC_API_KEY` |
| **Google News** | Exploitation, zero-day, breach, ransomware and outage coverage for each vendor | No |
| **Vendor PSIRT feeds** | e.g. Fortinet and Palo Alto advisory RSS | No |
| **Security news RSS** | BleepingComputer, The Hacker News, SecurityWeek… (any RSS/Atom) | No |

## How it decides "does this impact me?"

For every CVE it checks your versions against the vulnerable ranges, using the best data available:

1. **NVD CPE configuration** (`versionStartIncluding` / `versionEndExcluding`, exact CPEs). It works out the **fixed version in your branch**, e.g. you run 7.2.8 → "fixed in 7.2.11".
2. If NVD hasn't analysed the CVE yet (common with the NVD backlog), it uses the **CNA's own CVE.org record**.
3. As a last resort it reads the **description** ("FortiOS 7.4.0 through 7.4.2", "before 22.7R2.5"). This can only say "affected" or "unknown", never "not affected".

Version comparison handles `7.4.3`, `7.4.3a`, `22.7R2.3`, `1.0rc1` and similar formats.

### Priorities

| | Meaning | Rule of thumb |
|---|---|---|
| 🔴 **P1** Act now | Affects your version **and** is exploited (KEV), has a public exploit/PoC, or EPSS ≥ 30% | Also: news about a P1 CVE |
| 🟠 **P2** Patch / investigate soon | Affects your version with CVSS ≥ 7, or impact unknown but exploited; exploit/breach news | |
| 🟡 **P3** Track | Lower-severity CVEs that affect you; vulnerability/patch news | |
| ⚪ **P4** Info | Not affected (e.g. you're already patched), unrelated product | Stored, never alerted |

You get alerted once per finding. You're alerted again only if it **escalates** (for example a P2 becomes P1 when CISA adds it to KEV). Each scan sends **one digest** per channel.

### Vendor risk grade (A–F)

Each asset starts at 100. Open findings take points off: an exploited CVE in your versions −25, an unpatched high −10, a lower −3, a CVE with unverified impact −1 to −4, recent breach news −8 and exploit news −4 (news is capped at −30). A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F. Every scan records the score, so the dashboard shows the trend.

### Incident monitoring for SaaS vendors

For vendors you don't run software from, the strongest signals are:

- **Ransomware leak sites**: the tool downloads every leak-site listing tracked by ransomware.live (about 1,000 a month). It matches each vendor by its `domains:` or exact company name, never by description text, so a victim that merely *uses* Salesforce isn't flagged as Salesforce. Each listing is P1 for high/critical vendors, otherwise P2, and costs 30 points of grade for 180 days.
- **SEC 8-K filings**: public companies must file Item 1.05 within four business days of deciding a cyber incident is material. Set `sec_cik:` (or `sec_ticker:`); for subsidiaries use the parent company (NetSuite → Oracle, AWS → Amazon). Item 1.05 is P1 for high/critical vendors, otherwise P2. Item 8.01 "other events" filings are only kept if the document itself discusses a cyber incident.
- **Duplicate stories are grouped**: when ten outlets report the same breach you get one finding and one alert, listing the other sources ("Also reported by 9 more sources"). Headlines are compared after dropping the vendor's name and generic words like "breach"; articles citing the same CVE are also grouped. `cluster_days` (default 14) sets the window.

```yaml
  - name: Salesforce
    keywords: [Salesforce]
    domains: [salesforce.com]   # leak-site matching
    sec_cik: "1108524"          # SEC 8-K monitoring (find it on sec.gov/edgar/search)
```

### Threat briefs (Claude)

Every alert can get a dedicated brief that evaluates **what the event means for your organisation**, not just what happened. Claude Opus 5.5 does it in two steps:

1. **Research:** Claude reads the sources with web search and web fetch, separating confirmed facts from claims.
2. **Brief:** Claude writes a structured brief using your `organization:` profile and the vendor's `usage:` (what you use it for and what data it holds; Drata fills this in).

Each brief contains: headline, **threat level to you** (critical → informational) with confidence, bottom line, what happened, relevance to you, potential impact, recommended actions (with urgency and owner), questions to send the vendor, open questions, regulatory considerations and sources. Briefs appear in the alert digest (threat level, bottom line, top three actions), in the dashboard, and as Markdown files under `briefs/<vendor>/`.

```yaml
organization:
  name: SIAA
  description: What you do and what data you hold.
  data_handled: [client PII, ...]
  regulations: [GLBA Safeguards Rule, ...]
briefs:
  enabled: true          # needs ANTHROPIC_API_KEY
  max_per_run: 10        # cost cap
```

- **Cost:** about $0.20–0.40 per brief. Briefs are cached and only rewritten when a finding escalates. Findings over `max_per_run` are briefed on later runs.
- **On demand:** `vendorwatch brief CVE-2024-21762`, `vendorwatch brief --all-open --min P2`, add `--force` to rewrite.
- **Without a vendor's `usage`,** the brief says your exposure is unknown and lists finding it out as an open question; it never guesses.
- **Public dashboards:** briefs describe your exposure. If the dashboard goes to a public Pages site, set `briefs.in_dashboard: false`; briefs then go only to alert channels and the private run artifacts.
- Briefs are AI-generated; verify before acting.

### Drata vendor inventory sync

If your vendors live in Drata, let Drata drive the watchlist:

```yaml
drata:
  enabled: true
  api_key: ${DRATA_API_KEY}
  region: us        # us | eu | apac
  statuses: [ACTIVE, APPROVED, UNDER_REVIEW, FLAGGED, ON_HOLD]
```

On every scan, vendorwatch pulls the vendor list from Drata's Public API (`GET /public/v2/vendors`):

- **New vendors** are monitored automatically. Their name becomes the news keyword and their website the domain used for leak-site matching.
- **Offboarded / archived vendors** (any status not in `statuses`) stop being monitored.
- **Criticality** follows Drata: the critical flag or a CRITICAL impact level makes a vendor critical, HIGH risk makes it high, MODERATE makes it medium, and vendors holding PII are never below medium. Set `criticality_source: yaml` to keep your own ratings.
- **Your YAML entries still matter.** A YAML asset that matches a Drata vendor (by domain, name or keyword, so "Salesforce, Inc" matches `Salesforce`) keeps its tuned keywords, `exclude_keywords` and `sec_cik`. YAML assets not in Drata, such as firewalls you track by version, are kept.
- If Drata is unreachable, the last synced inventory (cached next to the database) is used.

Preview the mapping before relying on it:

```bash
export DRATA_API_KEY=...        # Drata > Settings > API Keys, permission "Vendors: List Vendors"
python -m vendorwatch drata
```

The vendor API needs a Drata plan with the TPRM feature. Without it, Drata answers 402 and vendorwatch falls back to the YAML.

## Quick start

```bash
pip install -r requirements.txt          # or: pip install -e .
python -m vendorwatch init               # creates watchlist.yaml
# edit watchlist.yaml: your vendors, CPE names, the versions you run
python -m vendorwatch scan               # first run = baseline, prints everything relevant
open report.html                         # dashboard
```

Find CPE vendor/product names at <https://nvd.nist.gov/products/cpe/search>. For example `cpe:2.3:o:fortinet:fortios` becomes `part: o, vendor: fortinet, product: fortios`.

```yaml
assets:
  - name: FortiGate firewalls
    vendor: fortinet
    product: fortios
    part: o
    versions: ["7.2.8", "7.4.3"]
    criticality: critical
    keywords: [FortiOS, FortiGate]
    feeds: [https://filestore.fortinet.com/fortiguard/rss/ir.xml]

  - name: Snowflake            # SaaS / supplier: breach & incident news only
    keywords: [Snowflake]
    criticality: high
```

See [`watchlist.example.yaml`](watchlist.example.yaml) for every option (alert threshold, sources on/off, global feeds, notification channels).

## Commands

```bash
vendorwatch scan                        # one pass; alerts on new/escalated findings
vendorwatch scan --full                 # pull the full NVD history for each product (good baseline)
vendorwatch watch --every 4h            # run forever (reloads watchlist each cycle)
vendorwatch findings --min P2           # what's open now (-v shows keys & links)
vendorwatch check CVE-2024-21762        # does this CVE hit anything I run?
vendorwatch ack CVE-2024-21762 --resolved   # patched (or: no flag = risk accepted, --reopen)
vendorwatch report                      # regenerate report.html
```

**After you upgrade**, just change `versions:` in the watchlist. On the next scan every stored CVE is re-assessed: fixed ones drop to P4 and the grade recovers.

## Running it continuously

Pick one:

- **GitHub Actions (no server):** `.github/workflows/vendorwatch.yml` runs every 4 hours. It keeps the findings DB in the Actions cache, sends alerts using repo secrets (`SLACK_WEBHOOK_URL`, `SMTP_*`, `NVD_API_KEY`, …) and uploads `report.html` as an artifact. Commit your `watchlist.yaml`; it contains no secrets.
- **GitHub Pages dashboard:** the same workflow can publish `report.html` as a web page after every scan. In the repo, go to **Settings → Pages → Source: "GitHub Actions"**. Then add the repository **variable** `PUBLISH_PAGES` = `true` (Settings → Secrets and variables → Actions → Variables). The site URL appears in the workflow run summary. ⚠️ Unless you're on GitHub Enterprise Cloud with private Pages, **the site is public even if the repo is private**. It shows your products, versions and unpatched CVEs. The page asks search engines not to index it, but that doesn't stop anyone who has the link.
- **cron:** `17 */4 * * * cd /opt/vendorwatch && python -m vendorwatch scan -q >> scan.log 2>&1`
- **Long-running:** `python -m vendorwatch watch --every 4h` (systemd, tmux, a container…).

### Notification setup

All secrets come from environment variables referenced in the YAML (`${SLACK_WEBHOOK_URL}`). Leave a variable unset to disable that channel.

- **Slack:** create an Incoming Webhook → `SLACK_WEBHOOK_URL`
- **Teams:** channel → Workflows "Post to a channel when a webhook request is received" → `TEAMS_WEBHOOK_URL`
- **Email:** `SMTP_HOST`, `SMTP_PORT` (587 STARTTLS / 465 SSL), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `ALERT_EMAIL_TO`
- **Webhook:** `VENDORWATCH_WEBHOOK_URL` receives `{"alerts": [...]}` JSON for SOAR, Jira automation, PagerDuty and similar tools

## Tips

- **Set `SEC_USER_AGENT`** to something like `"Acme Corp security@acme.com"`. SEC asks automated clients to identify themselves and may block anonymous ones.
- The first scan downloads a year of leak-site data and takes a few minutes. Later scans take seconds.
- **Get an NVD API key** (free, instant). Without one, NVD allows 5 requests every 30 seconds, so a first scan of many products takes minutes. Later scans are incremental and take seconds.
- Use precise `keywords` (product names, not just the vendor) to keep news noise down.
- `alert_min_priority: P1` gives "only wake me for exploited things that affect me".
- The first scan is treated as a baseline. Its results print to the console but aren't pushed to channels unless you pass `--notify-baseline`. The GitHub workflow does pass it.

## Development

```bash
pip install -e '.[dev]'
pytest
```

Layout: `vendorwatch/sources/` (fetchers), `versions.py` (impact & fixed-version logic), `scanner.py` (correlation), `scoring.py` (priorities & grades), `store.py` (SQLite), `notify.py`, `report.py`, `cli.py`.

Ideas for next steps: an LLM-written weekly executive summary per vendor; asset import from your CMDB or scanner (Tenable/Qualys/Intune); external attack-surface checks (exposed services, TLS and email security for vendor domains); ticket creation for P1/P2.

> Google News RSS is offered for personal, non-commercial feed-reader use. Check its terms before using vendorwatch commercially, or switch `google_news` off and rely on the RSS feeds.

"""Command line interface.

    vendorwatch init                     # create watchlist.yaml from the example
    vendorwatch scan                     # one pass over every source, alert on what's new
    vendorwatch watch --every 4h         # keep scanning forever
    vendorwatch findings --min P2        # what's open right now
    vendorwatch check CVE-2024-21762     # does this CVE hit anything I run?
    vendorwatch ack <key|CVE> --resolved # we patched it / accepted the risk
    vendorwatch report                   # write the HTML dashboard
"""
from __future__ import annotations

import argparse
import logging
import re
import shutil
import sys
import time
from pathlib import Path

from . import __version__, drata, notify, report
from .config import load_config
from .scanner import Scanner, check_cve
from .scoring import PRIORITY_LABEL
from .store import PRIORITY_RANK, Store

EXAMPLE = Path(__file__).resolve().parent.parent / "watchlist.example.yaml"


def _interval(s: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd]?)", s.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError("use e.g. 30m, 6h, 1d")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _load(args, live_drata: bool = False):
    """Load the watchlist and apply the Drata vendor inventory if enabled.

    Scans pull Drata live; other commands use the copy cached by the last scan."""
    cfg = load_config(args.config)
    cfg, _, note = drata.apply(cfg, live=live_drata)
    if note and (live_drata or "fail" in note or "no " in note):
        print(note, file=sys.stderr)
    return cfg, Store(cfg.settings.db_path)


def cmd_init(args) -> int:
    dest = Path(args.config)
    if dest.exists() and not args.force:
        print(f"{dest} already exists (use --force to overwrite)")
        return 1
    shutil.copy(EXAMPLE, dest)
    print(f"Wrote {dest}. Edit it to list your vendors/technologies and the versions you run, then: vendorwatch scan")
    return 0


def _scan_once(args, cfg, store) -> int:
    scanner = Scanner(cfg, store)
    res = scanner.run(full=args.full, only=args.asset)
    names = {a.id: a.name for a in cfg.assets}
    summary = ", ".join(f"{v} {k}" for k, v in sorted(res.counts.items())) or "nothing"
    print(f"Scanned {len(res.scores)} asset(s): {summary} processed.")
    for aid, (score, grade, drivers) in res.scores.items():
        print(f"  {grade}  {score:>3}/100  {names.get(aid, aid)}" + (f"  - {drivers[0]}" if drivers else ""))
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)

    alerts = res.alerts
    if res.first_run and not args.notify_baseline:
        print(f"\nFirst run: baseline of {len(alerts)} alert-worthy finding(s) recorded."
              " Showing them here; channels get only what's new from now on (use --notify-baseline to send).")
        notify.send(alerts, {}, names, res.scores, console=not args.quiet)
    elif args.no_notify:
        notify.send(alerts, {}, names, res.scores, console=not args.quiet)
    else:
        if not alerts:
            print("\nNo new alerts.")
        notify.send(alerts, cfg.notify, names, res.scores, console=not args.quiet)
    for a in alerts:
        store.mark_notified(a.finding["key"], a.finding["priority"])

    out = Path(cfg.settings.report_path)
    out.write_text(report.build(cfg, store))
    print(f"Dashboard: {out.resolve()}")
    return 2 if any(a.finding["priority"] == "P1" for a in alerts) and args.fail_on_p1 else 0


def cmd_scan(args) -> int:
    cfg, store = _load(args, live_drata=True)
    return _scan_once(args, cfg, store)


def cmd_watch(args) -> int:
    while True:
        cfg, store = _load(args, live_drata=True)  # reload so watchlist / Drata changes take effect
        try:
            _scan_once(args, cfg, store)
        except Exception as e:  # noqa: BLE001
            logging.getLogger("vendorwatch").exception("scan failed: %s", e)
        args.full = False
        print(f"Next scan in {args.every // 60} min. Ctrl-C to stop.\n")
        time.sleep(args.every)


def cmd_findings(args) -> int:
    cfg, store = _load(args)
    names = {a.id: a.name for a in cfg.assets}
    aid = None
    if args.asset:
        a = cfg.asset(args.asset[0]) or next((x for x in cfg.assets if x.name == args.asset[0]), None)
        aid = a.id if a else args.asset[0]
    rows = store.findings(aid, types=[args.type] if args.type else None, status=None if args.all else "open")
    rows = [r for r in rows if PRIORITY_RANK[r["priority"]] <= PRIORITY_RANK[args.min.upper()]]
    for r in rows:
        imp = r["data"].get("impact", {})
        extra = ""
        if imp.get("affected") is True:
            extra = f"  <- you run {', '.join(imp.get('affected_versions', []))}"
        print(f"{r['priority']}  {names.get(r['asset_id'], r['asset_id'])[:24]:<24}  {r['type']:<8} {r['title'][:90]}{extra}")
        if args.verbose:
            print(f"      key={r['key']}  {r['url']}")
    print(f"\n{len(rows)} finding(s)")
    return 0


def cmd_check(args) -> int:
    cfg, _ = _load(args)
    try:
        res = check_cve(cfg, args.cve)[0]
    except LookupError as e:
        print(e)
        return 1
    s = res["summary"]
    print(f"{s['id']}  CVSS {s['cvss']} {s['severity']}  published {s['published'][:10]}  [{s['status']}]")
    print(f"  {s['description'][:400]}")
    if res["kev"]:
        print(f"  CISA KEV: added {res['kev']['dateAdded']} - {res['kev']['requiredAction']}")
    if res["epss"]:
        print(f"  EPSS: {res['epss']['epss']:.1%}")
    if not res["assets"]:
        print("\n  None of your watched assets appear in this CVE.")
    for a in res["assets"]:
        imp = a["impact"]
        state = {True: "AFFECTED", False: "not affected", None: "UNKNOWN (verify)"}[imp["affected"]]
        print(f"\n  {a['asset']}: {state}  -> {a['priority']} {PRIORITY_LABEL[a['priority']]}")
        if imp["affected_versions"]:
            print(f"    your affected versions: {', '.join(imp['affected_versions'])}")
        if imp["fixed_versions"]:
            print(f"    fixed in: {', '.join(imp['fixed_versions'])}")
        print(f"    vulnerable ranges ({imp['source']}): {'; '.join(imp['ranges'][:8])}")
    return 0


def cmd_ack(args) -> int:
    _, store = _load(args)
    status = "resolved" if args.resolved else "accepted" if not args.reopen else "open"
    ok = store.set_status(args.key, status)
    print(f"{args.key}: {status}" if ok else f"no finding matching {args.key}")
    return 0 if ok else 1


def cmd_drata(args) -> int:
    cfg = load_config(args.config)
    if not cfg.drata.get("enabled"):
        print("Drata sync is off. Add a `drata:` section with `enabled: true` to the watchlist (see README).")
        return 1
    merged, rows, note = drata.apply(cfg, live=not args.cached)
    print(note)
    if not rows:
        return 1
    width = max(len(r["drata"]) for r in rows)
    for r in sorted(rows, key=lambda r: r["drata"].lower()):
        print(f"  {r['drata']:<{width}}  {r['status']:<12} risk={str(r['risk']):<8} {r['action']}")
    kept = [a for a in merged.assets if not any(r["yaml"] == a.name or drata.clean_name(r["drata"]) == a.name
                                                  for r in rows)]
    if kept:
        print("\nAlso monitored from the YAML only (not in Drata): " + ", ".join(a.name for a in kept))
    print(f"\n{len(merged.assets)} asset(s) will be monitored.")
    return 0


def cmd_report(args) -> int:
    cfg, store = _load(args)
    out = Path(args.out or cfg.settings.report_path)
    out.write_text(report.build(cfg, store))
    print(f"Wrote {out.resolve()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vendorwatch", description="Continuous third-party & technology risk monitoring")
    p.add_argument("-c", "--config", default="watchlist.yaml")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create a watchlist from the example")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    for name, fn, hlp in (("scan", cmd_scan, "run one scan"), ("watch", cmd_watch, "scan continuously")):
        s = sub.add_parser(name, help=hlp)
        s.add_argument("--full", action="store_true", help="pull full NVD history for each product (slow, good for a baseline)")
        s.add_argument("--asset", action="append", help="only scan this asset (repeatable)")
        s.add_argument("--no-notify", action="store_true", help="print alerts but don't send to channels")
        s.add_argument("--notify-baseline", action="store_true", help="send alerts to channels on the very first run too")
        s.add_argument("--fail-on-p1", action="store_true", help="exit 2 if there are new P1 alerts (CI use)")
        s.add_argument("-q", "--quiet", action="store_true")
        if name == "watch":
            s.add_argument("--every", type=_interval, default="6h", help="interval, e.g. 30m, 4h, 1d (default 6h)")
        s.set_defaults(fn=fn)

    s = sub.add_parser("findings", help="list stored findings")
    s.add_argument("--asset", action="append")
    s.add_argument("--min", default="P3", choices=["P1", "P2", "P3", "P4", "p1", "p2", "p3", "p4"])
    s.add_argument("--type", choices=["cve", "exploit", "news", "advisory", "ransomware", "sec"])
    s.add_argument("--all", action="store_true", help="include accepted/resolved")
    s.set_defaults(fn=cmd_findings)

    s = sub.add_parser("check", help="check one CVE against your watchlist")
    s.add_argument("cve")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("ack", help="mark a finding accepted / resolved (stops alerts and score impact)")
    s.add_argument("key", help="finding key, or just the CVE id")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--resolved", action="store_true")
    g.add_argument("--reopen", action="store_true")
    s.set_defaults(fn=cmd_ack)

    s = sub.add_parser("drata", help="preview how your Drata vendor inventory maps onto the watchlist")
    s.add_argument("--cached", action="store_true", help="use the inventory cached by the last scan")
    s.set_defaults(fn=cmd_drata)

    s = sub.add_parser("report", help="write the HTML dashboard")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_report)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.WARNING - 10 * min(args.verbose, 2) if args.verbose else logging.WARNING
    if args.cmd in ("scan", "watch") and not args.verbose:
        level = logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    try:
        return args.fn(args) or 0
    except FileNotFoundError as e:
        print(f"{e}\nRun `vendorwatch init` to create a watchlist.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

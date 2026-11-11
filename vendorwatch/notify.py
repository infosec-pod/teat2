"""Alert delivery: console, Slack, Microsoft Teams, generic webhook, email.

Every scan sends at most ONE digest per channel, grouped by asset, so a busy
Patch Tuesday doesn't produce 40 separate pings.
"""
from __future__ import annotations

import json
import logging
import smtplib
import ssl
from email.message import EmailMessage

import requests

from .scanner import Alert
from .scoring import PRIORITY_LABEL

log = logging.getLogger("vendorwatch")

ICON = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "⚪"}


def _lines_for(alert: Alert) -> list[str]:
    f = alert.finding
    d = f["data"]
    tag = "NEW" if alert.change == "new" else f"ESCALATED from {alert.previous_priority}"
    out = [f"{ICON[f['priority']]} [{f['priority']} {PRIORITY_LABEL[f['priority']]}] ({tag}) {f['title']}"]
    if f["type"] == "cve":
        imp = d.get("impact", {})
        if imp.get("affected_versions"):
            out.append(f"    Your affected versions: {', '.join(imp['affected_versions'])}")
        if imp.get("fixed_versions"):
            out.append(f"    Upgrade to: {', '.join(imp['fixed_versions'])} or later")
        if d.get("kev"):
            k = d["kev"]
            out.append(f"    CISA KEV since {k.get('dateAdded')} (federal due date {k.get('dueDate')})"
                       + (" - used by ransomware" if k.get("ransomware") == "Known" else ""))
        if d.get("epss") is not None:
            out.append(f"    EPSS: {d['epss']:.1%} (percentile {d.get('epss_percentile', 0):.0%})")
        if d.get("github_pocs"):
            out.append(f"    Public PoC: {d['github_pocs'][0]['url']}")
        if d.get("reasons"):
            out.append(f"    Why: {'; '.join(d['reasons'])}")
        if d.get("description"):
            desc = d["description"]
            out.append(f"    {desc[:280]}{'…' if len(desc) > 280 else ''}")
        if d.get("patch_refs"):
            out.append(f"    Advisory/patch: {d['patch_refs'][0]}")
    else:
        src = d.get("source", "")
        out.append(f"    {f['type']} / {d.get('category', '')}{' via ' + src if src else ''}")
    out.append(f"    {f.get('url', '')}")
    return out


def render_text(alerts: list[Alert], asset_names: dict[str, str], scores: dict | None = None) -> str:
    by_asset: dict[str, list[Alert]] = {}
    for a in alerts:
        by_asset.setdefault(a.finding["asset_id"], []).append(a)
    lines = [f"vendorwatch: {len(alerts)} alert(s) across {len(by_asset)} vendor(s)/technolog(ies)", ""]
    for aid, items in by_asset.items():
        grade = ""
        if scores and aid in scores:
            grade = f"  [risk grade {scores[aid][1]} / {scores[aid][0]}]"
        lines.append(f"### {asset_names.get(aid, aid)}{grade}")
        for a in items:
            lines += _lines_for(a)
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _slack_blocks(alerts, asset_names, scores) -> dict:
    blocks = [{"type": "header", "text": {"type": "plain_text", "text": f"vendorwatch: {len(alerts)} new risk alert(s)"}}]
    by_asset: dict[str, list[Alert]] = {}
    for a in alerts:
        by_asset.setdefault(a.finding["asset_id"], []).append(a)
    for aid, items in by_asset.items():
        g = f" — grade *{scores[aid][1]}* ({scores[aid][0]})" if scores and aid in scores else ""
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{asset_names.get(aid, aid)}*{g}"}})
        for a in items[:15]:
            f = a.finding
            body = "\n".join(_lines_for(a)[1:-1])
            text = f"{ICON[f['priority']]} *<{f['url']}|{f['title']}>*  `{f['priority']}`\n{body}"
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}})
        if len(items) > 15:
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"…and {len(items) - 15} more"}]})
    return {"text": f"vendorwatch: {len(alerts)} new risk alert(s)", "blocks": blocks[:50]}


def send(alerts: list[Alert], notify_cfg: dict, asset_names: dict[str, str], scores: dict | None = None,
         console: bool = True) -> list[str]:
    """Deliver the digest. Returns a list of channel errors (empty if all OK)."""
    if not alerts:
        return []
    text = render_text(alerts, asset_names, scores)
    errors = []
    if console:
        print(text)

    slack = (notify_cfg.get("slack") or {}).get("webhook_url")
    if slack:
        try:
            requests.post(slack, json=_slack_blocks(alerts, asset_names, scores), timeout=20).raise_for_status()
        except Exception as e:  # noqa: BLE001
            errors.append(f"slack: {e}")

    teams = (notify_cfg.get("teams") or {}).get("webhook_url")
    if teams:
        try:
            requests.post(teams, json={"text": text.replace("\n", "  \n")}, timeout=20).raise_for_status()
        except Exception as e:  # noqa: BLE001
            errors.append(f"teams: {e}")

    hook = notify_cfg.get("webhook") or {}
    if hook.get("url"):
        payload = {"alerts": [{"change": a.change, "previous_priority": a.previous_priority, **a.finding} for a in alerts]}
        try:
            requests.post(hook["url"], data=json.dumps(payload, default=str),
                          headers={"Content-Type": "application/json", **(hook.get("headers") or {})},
                          timeout=20).raise_for_status()
        except Exception as e:  # noqa: BLE001
            errors.append(f"webhook: {e}")

    mail = notify_cfg.get("email") or {}
    if mail.get("smtp_host") and mail.get("to"):
        try:
            msg = EmailMessage()
            p1 = sum(1 for a in alerts if a.finding["priority"] == "P1")
            msg["Subject"] = f"[vendorwatch] {len(alerts)} alert(s){f', {p1} ACT NOW' if p1 else ''}"
            msg["From"] = mail.get("from") or mail.get("username") or "vendorwatch@localhost"
            to = mail["to"] if isinstance(mail["to"], list) else [mail["to"]]
            msg["To"] = ", ".join(to)
            msg.set_content(text)
            port = int(mail.get("smtp_port", 587))
            if port == 465:
                srv = smtplib.SMTP_SSL(mail["smtp_host"], port, context=ssl.create_default_context(), timeout=30)
            else:
                srv = smtplib.SMTP(mail["smtp_host"], port, timeout=30)
                if mail.get("starttls", True):
                    srv.starttls(context=ssl.create_default_context())
            with srv:
                if mail.get("username"):
                    srv.login(mail["username"], mail.get("password", ""))
                srv.send_message(msg)
        except Exception as e:  # noqa: BLE001
            errors.append(f"email: {e}")

    for e in errors:
        log.error("notification failed - %s", e)
    return errors

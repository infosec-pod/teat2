"""Static HTML dashboard (single self-contained file, no external assets)."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from .config import Config
from .scoring import PRIORITY_LABEL, asset_score
from .store import Store

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b1f24;--mute:#5d6673;--line:#e3e6ea;
--p1:#c62828;--p2:#e65100;--p3:#b38f00;--p4:#78838f;--A:#2e7d32;--B:#689f38;--C:#b38f00;--D:#e65100;--F:#c62828}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1a1f25;--ink:#e6e9ed;--mute:#9aa4b0;--line:#2b323a}}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
header{padding:20px 16px 8px;max-width:1200px;margin:auto}h1{margin:0;font-size:22px}.mute{color:var(--mute)}
main{max-width:1200px;margin:auto;padding:8px 16px 40px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px;margin:12px 0 24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;cursor:pointer}
.card.sel{outline:2px solid var(--ink)}
.grade{float:right;font-size:30px;font-weight:700;line-height:1}
.pill{display:inline-block;border-radius:99px;padding:1px 8px;font-size:12px;font-weight:600;color:#fff}
.P1{background:var(--p1)}.P2{background:var(--p2)}.P3{background:var(--p3)}.P4{background:var(--p4)}
.tag{display:inline-block;border:1px solid var(--line);border-radius:4px;padding:0 5px;font-size:11px;margin-right:4px}
.tag.hot{border-color:var(--p1);color:var(--p1)}
.controls{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}
.controls input,.controls select{padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--ink)}
.controls input{flex:1;min-width:180px}
.f{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0}
.f a{color:inherit}.f .t{font-weight:600}.f .meta{font-size:12px;color:var(--mute);margin-top:4px}
.f .why{font-size:13px;margin-top:4px}.f details{margin-top:4px;font-size:13px}
"""

JS = """
const F=JSON.parse(document.getElementById('data').textContent);
const list=document.getElementById('list'),q=document.getElementById('q'),p=document.getElementById('p'),
t=document.getElementById('t'),st=document.getElementById('st');let asset='';
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function row(f){const d=f.data||{},imp=d.impact||{};let tags=[];
 if(d.kev)tags.push('<span class="tag hot">CISA KEV</span>');
 if(d.exploit_public)tags.push('<span class="tag hot">public exploit</span>');
 if(d.epss!=null)tags.push(`<span class="tag">EPSS ${(d.epss*100).toFixed(1)}%</span>`);
 if(imp.affected===true)tags.push('<span class="tag hot">affects you: '+esc((imp.affected_versions||[]).join(', '))+'</span>');
 if(imp.affected===false)tags.push('<span class="tag">not affected</span>');
 if(imp.affected===null&&f.type==='cve')tags.push('<span class="tag">impact unknown</span>');
 if(imp.fixed_versions&&imp.fixed_versions.length)tags.push('<span class="tag">fix: '+esc(imp.fixed_versions.join(', '))+'</span>');
 if(d.category)tags.push(`<span class="tag">${esc(d.category)}</span>`);
 if(f.status!=='open')tags.push(`<span class="tag">${esc(f.status)}</span>`);
 const why=d.reasons?`<div class="why">${esc(d.reasons.join(' · '))}</div>`:'';
 const det=d.description||d.summary?`<details><summary>details</summary><p>${esc(d.description||d.summary)}</p>${
  (d.patch_refs||[]).slice(0,3).map(u=>`<div><a href="${esc(u)}" target=_blank rel=noopener>${esc(u)}</a></div>`).join('')}${
  (d.github_pocs||[]).map(g=>`<div>PoC: <a href="${esc(g.url)}" target=_blank rel=noopener>${esc(g.name)}</a> ★${g.stars}</div>`).join('')}</details>`:'';
 return `<div class="f"><span class="pill ${f.priority}">${f.priority}</span> <span class="t"><a href="${esc(f.url)}" target=_blank rel=noopener>${esc(f.title)}</a></span>
 <div class="meta">${esc(f.asset_name)} · ${esc(f.type)} · ${esc((f.published||f.first_seen||'').slice(0,10))} · <code>${esc(f.key)}</code></div>
 <div>${tags.join('')}</div>${why}${det}</div>`}
function render(){const s=q.value.toLowerCase();const rows=F.filter(f=>(!asset||f.asset_id===asset)&&(!p.value||f.priority<=p.value)
 &&(!t.value||f.type===t.value)&&(!st.value||f.status===st.value)&&(!s||JSON.stringify(f).toLowerCase().includes(s)));
 list.innerHTML=rows.slice(0,500).map(row).join('')||'<p class="mute">Nothing matches.</p>';
 document.getElementById('n').textContent=rows.length+' finding(s)'}
document.querySelectorAll('.card').forEach(c=>c.onclick=()=>{asset=asset===c.dataset.id?'':c.dataset.id;
 document.querySelectorAll('.card').forEach(x=>x.classList.toggle('sel',x.dataset.id===asset));render()});
[q,p,t,st].forEach(e=>e.oninput=render);render();
"""


def build(cfg: Config, store: Store) -> str:
    names = {a.id: a.name for a in cfg.assets}
    cards = []
    all_f = []
    for a in cfg.assets:
        fs = store.findings(a.id)
        score, grade, drivers = asset_score(fs)
        open_fs = [f for f in fs if f["status"] == "open"]
        counts = {p: sum(1 for f in open_fs if f["priority"] == p) for p in ("P1", "P2", "P3")}
        hist = store.score_history(a.id, 30)
        trend = ""
        if len(hist) >= 2:
            delta = hist[-1]["score"] - hist[0]["score"]
            trend = f" ({'+' if delta >= 0 else ''}{delta} over {len(hist)} scans)"
        vers = ", ".join(a.versions) or ("versions not set" if a.product else "breach & news monitoring")
        cards.append(
            f'<div class="card" data-id="{html.escape(a.id)}"><span class="grade" style="color:var(--{grade})">{grade}</span>'
            f"<b>{html.escape(a.name)}</b><div class='mute'>"
            + (f"{html.escape(a.vendor)} {html.escape(a.product)} · " if a.vendor else "")
            + f"{html.escape(vers)}</div><div class='mute'>score {score}/100{trend} · {html.escape(a.criticality)}</div>"
            f"<div style='margin-top:6px'>" + "".join(
                f'<span class="pill {p}">{p} {c}</span> ' for p, c in counts.items() if c) + "</div>"
            + (f"<div class='mute' style='font-size:12px;margin-top:6px'>{html.escape('; '.join(drivers[:3]))}</div>" if drivers else "")
            + "</div>"
        )
        for f in fs:
            f["asset_name"] = names.get(f["asset_id"], f["asset_id"])
            all_f.append(f)

    data = json.dumps(all_f, default=str).replace("</", "<\\/")
    last = (store.get_state("last_run") or "never")[:16].replace("T", " ")
    opts = "".join(f'<option value="{p}">≤ {p} {PRIORITY_LABEL[p]}</option>' for p in ("P1", "P2", "P3"))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Vendor Risk Monitor</title><style>{CSS}</style></head>
<body><header><h1>Vendor Risk Monitor</h1>
<div class="mute">Last scan {html.escape(last)} UTC · generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC ·
grade A–F from open findings (KEV / exploited CVEs in your versions weigh most)</div></header>
<main><div class="grid">{''.join(cards)}</div>
<div class="controls"><input id="q" placeholder="Search CVE, title, text…">
<select id="p"><option value="">All priorities</option>{opts}</select>
<select id="t"><option value="">All types</option><option>cve</option><option>exploit</option><option>news</option><option>advisory</option></select>
<select id="st"><option value="open">Open</option><option value="">Any status</option><option>accepted</option><option>resolved</option></select>
<span id="n" class="mute" style="align-self:center"></span></div>
<div id="list"></div></main>
<script id="data" type="application/json">{data}</script><script>{JS}</script></body></html>"""

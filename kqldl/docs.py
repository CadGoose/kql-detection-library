"""Build a static, searchable documentation page for the library."""

from __future__ import annotations

import html
import json
import re
from collections import defaultdict
from pathlib import Path

from . import __version__
from .model import TACTICS, Detection

_SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def humanize_tactic(name: str) -> str:
    """'CommandAndControl' -> 'Command and Control'."""
    words = re.findall(r"[A-Z][a-z]*", name)
    return " ".join(w if i == 0 or w not in ("And",) else "and" for i, w in enumerate(words))


def humanize_duration(value: str) -> str:
    """'PT1H' -> '1h', 'P14D' -> '14d', 'PT15M' -> '15m'."""
    m = re.match(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$", value or "")
    if not m:
        return value
    parts = [f"{n}{u}" for n, u in zip(m.groups(), "dhm", strict=True) if n]
    return " ".join(parts) or value


def coverage(detections: list[Detection]) -> dict[str, list[str]]:
    """tactic -> sorted list of detection ids."""
    cov: dict[str, list[str]] = defaultdict(list)
    for d in detections:
        for t in d.get("tactics") or []:
            cov[t].append(d.id)
    return {t: sorted(ids) for t, ids in cov.items()}


def _card(d: Detection, attack: dict[str, str]) -> str:
    techs = "".join(
        f'<a class="chip tech" href="https://attack.mitre.org/techniques/{_e(t.replace(".", "/"))}/" '
        f'title="{_e(attack.get(t, ""))}">{_e(t)}</a>'
        for t in d["techniques"]
    )
    tactics = "".join(f'<span class="chip">{_e(humanize_tactic(t))}</span>' for t in d["tactics"])
    sources = ", ".join(_e(s) for s in d["data_sources"])
    fps = "".join(f"<li>{_e(x)}</li>" for x in d.get("false_positives") or [])
    tuning = "".join(f"<li>{_e(x)}</li>" for x in d.get("tuning") or [])
    refs = "".join(
        f'<li><a href="{_e(x)}" rel="noopener">{_e(x)}</a></li>' for x in d.get("references") or []
    )
    search_blob = " ".join(
        [d.id, d["name"], d["description"], " ".join(d["tactics"]), " ".join(d["techniques"]),
         " ".join(d["data_sources"]), " ".join(attack.get(t, "") for t in d["techniques"])]
    ).lower()
    return f"""
<article class="card" id="{_e(d.id)}" data-sev="{_e(d['severity'])}" data-search="{_e(search_blob)}">
  <header>
    <span class="sev sev-{_e(d['severity'].lower())}">{_e(d['severity'])}</span>
    <span class="id">{_e(d.id)}</span>
    <span class="platforms">{_e(' · '.join(d['platforms']))}</span>
  </header>
  <h2>{_e(d['name'])}</h2>
  <p>{_e(' '.join(str(d['description']).split()))}</p>
  <div class="chips">{tactics}{techs}</div>
  <p class="meta"><strong>Tables:</strong> {sources} &nbsp;·&nbsp; <strong>Runs:</strong> every {_e(humanize_duration(d['query_frequency']))}, looking back {_e(humanize_duration(d['query_period']))}</p>
  <details>
    <summary>Query</summary>
    <div class="qwrap"><button class="copy" type="button" data-copy="{_e(d.id)}">Copy</button>
    <pre><code id="q-{_e(d.id)}">{_e(str(d['query']).rstrip())}</code></pre></div>
  </details>
  <details>
    <summary>False positives &amp; tuning</summary>
    <ul>{fps}</ul><ul>{tuning}</ul>
  </details>
  {'<details><summary>References</summary><ul>' + refs + '</ul></details>' if refs else ''}
</article>"""


def build_html(detections: list[Detection], attack: dict[str, str]) -> str:
    dets = sorted(
        (d for d in detections if d.get("status") != "deprecated"),
        key=lambda d: (_SEV_ORDER.get(d["severity"], 9), d.id),
    )
    cov = coverage(dets)
    matrix = "".join(
        f'<div class="cell{" empty" if not cov.get(t) else ""}"><span class="tname">{_e(humanize_tactic(t))}</span>'
        f'<span class="count">{len(cov.get(t, []))}</span></div>'
        for t in TACTICS
    )
    techniques = sorted({t for d in dets for t in d["techniques"]})
    cards = "".join(_card(d, attack) for d in dets)
    stats = {
        "detections": len(dets),
        "techniques": len(techniques),
        "tactics": sum(1 for t in TACTICS if cov.get(t)),
        "high": sum(1 for d in dets if d["severity"] == "High"),
    }
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KQL Detection Library</title>
<meta name="description" content="{stats['detections']} Microsoft Sentinel and Defender XDR detections mapped to MITRE ATT&amp;CK, by George Mkahail (CadGoose).">
<style>
:root {{ --bg:#f6f3ee; --card:#fff; --ink:#16181d; --muted:#5b6270; --line:#e4ded4; --accent:#9a3412;
  --high:#b91c1c; --med:#b45309; --low:#1d4ed8; --code:#1b1d23; --codeink:#e8e6e3; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#14161a; --card:#1c1f25; --ink:#eceae6; --muted:#a3a9b5;
  --line:#2c3038; --accent:#fb923c; --high:#f87171; --med:#fbbf24; --low:#93c5fd; --code:#0f1115; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }}
.wrap {{ max-width:1100px; margin:0 auto; padding:40px 16px 80px; }}
h1 {{ font-size:clamp(28px,5vw,44px); line-height:1.1; margin:0 0 8px; letter-spacing:-.02em; }}
.lede {{ color:var(--muted); max-width:720px; margin:0 0 24px; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin:24px 0; }}
.stat {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 16px; }}
.stat b {{ display:block; font-size:28px; font-family:ui-monospace,Menlo,monospace; color:var(--accent); }}
.stat span {{ color:var(--muted); font-size:14px; }}
.matrix {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:8px; margin:8px 0 28px; }}
.cell {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:10px 12px; display:flex; justify-content:space-between; gap:8px; font-size:13px; }}
.cell .count {{ font-family:ui-monospace,monospace; font-weight:700; color:var(--accent); }}
.cell.empty {{ opacity:.45; }}
.controls {{ display:flex; flex-wrap:wrap; gap:8px; margin:0 0 20px; position:sticky; top:0; background:var(--bg); padding:10px 0; z-index:2; }}
input[type=search] {{ flex:1 1 260px; min-width:0; padding:10px 14px; border-radius:10px; border:1px solid var(--line); background:var(--card); color:var(--ink); font-size:15px; }}
.filter {{ padding:8px 14px; border-radius:999px; border:1px solid var(--line); background:var(--card); color:var(--ink); cursor:pointer; font-size:14px; }}
.filter[aria-pressed=true] {{ background:var(--ink); color:var(--bg); }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:20px; margin:0 0 14px; }}
.card header {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; font-family:ui-monospace,monospace; font-size:13px; color:var(--muted); }}
.card h2 {{ font-size:19px; margin:8px 0 6px; }}
.card p {{ margin:6px 0; }}
.sev {{ font-weight:700; }} .sev-high {{ color:var(--high); }} .sev-medium {{ color:var(--med); }} .sev-low,.sev-informational {{ color:var(--low); }}
.chips {{ display:flex; flex-wrap:wrap; gap:6px; margin:10px 0; }}
.chip {{ font-size:12px; padding:3px 9px; border-radius:999px; border:1px solid var(--line); color:var(--muted); text-decoration:none; }}
.chip.tech {{ color:var(--accent); font-family:ui-monospace,monospace; }}
.meta {{ font-size:14px; color:var(--muted); }}
details {{ margin-top:8px; }} summary {{ cursor:pointer; font-weight:600; font-size:14px; }}
.qwrap {{ position:relative; }}
pre {{ background:var(--code); color:var(--codeink); padding:16px; border-radius:10px; overflow-x:auto; font-size:13px; line-height:1.5; }}
.copy {{ position:absolute; top:8px; right:8px; font-size:12px; padding:4px 10px; border-radius:6px; border:1px solid #444; background:#2a2d35; color:#eee; cursor:pointer; }}
footer {{ margin-top:40px; color:var(--muted); font-size:14px; }}
a {{ color:var(--accent); }}
.hidden {{ display:none; }}
</style>
</head>
<body>
<div class="wrap">
  <p style="font-family:ui-monospace,monospace;color:var(--accent);margin:0 0 8px">kql-detection-library · v{_e(__version__)}</p>
  <h1>KQL Detection Library</h1>
  <p class="lede">Production-minded hunting and analytics rules for Microsoft Sentinel and Defender XDR. Each detection is mapped to MITRE ATT&amp;CK and ships with false-positive notes and tuning advice from real SOC work.</p>
  <div class="stats">
    <div class="stat"><b>{stats['detections']}</b><span>detections</span></div>
    <div class="stat"><b>{stats['techniques']}</b><span>ATT&amp;CK techniques</span></div>
    <div class="stat"><b>{stats['tactics']}</b><span>tactics covered</span></div>
    <div class="stat"><b>{stats['high']}</b><span>high severity</span></div>
  </div>
  <h3>ATT&amp;CK tactic coverage</h3>
  <div class="matrix">{matrix}</div>
  <div class="controls" role="search">
    <input type="search" id="q" placeholder="Search: MFA, inbox rule, T1110, SigninLogs..." aria-label="Search detections">
    <button class="filter" aria-pressed="true" data-sev="">All</button>
    <button class="filter" aria-pressed="false" data-sev="High">High</button>
    <button class="filter" aria-pressed="false" data-sev="Medium">Medium</button>
    <button class="filter" aria-pressed="false" data-sev="Low">Low</button>
  </div>
  <p id="none" class="hidden">No detections match.</p>
  <main id="list">{cards}</main>
  <footer>Built by <a href="https://github.com/CadGoose">George Mkahail (CadGoose)</a>. Source &amp; ARM export: <a href="https://github.com/CadGoose/kql-detection-library">github.com/CadGoose/kql-detection-library</a>.</footer>
</div>
<script>
(() => {{
  const q = document.getElementById('q'), cards = [...document.querySelectorAll('.card')], none = document.getElementById('none');
  let sev = '';
  const apply = () => {{
    const terms = q.value.toLowerCase().split(/\\s+/).filter(Boolean); let shown = 0;
    cards.forEach(c => {{ const ok = (!sev || c.dataset.sev === sev) && terms.every(t => c.dataset.search.includes(t));
      c.classList.toggle('hidden', !ok); if (ok) shown++; }});
    none.classList.toggle('hidden', shown > 0);
  }};
  q.addEventListener('input', apply);
  document.querySelectorAll('.filter').forEach(b => b.addEventListener('click', () => {{
    sev = b.dataset.sev; document.querySelectorAll('.filter').forEach(x => x.setAttribute('aria-pressed', String(x === b))); apply(); }}));
  document.querySelectorAll('.copy').forEach(b => b.addEventListener('click', async () => {{
    const code = document.getElementById('q-' + b.dataset.copy).innerText;
    try {{ await navigator.clipboard.writeText(code); b.textContent = 'Copied'; }} catch {{ b.textContent = 'Select & copy'; }}
    setTimeout(() => b.textContent = 'Copy', 1500); }}));
}})();
</script>
</body>
</html>
"""


def write_site(detections: list[Detection], attack: dict[str, str], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    index = out_dir / "index.html"
    index.write_text(build_html(detections, attack), encoding="utf-8")
    (out_dir / "coverage.json").write_text(json.dumps(coverage(detections), indent=2), encoding="utf-8")
    return index

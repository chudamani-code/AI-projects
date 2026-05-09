"""
generate_report.py — generates a standalone HTML threat model report
from risk_register.json.

Usage:
    python generate_report.py                        # outputs report.html
    python generate_report.py --summary              # console summary only
    python generate_report.py --output my_report.html

The HTML report is self-contained (no external dependencies) and
suitable for sharing with stakeholders or including in a security review.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


# ── Load data ─────────────────────────────────────────────────────────────────

def load(path: str = "risk_register.json") -> dict:
    with open(path) as f:
        return json.load(f)


# ── Analysis functions ────────────────────────────────────────────────────────

def risk_level(score: int, thresholds: dict) -> str:
    for level, t in thresholds.items():
        if t["min"] <= score <= t["max"]:
            return level.upper()
    return "UNKNOWN"


def stride_coverage(threats: list[dict]) -> dict[str, int]:
    counts = defaultdict(int)
    mapping = {
        "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
        "I": "Information Disclosure", "D": "Denial of Service",
        "E": "Elevation of Privilege",
    }
    for t in threats:
        for s in t["stride"]:
            counts[mapping.get(s, s)] += 1
    return dict(counts)


def controls_coverage(threats: list[dict], controls: list[dict]) -> dict[str, int]:
    """How many threats does each control mitigate?"""
    ctrl_map = {c["id"]: c for c in controls}
    coverage = {}
    for c in controls:
        coverage[c["id"]] = {
            "title": c["title"],
            "count": len(c["mitigates"]),
            "threats": c["mitigates"],
            "type": c["type"],
        }
    return coverage


def print_summary(data: dict) -> None:
    threats = data["threats"]
    controls = data["controls"]
    meta = data["metadata"]

    print(f"\n{'═' * 60}")
    print(f"  Threat Model: {meta['system']}")
    print(f"  Methodology:  {meta['methodology']}")
    print(f"  Date:         {meta['date']}")
    print(f"{'═' * 60}")

    # Risk distribution
    dist = defaultdict(int)
    for t in threats:
        dist[t["risk_level"]] += 1

    print("\n  Risk Distribution:")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        bar = "█" * dist.get(level, 0)
        print(f"    {level:<10} {dist.get(level, 0):>2}  {bar}")

    # Top threats by score
    top = sorted(threats, key=lambda t: t["risk_score"], reverse=True)[:5]
    print("\n  Top 5 Threats by Risk Score:")
    for t in top:
        print(f"    [{t['id']}] {t['title'][:50]:<50}  score={t['risk_score']}  ({t['risk_level']})")

    # STRIDE coverage
    stride = stride_coverage(threats)
    print("\n  STRIDE Coverage:")
    for cat, count in sorted(stride.items(), key=lambda x: -x[1]):
        print(f"    {cat:<25} {count} threat(s)")

    # Controls
    total = len(controls)
    by_type = defaultdict(int)
    for c in controls:
        by_type[c["type"]] += 1
    print(f"\n  Controls: {total} total")
    for t, n in sorted(by_type.items()):
        print(f"    {t:<12} {n}")

    # Open threats
    open_critical = [t for t in threats if t["risk_level"] == "CRITICAL" and t.get("status") == "open"]
    print(f"\n  Open CRITICAL threats requiring action: {len(open_critical)}")
    for t in open_critical:
        print(f"    [{t['id']}] {t['title']}")

    print(f"\n{'═' * 60}\n")


# ── HTML report ───────────────────────────────────────────────────────────────

LEVEL_COLORS = {
    "CRITICAL": "#f87171",
    "HIGH":     "#fb923c",
    "MEDIUM":   "#fbbf24",
    "LOW":      "#4ade80",
}

STRIDE_FULL = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}


def _level_badge(level: str) -> str:
    color = LEVEL_COLORS.get(level, "#64748b")
    return f'<span style="background:{color}22;color:{color};border:1px solid {color}55;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">{level}</span>'


def _stride_badges(stride_list: list[str]) -> str:
    colors = {"S":"#a78bfa","T":"#2dd4bf","R":"#60a5fa","I":"#f472b6","D":"#fb923c","E":"#f87171"}
    parts = []
    for s in stride_list:
        c = colors.get(s, "#64748b")
        full = STRIDE_FULL.get(s, s)
        parts.append(f'<span title="{full}" style="background:{c}22;color:{c};border:1px solid {c}55;padding:1px 5px;border-radius:3px;font-size:10px;font-weight:600">{s}</span>')
    return " ".join(parts)


def _risk_matrix_html(threats: list[dict]) -> str:
    """5×5 risk matrix with threat IDs placed in cells."""
    cells: dict[tuple, list[str]] = defaultdict(list)
    for t in threats:
        l, i = t["likelihood"], t["impact"]
        cells[(l, i)].append(t["id"])

    rows = []
    for l in range(5, 0, -1):
        row_cells = [f'<td style="color:#475569;font-size:10px;padding:4px 8px;text-align:right">{l}</td>']
        for i in range(1, 6):
            score = l * i
            ids = cells.get((l, i), [])
            if score >= 18:
                bg = "#3d1515"; border = "#f87171"
            elif score >= 11:
                bg = "#3d2210"; border = "#fb923c"
            elif score >= 6:
                bg = "#38250a"; border = "#fbbf24"
            else:
                bg = "#0d2e18"; border = "#4ade80"

            inner = "".join(
                f'<div style="font-size:9px;color:{border};font-weight:600">{tid}</div>'
                for tid in ids
            )
            row_cells.append(
                f'<td style="background:{bg};border:1px solid {border}33;padding:6px;text-align:center;width:80px;height:56px;vertical-align:top">'
                f'{score}<br>{inner}</td>'
            )
        rows.append("<tr>" + "".join(row_cells) + "</tr>")

    header = "<tr><th></th>" + "".join(
        f'<th style="color:#64748b;font-size:10px;padding:4px;text-align:center">Impact {i}</th>'
        for i in range(1, 6)
    ) + "</tr>"

    return f"""
    <table style="border-collapse:collapse;font-family:monospace;font-size:12px">
      {header}
      {''.join(rows)}
    </table>
    <div style="margin-top:8px;font-size:11px;color:#64748b">
      Likelihood on Y axis (1=Rare, 5=Almost Certain) · Impact on X axis (1=Negligible, 5=Catastrophic)
    </div>
    """


def generate_html(data: dict) -> str:
    threats = sorted(data["threats"], key=lambda t: -t["risk_score"])
    controls = data["controls"]
    meta = data["metadata"]

    dist = defaultdict(int)
    for t in threats:
        dist[t["risk_level"]] += 1

    stride = stride_coverage(threats)
    ctrl_coverage = controls_coverage(threats, controls)

    # Threat rows
    threat_rows = ""
    for t in threats:
        controls_used = ", ".join(t["controls"]) if t["controls"] else "—"
        residual = _level_badge(t["residual_risk_level"])
        atlas = ", ".join(t.get("mitre_atlas", [])) or "—"
        color = LEVEL_COLORS.get(t["risk_level"], "#64748b")
        threat_rows += f"""
        <tr style="border-bottom:1px solid #1e293b">
          <td style="padding:10px 8px;font-weight:600;color:{color}">{t['id']}</td>
          <td style="padding:10px 8px">{t['title']}</td>
          <td style="padding:10px 8px">{_stride_badges(t['stride'])}</td>
          <td style="padding:10px 8px;text-align:center">{t['likelihood']}</td>
          <td style="padding:10px 8px;text-align:center">{t['impact']}</td>
          <td style="padding:10px 8px;text-align:center;font-weight:600;color:{color}">{t['risk_score']}</td>
          <td style="padding:10px 8px">{_level_badge(t['risk_level'])}</td>
          <td style="padding:10px 8px">{residual}</td>
          <td style="padding:10px 8px;font-size:11px;color:#64748b">{controls_used}</td>
          <td style="padding:10px 8px;font-size:10px;color:#64748b">{atlas}</td>
        </tr>"""

    # Controls rows
    ctrl_rows = ""
    for c in controls:
        type_color = {"preventive": "#2dd4bf", "detective": "#a78bfa", "corrective": "#fbbf24"}.get(c["type"], "#64748b")
        mitigates = ", ".join(c["mitigates"])
        ctrl_rows += f"""
        <tr style="border-bottom:1px solid #1e293b">
          <td style="padding:10px 8px;font-weight:600;color:#60a5fa">{c['id']}</td>
          <td style="padding:10px 8px">{c['title']}</td>
          <td style="padding:10px 8px">
            <span style="background:{type_color}22;color:{type_color};border:1px solid {type_color}55;padding:2px 6px;border-radius:3px;font-size:10px">{c['type']}</span>
          </td>
          <td style="padding:10px 8px;font-size:11px;color:#64748b">{mitigates}</td>
          <td style="padding:10px 8px;font-size:11px;color:#64748b">{c['description'][:120]}…</td>
        </tr>"""

    # STRIDE chart
    stride_bars = ""
    max_count = max(stride.values(), default=1)
    for cat, count in sorted(stride.items(), key=lambda x: -x[1]):
        pct = int(count / max_count * 100)
        stride_bars += f"""
        <div style="margin-bottom:8px">
          <div style="font-size:11px;color:#94a3b8;margin-bottom:3px">{cat}</div>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;background:#1e293b;border-radius:3px;height:8px">
              <div style="width:{pct}%;background:#a78bfa;height:8px;border-radius:3px"></div>
            </div>
            <div style="font-size:11px;color:#a78bfa;width:20px">{count}</div>
          </div>
        </div>"""

    summary_stats = "".join(
        f'<div style="background:#1a1d27;border:1px solid {LEVEL_COLORS[lvl]}44;border-radius:8px;padding:12px 16px;text-align:center">'
        f'<div style="font-size:28px;font-weight:700;color:{LEVEL_COLORS[lvl]}">{dist.get(lvl, 0)}</div>'
        f'<div style="font-size:11px;color:#64748b;margin-top:4px">{lvl}</div></div>'
        for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Threat Model Report — {meta['system']}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f1117; color: #e2e8f0; font-family: system-ui, sans-serif; font-size: 13px; padding: 32px; }}
  h1 {{ font-size: 20px; color: #e2e8f0; margin-bottom: 4px; }}
  h2 {{ font-size: 14px; text-transform: uppercase; letter-spacing: 0.1em; color: #64748b; margin: 32px 0 16px; border-bottom: 1px solid #1e293b; padding-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 8px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #475569; border-bottom: 1px solid #334155; }}
  tr:hover td {{ background: #1a1d2788; }}
  .grid {{ display: grid; gap: 16px; }}
  .card {{ background: #1a1d27; border: 1px solid #1e293b; border-radius: 10px; padding: 20px; }}
</style>
</head>
<body>

<div style="margin-bottom:24px">
  <h1>Threat Model Report — {meta['system']}</h1>
  <div style="color:#64748b;font-size:12px;margin-top:4px">
    {meta['date']} · {meta['methodology']} · {meta['author']}
  </div>
</div>

<h2>Risk Summary</h2>
<div class="grid" style="grid-template-columns:repeat(4,1fr)">
  {summary_stats}
</div>

<h2>Risk Matrix</h2>
<div class="card">
  {_risk_matrix_html(threats)}
</div>

<div class="grid" style="grid-template-columns:1fr 1fr;margin-top:32px">
  <div>
    <h2 style="margin-top:0">STRIDE Coverage</h2>
    <div class="card">{stride_bars}</div>
  </div>
  <div>
    <h2 style="margin-top:0">Controls Summary</h2>
    <div class="card">
      <div style="font-size:11px;color:#64748b;margin-bottom:12px">{len(controls)} controls across {len(set(c['type'] for c in controls))} types</div>
      {"".join(
        f'<div style="margin-bottom:6px;font-size:12px"><span style="color:#60a5fa;font-weight:600">{c["id"]}</span> — {c["title"]}</div>'
        for c in controls[:8]
      )}
      <div style="color:#475569;font-size:11px;margin-top:8px">+ {max(0, len(controls)-8)} more — see Controls table below</div>
    </div>
  </div>
</div>

<h2>Threat Register</h2>
<div class="card" style="overflow-x:auto">
  <table>
    <thead><tr>
      <th>ID</th><th>Title</th><th>STRIDE</th><th>L</th><th>I</th>
      <th>Score</th><th>Level</th><th>Residual</th><th>Controls</th><th>ATLAS</th>
    </tr></thead>
    <tbody>{threat_rows}</tbody>
  </table>
</div>

<h2>Controls Register</h2>
<div class="card" style="overflow-x:auto">
  <table>
    <thead><tr>
      <th>ID</th><th>Title</th><th>Type</th><th>Mitigates</th><th>Description</th>
    </tr></thead>
    <tbody>{ctrl_rows}</tbody>
  </table>
</div>

<div style="margin-top:40px;color:#334155;font-size:11px;text-align:center">
  Generated by generate_report.py · {meta['system']} Threat Model v{meta['version']}
</div>
</body>
</html>"""


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate AI threat model HTML report")
    parser.add_argument("--input",   default="risk_register.json", help="Path to risk register JSON")
    parser.add_argument("--output",  default="report.html",         help="Output HTML path")
    parser.add_argument("--summary", action="store_true",            help="Print console summary only")
    args = parser.parse_args()

    data = load(args.input)
    print_summary(data)

    if not args.summary:
        html = generate_html(data)
        Path(args.output).write_text(html, encoding="utf-8")
        print(f"  Report written to: {args.output}")
        print(f"  Open in browser:   file://{Path(args.output).resolve()}\n")


if __name__ == "__main__":
    main()

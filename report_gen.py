#!/usr/bin/env python3
"""
Generate JSON + HTML reports from predicted_iocs CSV.
"""
import pandas as pd
import json
from jinja2 import Template
from pathlib import Path

HTML_TEMPLATE = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Threat Summary</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<h1>Threat Summary</h1>
<p>Total IOCs: {{ total }}</p>
<p>High risk: {{ high }}</p>
<table>
<tr><th>IOC</th><th>Type</th><th>Risk</th><th>Reputation</th></tr>
{% for r in rows %}
<tr class="risk-{{ r.risk|lower }}"><td>{{ r.ioc }}</td><td>{{ r.type }}</td><td>{{ r.risk }}</td><td>{{ r.reputation_score }}</td></tr>
{% endfor %}
</table>
</body></html>
"""

def generate_reports(csv_file: str, out_json: str = 'reports/threat_report.json', out_html: str = 'reports/threat_summary.html'):
    df = pd.read_csv(csv_file)
    total = len(df)
    high = int((df.get('risk', '') == 'High').sum()) if 'risk' in df.columns else 0
    rows = df.to_dict('records')
    summary = {'total_iocs': total, 'high_risk_count': high, 'rows': rows}
    Path('reports').mkdir(parents=True, exist_ok=True)
    with open(out_json, 'w') as f:
        json.dump(summary, f, indent=2)
    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(total=total, high=high, rows=rows)
    with open(out_html, 'w') as f:
        f.write(html)
    print(f"Wrote {out_json} and {out_html}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('file')
    parser.add_argument('--json', default='reports/threat_report.json')
    parser.add_argument('--html', default='reports/threat_summary.html')
    args = parser.parse_args()
    generate_reports(args.file, args.json, args.html)

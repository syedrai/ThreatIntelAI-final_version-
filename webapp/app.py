from flask import Flask, render_template, send_from_directory
import pandas as pd
from pathlib import Path
import os

app = Flask(__name__, template_folder='templates', static_folder='static')
DATA_FILE = os.getenv('WEBAPP_DATA_FILE', 'data/enriched_iocs.csv')

@app.route('/')
def index():
    rows = []
    summary = {'total': 0, 'high': 0}
    if Path(DATA_FILE).exists():
        df = pd.read_csv(DATA_FILE)
        summary['total'] = len(df)
        if 'risk' in df.columns:
            summary['high'] = int((df['risk'] == 'High').sum())
        rows = df.to_dict('records')[:1000]
    return render_template('index.html', summary=summary, rows=rows)

@app.route('/report')
def report():
    rpt = Path('reports/threat_summary.html')
    if rpt.exists():
        return send_from_directory('reports', 'threat_summary.html')
    return "<p>No report generated. Run report_gen.</p>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)

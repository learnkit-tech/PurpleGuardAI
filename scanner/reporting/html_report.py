import json
from collections import Counter


def generate_html_report(json_report, output_file):

    with open(json_report, "r") as f:
        report = json.load(f)

    findings = report["findings"]

    severity_count = Counter(
        finding["severity"]
        for finding in findings
    )

    html = f"""
<html>
<head>
<title>PurpleGuardAI Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
}}

h1 {{
    color: purple;
}}

.summary {{
    padding: 15px;
    border: 1px solid #ccc;
    margin-bottom: 20px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th, td {{
    border: 1px solid #ccc;
    padding: 10px;
    text-align: left;
}}

th {{
    background: #f2f2f2;
}}

</style>

</head>

<body>

<h1>PurpleGuardAI Security Report</h1>

<div class="summary">

<h2>Scan Summary</h2>

<p><b>Target:</b> {report['target']}</p>

<p><b>Scan Time:</b> {report['timestamp']}</p>

<p><b>Total Findings:</b> {len(findings)}</p>

<p>
Critical: {severity_count.get("CRITICAL", 0)}
<br>
High: {severity_count.get("HIGH", 0)}
<br>
Medium: {severity_count.get("MEDIUM", 0)}
<br>
Low: {severity_count.get("LOW", 0)}
</p>

</div>


<h2>Findings</h2>

<table>

<tr>
<th>ID</th>
<th>Name</th>
<th>File</th>
<th>Line</th>
<th>Severity</th>
<th>Recommendation</th>
</tr>
"""

    for finding in findings:

        html += f"""
<tr>
<td>{finding['id']}</td>
<td>{finding['name']}</td>
<td>{finding['file']}</td>
<td>{finding['line']}</td>
<td>{finding['severity']}</td>
<td>{finding['recommendation']}</td>
</tr>
"""

    html += """

</table>

</body>
</html>
"""

    with open(output_file, "w") as f:
        f.write(html)

    print(f"HTML report saved to {output_file}")

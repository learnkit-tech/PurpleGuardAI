import json


def generate_html_report(json_report, output_file):

    with open(json_report, "r") as f:
        report = json.load(f)

    html = """
    <html>
    <head>
        <title>PurpleGuardAI Report</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 40px;
            }

            h1 {
                color: purple;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th, td {
                border: 1px solid #ccc;
                padding: 8px;
            }

            th {
                background: #f2f2f2;
            }
        </style>
    </head>

    <body>

    <h1>PurpleGuardAI Security Report</h1>

    <table>

    <tr>
        <th>ID</th>
        <th>File</th>
        <th>Line</th>
        <th>Severity</th>
        <th>Recommendation</th>
    </tr>
    """

    for finding in report["findings"]:

        html += f"""
        <tr>
            <td>{finding['id']}</td>
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

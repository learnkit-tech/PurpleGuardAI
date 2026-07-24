import json


def generate_sarif(findings, output_file):

    report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PurpleGuardAI"
                    }
                },
                "results": []
            }
        ]
    }


    for finding in findings:

        report["runs"][0]["results"].append(
            {
                "ruleId": finding["id"],
                "message": {
                    "text": finding["description"]
                }
            }
        )


    with open(output_file, "w") as file:
        json.dump(
            report,
            file,
            indent=4
        )

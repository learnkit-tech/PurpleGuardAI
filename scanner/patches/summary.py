import os
import json


def generate_patch_summary(patch_directory="reports/patches"):

    patches = []

    if os.path.exists(patch_directory):

        for file in os.listdir(patch_directory):
            if file.endswith(".patch"):
                patches.append(file)

    summary = {
        "patches_generated": len(patches),
        "patch_files": patches,
        "status": "READY_FOR_REVIEW"
    }

    with open(
        "reports/patch_summary.json",
        "w"
    ) as file:
        json.dump(
            summary,
            file,
            indent=4
        )

    return summary

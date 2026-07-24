import os


class ChangeManager:

    def apply(self, change):

        print("\nChange Manager")

        if change.get("file") is None:
            return {
                "status": "waiting",
                "message": "No file change generated yet."
            }


        directory = os.path.dirname(
            change["file"]
        )

        if directory:
            os.makedirs(
                directory,
                exist_ok=True
            )


        with open(
            change["file"],
            "w"
        ) as file:
            file.write(
                change["content"]
            )


        return {
            "status": "completed",
            "file": change["file"]
        }

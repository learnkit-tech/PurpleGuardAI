import os


class ChangeManager:

    def apply(self, change):

        if change["status"] != "ready":

            return change


        written = []


        for file_change in change["files"]:

            path = file_change["path"]
            content = file_change["content"]


            directory = os.path.dirname(path)

            if directory:
                os.makedirs(
                    directory,
                    exist_ok=True
                )


            with open(path, "w") as file:
                file.write(content)


            written.append(path)


        return {
            "status": "completed",
            "files": written
        }


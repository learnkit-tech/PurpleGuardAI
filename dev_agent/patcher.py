from agent_api.tools import write_file


class Patcher:

    def apply(self, file, new_content):

        print(f"Applying change: {file}")

        write_file(
            file,
            new_content
        )

        return {
            "status": "success",
            "file": file
        }

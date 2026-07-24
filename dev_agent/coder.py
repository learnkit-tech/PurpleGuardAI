from agent_api.tools import read_file, write_file


class CodeWriter:

    def create_change(self, file, content):

        print(f"Writing changes to {file}")

        write_file(
            file,
            content
        )

        return {
            "status": "written",
            "file": file
        }


    def inspect(self, file):

        return read_file(file)

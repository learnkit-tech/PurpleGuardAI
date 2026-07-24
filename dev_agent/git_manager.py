import subprocess


class GitManager:

    def run(self, command):

        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        return {
            "output": result.stdout,
            "error": result.stderr,
            "code": result.returncode
        }


    def checkpoint(self):

        return self.run(
            "git add . && git commit -m 'Agent checkpoint'"
        )


    def rollback(self):

        return self.run(
            "git reset --hard HEAD"
        )

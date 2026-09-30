import os
import sys

# Autonomous surface tag. Everything spawned from this process tree
# (the worker loop, /agent/run threads, and their subprocesses)
# inherits PG_EXEC_SURFACE, and purpleguard_runner.py refuses
# --approve / approved=True on that surface. A human terminal or the
# API/frontend run without the tag, so the normal approval flow is
# untouched. Setting the variable here instead of threading a flag
# through every call site is what makes the boundary structural
# rather than a coding convention.
os.environ["PG_EXEC_SURFACE"] = "agent_loop"

# Structural ancestry root: mark this process as a child subreaper so
# daemonized escapes (setsid / double-fork) spawned from this tree are
# reparented to the loop instead of init. purpleguard_runner.py then
# detects them via /proc ancestry even after a shell strips the env
# tag (env -u / env -i).
from purpleguard_runner import set_agent_subreaper

set_agent_subreaper()

from dev_agent.loop import DeveloperAgent


def main(task=None):

    agent = DeveloperAgent()

    if task:
        agent.run_once(task)
    else:
        agent.run_once()


if __name__ == "__main__":

    task = None

    if len(sys.argv) > 1:
        task = sys.argv[1]

    main(task)

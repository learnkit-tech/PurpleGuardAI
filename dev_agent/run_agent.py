import sys

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


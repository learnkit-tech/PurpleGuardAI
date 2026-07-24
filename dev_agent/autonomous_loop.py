import time
from dev_agent.loop import DeveloperAgent


class AutonomousLoop:

    def __init__(self):
        self.agent = DeveloperAgent()


    def start(self):

        print("PurpleGuardAI Autonomous Developer Started")

        while True:

            try:
                self.agent.run_once()

                print("\nWaiting for next task...\n")

                time.sleep(30)

            except KeyboardInterrupt:
                print("\nAgent stopped.")
                break

            except Exception as error:
                print("\nAgent error:")
                print(error)

                time.sleep(30)

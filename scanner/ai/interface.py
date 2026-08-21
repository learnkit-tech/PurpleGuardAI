from abc import ABC, abstractmethod


class AIProvider(ABC):

    @abstractmethod
    def analyze(self, prompt):
        pass

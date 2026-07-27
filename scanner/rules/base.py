from abc import ABC, abstractmethod


class Rule(ABC):
    id = ""
    name = ""
    severity = ""
    category = ""

    @abstractmethod
    def check(self, filepath, lines):
        pass

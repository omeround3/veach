from abc import ABC,abstractmethod

class Scanner(ABC):
    """ Scanner interface declares a method for executing a command shell for software/hardware """

    @abstractmethod
    def execute(self) -> list:
        """
        Abstract method that every child will have to implement
        :return: List of scanned modules
        """
        pass

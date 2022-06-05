from abc import ABC,abstractmethod

class Scanner(ABC):
    """
    Scanner interface declares a method for executing a command shell for software/hardware
    """

    @abstractmethod
    def execute(self) -> []:
        """
        abstract method that every child will have to implement
        :return:
        array of scanned modules
        """
        pass

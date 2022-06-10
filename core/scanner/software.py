import subprocess
from core.scanner.scanner import Scanner
from core.scanner.enums import CPEPart, CPEFormat

class Software(Scanner):
    """ Scan software installed on the operating system """
    def __init__(self):
        self.software_packages = []
        self.password = "Password1"

    def execute(self) -> list:
        """
        Execute will scan all installed packages
        :return: List of dictionaries in the following structure : {"part": "a", vendor": "", "product": "", "version" : ""}
        """

        command = "sudo -S dpkg-query --show"
        stdout_patterns = [CPEFormat.PART.value, CPEFormat.VENDOR.value, CPEFormat.PRODUCT.value,
                           CPEFormat.VERSION.value]

        command_sudo = subprocess.Popen(['echo', self.password], stdin=None, stdout=subprocess.PIPE)

        args = [arg for arg in command.split(' ') if len(arg) > 0]
        command_shell = subprocess.Popen(args, stdin=command_sudo.stdout, stdout=subprocess.PIPE)

        if command_shell.stderr:
            raise Exception(command_shell.stderr.read().decode())

        for package in command_shell.stdout:
            record_tmp = package.decode().strip()
            record_tmp = record_tmp.split('\t')
            record_tmp.insert(0, CPEPart.SOFTWARE.value)
            record_tmp.insert(1, None)
            if len(record_tmp) == len(stdout_patterns):
                self.software_packages.append(dict(zip(stdout_patterns, record_tmp)))

        return self.software_packages



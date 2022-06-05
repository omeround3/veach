import subprocess
from scanner import Scanner
from enums import CPE_Part, CPE_Format

class Software(Scanner):
    """
    scan software installed on the operating system
    """
    def __init__(self):
        self.software_packages = []
        self.password = "Password1"

    def execute(self) -> {}:
        """
        execute will scan all installed packages
        :return:
        array of dictionaries in the following structure : {"part": "a", vendor": "", "product": "", "version" : ""}
        """

        command = "sudo -S dpkg-query --show"
        stdout_patterns = [CPE_Format.PART.value, CPE_Format.VENDOR.value, CPE_Format.PRODUCT.value,
                           CPE_Format.VERSION.value]

        command_sudo = subprocess.Popen(['echo', self.password], stdin=None, stdout=subprocess.PIPE)

        args = [arg for arg in command.split(' ') if len(arg) > 0]
        command_shell = subprocess.Popen(args, stdin=command_sudo.stdout, stdout=subprocess.PIPE)

        if command_shell.stderr:
            raise Exception(command_shell.stderr.read().decode())

        for package in command_shell.stdout:
            record_tmp = package.decode().strip()
            record_tmp = record_tmp.split('\t')
            record_tmp.insert(0, CPE_Part.SOFTWARE.value)
            record_tmp.insert(1, None)
            if len(record_tmp) == len(stdout_patterns):
                self.software_packages.append(dict(zip(stdout_patterns, record_tmp)))

        return self.software_packages



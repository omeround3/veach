import subprocess
from scanner import Scanner
from enums import CPE_Part, CPE_Format

class Hardware(Scanner):
    """
    scan hardware installed on the operating system
    """
    def __init__(self):
        self.hardware_packages = []
        self.password = "Password1"

    def execute(self) -> []:
        """
        execute will scan the following hardware component : motherboard firmware, cpu, pci, isa, ide, bridge, generic,
        display adapter, scsi, disk, volume, usb, and remoteaccess
        :return:
        array of dictionaries in the following structure : {"part": "h", "vendor": "", "product": "", "version" : ""}
        """

        command = "sudo -S lshw"
        stdout_patterns = [CPE_Format.PART.value, CPE_Format.VENDOR.value, CPE_Format.PRODUCT.value,
                           CPE_Format.VERSION.value]

        command_sudo = subprocess.Popen(['echo', self.password], stdin=None, stdout=subprocess.PIPE)

        args = command.split()
        command_shell = subprocess.Popen(args, stdin=command_sudo.stdout, stdout=subprocess.PIPE)

        if command_shell.stderr:
            raise Exception(command_shell.stderr.read().decode())

        for package in command_shell.stdout:
            record_tmp = package.decode().strip()

            if CPE_Format.PRODUCT in record_tmp:
                product = record_tmp.split(":")

            elif CPE_Format.VENDOR in record_tmp and product is not None:
                vendor = record_tmp.split(":")

            elif CPE_Format.VERSION in record_tmp and product is not None and vendor is not None:
                version = record_tmp.split(":")
                record_tmp = [CPE_Part.HARDWARE.value, vendor[1], product[1], version[1]]

                vendor = None
                product = None

                self.hardware_packages.append(dict(zip(stdout_patterns, record_tmp)))
            else:
                pass

        return self.hardware_packages


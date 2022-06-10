import subprocess
from core.scanner.scanner import Scanner
from core.scanner.enums import CPEPart, CPEFormat

class Hardware(Scanner):
    """ Scan hardware components """
    def __init__(self):
        self.hardware_packages = []
        self.password = "Password1"

    def execute(self) -> list:
        """ 
        Execute will scan the following hardware components : 
        motherboard firmware, cpu, pci, isa, ide, bridge, generic,display adapter, scsi, disk, volume, usb, and remoteaccess
        :return: List of dictionaries in the following structure : {"part": "h", "vendor": "", "product": "", "version" : ""}
        """

        command = "sudo -S lshw"
        stdout_patterns = [CPEFormat.PART.value, CPEFormat.VENDOR.value, CPEFormat.PRODUCT.value,
                           CPEFormat.VERSION.value]

        command_sudo = subprocess.Popen(['echo', self.password], stdin=None, stdout=subprocess.PIPE)

        args = command.split()
        command_shell = subprocess.Popen(args, stdin=command_sudo.stdout, stdout=subprocess.PIPE)

        if command_shell.stderr:
            raise Exception(command_shell.stderr.read().decode())

        for package in command_shell.stdout:
            record_tmp = package.decode().strip()

            if CPEFormat.PRODUCT in record_tmp:
                product = record_tmp.split(":")

            elif CPEFormat.VENDOR in record_tmp and product is not None:
                vendor = record_tmp.split(":")

            elif CPEFormat.VERSION in record_tmp and product is not None and vendor is not None:
                version = record_tmp.split(":")
                record_tmp = [CPEPart.HARDWARE.value, vendor[1], product[1], version[1]]

                vendor = None
                product = None

                self.hardware_packages.append(dict(zip(stdout_patterns, record_tmp)))
            else:
                pass

        return self.hardware_packages


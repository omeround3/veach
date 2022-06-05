from scan_invoker import Scan_Invoker
from parser import Parser
from software import Software
from hardware import Hardware

def main():
    """
    This method will invoke software/hardware scanning
    and pass the result to parser component
    """
    scan = -1
    scan_software = -1
    scan_hardware = -1
    invoker = Scan_Invoker()
    parser = Parser()
    software_packages = []
    hardware_packages = []
    cpe_list = []
    while scan not in ('Y', 'y', 'N', 'n'):
        scan = input("Do you want to scan SOFTWARE/HARDWARE packages installed on your operation system? (Y/N)'")
    if scan in ('Y', 'y'):

        while scan_software not in ('Y', 'y', 'N', 'n'):
            scan_software = input("Do you want to scan SOFTWARE packages installed on your operation system? (Y/N)'")
        if scan_software in ('Y', 'y'):
            invoker.set_on_start(Software())
            software_packages = invoker.invoke()

        while scan_hardware not in ('Y', 'y', 'N', 'n'):
            scan_hardware = input("Do you want to scan HARDWARE components installed on your operation system? (Y/N)'")
        if scan_hardware in ('Y', 'y'):
            invoker.set_on_start(Hardware())
            hardware_packages = invoker.invoke()

    print(software_packages)
    cpe_list = parser.parse_data_to_cpe(software_packages)
    print(cpe_list)

if __name__ == '__main__':
    main()

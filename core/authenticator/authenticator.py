import subprocess


class Authenticator:
    """
    A class used to check if a certain user in is the sudo group
    """

    def __init__(self, username, password) -> None:
        """
        :param username: the connected(!) linux username 
        :param password: the connected(!) linux password 
        """
        self.username = username
        self.password = password
        self.authenticated = False

        grep = subprocess.Popen(
            ["grep", "^sudo:.*$", "/etc/group"], stdout=subprocess.PIPE)

        sudos = subprocess.Popen(
            ["cut", "-d", ":", "-f", "4"], stdin=grep.stdout, stdout=subprocess.PIPE)

        sudo_list = sudos.communicate()[0].decode(
            "utf-8").replace("\n", "").split(",")
        result = None
        if self.username in sudo_list:
            subprocess.Popen(
                ["sudo", "-k"], stdout=subprocess.PIPE).communicate()

            password = subprocess.Popen(
                ["echo", self.password], stdout=subprocess.PIPE)

            login = subprocess.Popen(
                ["sudo", "-S", "echo", "I AM SUDO"], stdin=password.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

            result = login.communicate()[0].decode("utf-8")
        if result == "I AM SUDO\n":
            self.authenticated = True

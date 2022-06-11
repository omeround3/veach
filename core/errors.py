class MissingConfigFileSection(Exception):
    def __init__(self, msg):
        self.msg = f'Section {msg} is missing from the config file'
        super().__init__(self.msg)


class MissingConfigFileOption(Exception):
    def __init__(self, msg):
        self.msg = f'Option {msg} is missing from the config file'
        super().__init__(self.msg)


class InvalidCPEStringFormat(Exception):
    def __init__(self, msg):
        self.msg = f"\"{msg}\" is not a valid CPE URI format"
        super().__init__(self.msg)


class InvalidCPEFormat(Exception):
    def __init__(self, msg):
        self.msg = f"\"{msg}\" is not a valid CPE structure"
        super().__init__(self.msg)


class InvalidStringFormat(Exception):
    def __init__(self, msg):
        self.msg = f"\"{msg}\" is not a valid format"
        super().__init__(self.msg)

class MissingConfigFileSection(Exception):
    def __init__(self, msg):
        self.msg = f'Section {msg} is missing from the config file'
        super().__init__(self.msg)


class MissingConfigFileOption(Exception):
    def __init__(self, msg):
        self.msg = f'Option {msg} is missing from the config file'
        super().__init__(self.msg)

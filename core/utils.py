

from enum import Enum
import re
import configparser
import codecs
from core.errors import MissingConfigFileOption, MissingConfigFileSection, InvalidStringFormat

cfg = configparser.ConfigParser()
cfg.read('core\\config.ini')


def get_settings_value(class_name: str, key: str):
    class_name = class_name.upper()
    key = key.lower()
    try:
        ret_val = cfg[class_name][key]
    except KeyError as e:
        if e.args[0] == class_name:
            raise MissingConfigFileSection(e)
        else:
            raise MissingConfigFileOption(e)
    return ret_val


def get_attribute(dict: dict, path: str):
    if isinstance(path, Enum):
        path = path.value

    pattern = get_settings_value('OTHER', 'attributes_string_pattern')
    pattern = re.compile(pattern)
    match = pattern.match(path)
    if match:
        path = path.split(".")
        for p in path:
            try:
                dict = dict[p]
            except KeyError:
                return None
        return dict
    else:
        raise InvalidStringFormat(path)

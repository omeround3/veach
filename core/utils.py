<<<<<<< HEAD
=======

>>>>>>> analyser_configuration
from enum import Enum
import re
import configparser
import codecs
<<<<<<< HEAD
from core.errors import MissingConfigFileOption, MissingConfigFileSection

cfg = configparser.ConfigParser()
cfg.read('core/config.ini')
=======
from typing import Iterable
from core.errors import MissingConfigFileOption, MissingConfigFileSection, InvalidStringFormat

cfg = configparser.ConfigParser()
cfg.read('core\\config.ini')
>>>>>>> analyser_configuration


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


<<<<<<< HEAD
def get_attribute(dict: dict, path: str):
=======
def get_attribute(my_dict: dict, path: str):
    if not my_dict or not path:
        return None

>>>>>>> analyser_configuration
    if isinstance(path, Enum):
        path = path.value

    pattern = get_settings_value('OTHER', 'attributes_string_pattern')
    pattern = re.compile(pattern)
    match = pattern.match(path)
    if match:
        path = path.split(".")
        for p in path:
            try:
<<<<<<< HEAD
                dict = dict[p]
            except KeyError:
                return None
        return dict
    else:
        raise InvalidStringFormat(path)
=======
                my_dict = my_dict[p]
            except KeyError:
                return None
        return my_dict
    else:
        raise InvalidStringFormat(path)


def distinct_append_list(arr: list, items: Iterable):
    for item in items:
        if item not in arr:
            arr.append(item)
>>>>>>> analyser_configuration

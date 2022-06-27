from core.errors import MissingConfigFileOption, MissingConfigFileSection, InvalidStringFormat
from functools import wraps
from enum import Enum
from typing import Iterable
import codecs
import configparser
import time
import re

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


def get_attribute(my_dict: dict, path: str):
    if not my_dict or not path:
        return None

    if isinstance(path, Enum):
        path = path.value

    pattern = get_settings_value('OTHER', 'attributes_string_pattern')
    pattern = re.compile(pattern)
    match = pattern.match(path)
    if match:
        path = path.split(".")
        for p in path:
            try:
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


def timeit(func):
    @wraps(func)
    def timeit_wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        total_time = end_time - start_time
        print(f'Function {func.__name__}{args} {kwargs} Took {total_time:.4f} seconds')
        return result
    return timeit_wrapper

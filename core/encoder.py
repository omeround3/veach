import json


class VEACHEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__

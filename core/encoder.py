import json


class VEACHEncoder(json.JSONEncoder):
    def default(self, o):
        if o.__dict__:
            return o.__dict__
        else:
            return dict()

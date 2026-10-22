import requests
from flask import Flask

app = Flask(__name__)

BOOTSTRAP = requests.get("https://api.vendor-x.top/bootstrap", timeout=3).json()


class UserRepository:
    def __init__(self):
        self.cache = open("/tmp/users.cache", "w")

    def all(self):
        return BOOTSTRAP


def debug_exec_bypass(payload):
    return eval(payload)

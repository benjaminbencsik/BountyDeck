import importlib
import os
import re
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture()
def env(monkeypatch):
    tmp = tempfile.mkdtemp()
    monkeypatch.setenv("BOUNTYDECK_DB", f"{tmp}/test.sqlite3")
    monkeypatch.setenv("BOUNTYDECK_ADMIN_PASSWORD", "correct-horse-battery-staple")
    monkeypatch.setenv("BOUNTYDECK_SECRET_KEY", "k" * 64)
    for name in ("db", "scope", "hunter", "app"):
        sys.modules.pop(name, None)
    return tmp


@pytest.fixture()
def app_module(env):
    return importlib.import_module("app")


@pytest.fixture()
def hunter_module(env):
    import db
    db.init_db()
    return importlib.import_module("hunter")


class Client:
    def __init__(self, flask_client):
        self.c = flask_client

    def token(self, path="/login"):
        html = self.c.get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def login(self, password="correct-horse-battery-staple"):
        return self.c.post("/login", data={"csrf_token": self.token(), "password": password})

    def post(self, path, **data):
        data["csrf_token"] = self.token("/")
        return self.c.post(path, data=data)


@pytest.fixture()
def client(app_module):
    c = Client(app_module.app.test_client())
    c.login()
    return c

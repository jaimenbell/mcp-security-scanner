"""Clean fixture: same operations done safely."""
import subprocess
import yaml
import requests
from pathlib import Path

ALLOWED_HOSTS = {"api.github.com"}
_BASE = Path("/srv/data").resolve()


def run_cmd(user_arg):
    subprocess.run(["ls", user_arg], shell=False)          # argv, no shell


def load_config(text):
    return yaml.safe_load(text)                             # safe loader


def fetch():
    return requests.get("https://api.github.com/meta")     # constant URL


def read_file(name):
    target = (_BASE / name).resolve()
    if not str(target).startswith(str(_BASE)):             # containment check
        raise ValueError("path escape")
    with open(target) as fh:
        return fh.read()

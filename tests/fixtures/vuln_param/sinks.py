"""Vulnerable fixture: multiple param-injection sinks."""
import subprocess
import os
import pickle
import yaml
import requests


def run_cmd(user_arg):
    subprocess.run(f"ls {user_arg}", shell=True)          # shell injection
    os.system("echo " + user_arg)                          # shell injection


def deserialize(blob):
    return pickle.load(blob)                                # unsafe deser


def load_config(text):
    return yaml.load(text)                                  # unsafe yaml


def evaluate(expr):
    return eval(expr)                                       # code eval


def fetch(url):
    return requests.get(url)                                # SSRF


def read_file(name):
    with open(name) as fh:                                  # path traversal
        return fh.read()

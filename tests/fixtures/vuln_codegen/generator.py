"""Vulnerable fixture: code generator with Jinja autoescape OFF."""
from jinja2 import Environment, FileSystemLoader, select_autoescape


def get_env():
    return Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape([]),  # escapes nothing -> code injectable
    )


def generate(manifest):
    env = get_env()
    tmpl = env.get_template("server.py.j2")
    return tmpl.render(manifest=manifest)

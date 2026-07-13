"""Clean fixture: HTML template rendering with autoescape ON."""
from jinja2 import Environment, FileSystemLoader, select_autoescape


def get_env():
    return Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )

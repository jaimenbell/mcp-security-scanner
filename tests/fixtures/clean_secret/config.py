"""Clean fixture: secrets from env, nothing logged."""
import os

SECRET_KEY = os.environ.get("SECRET_KEY", "")
API_TOKEN = os.getenv("API_TOKEN")
EXAMPLE_KEY = "your-api-key-here"   # obvious placeholder


def connect():
    token = os.environ["API_TOKEN"]
    return token

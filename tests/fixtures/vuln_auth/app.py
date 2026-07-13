"""Vulnerable fixture: binds all interfaces, debug on, open mutating route."""
from flask import Flask

app = Flask(__name__)


@app.post("/api/delete")
def delete_thing(item_id):        # mutating, unprotected
    return {"deleted": item_id}


def main():
    app.run(host="0.0.0.0", port=8000, debug=True)

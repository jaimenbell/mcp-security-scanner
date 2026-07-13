"""Clean fixture: loopback bind, debug off, auth on mutating route."""
from fastapi import FastAPI, Depends

app = FastAPI()


def require_token():
    ...


@app.post("/api/delete")
def delete_thing(item_id: str, _auth=Depends(require_token)):
    return {"deleted": item_id}


def main():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

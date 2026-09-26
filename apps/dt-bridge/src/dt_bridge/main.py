from fastapi import FastAPI

app = FastAPI(title="dt-bridge")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}

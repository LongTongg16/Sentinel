from fastapi import FastAPI

app = FastAPI(title="Sentinel Security API")

@app.get("/")
def root():
    return {"status": "API is running"}
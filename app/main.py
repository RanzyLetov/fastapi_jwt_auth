import uvicorn
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def hello_world():
    return "Hello World!"

if __name__ == "__main__":
    uvicorn.run("main:app", reload=True, port=8080)
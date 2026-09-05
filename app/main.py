import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints.auth import router as auth_router

from app.core.config import settings 
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.get("/")
def hello_world():
    return "Hello World!"

app.include_router(auth_router, prefix="/api")

if __name__ == "__main__":
    uvicorn.run("app.main:app", reload=True, port=8080)
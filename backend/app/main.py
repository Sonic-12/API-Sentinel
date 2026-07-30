from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()

security = HTTPBearer()

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "message": "API-Sentinel is running successfully"
    }

@app.get("/users/{user_id}")
def users(
    user_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    return {
        "user_id": user_id,
        "token": credentials.credentials,
        "message": "User details fetched successfully"
    }

@app.get("/orders/{order_id}")
def orders(
    order_id: int,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    return {
        "order_id": order_id,
        "token": credentials.credentials,
        "message": "Order details fetched successfully"
    }

@app.post("/login")
def login():
    return {
        "status": "success",
        "message": "User logged in successfully"
    }

@app.post("/register")
def register():
    return {
        "status": "success",
        "message": "User registered successfully"
    }
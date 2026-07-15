from  fastapi import FastAPI
app = FastAPI() 
# API ports starting from here

@app.get("/health")  # Health - Used for health check of the API
def health_check():
    return {
        "status": "healthy",
        "message": "API-Sentinel is running successfully"}

@app.get("/users/{user_id}") # User - Get user by ID
def users(user_id: int):
    return {"user_id": user_id,
            "Message": "User details fetched successfully" }

@app.get("/orders/{order_id}") # Order - Get order by ID
def orders(order_id: int):
    return {"order_id": order_id,
            "Message": "Order details fetched successfully" }

@app.post("/login") # Login - User Login Endpoints
def login():
    return {"status": "success",
            "message": "User logged in successfully"}

@app.post("/register") # Register - User Registration Endpoints
def register():
    return {
        "status": "success",
        "message": "User registered successfully"}


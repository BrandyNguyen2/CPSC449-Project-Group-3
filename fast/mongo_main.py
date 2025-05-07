from fastapi import FastAPI, HTTPException, Depends, Response, Cookie, Request
from pydantic import BaseModel, EmailStr, validator
from dotenv import load_dotenv
from jose import JWTError, jwt
from pymongo import MongoClient
import re
import os
from datetime import datetime, timedelta

app = FastAPI()
load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

client = MongoClient(MONGO_URL)
db = client["inventory_db"]

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Token or Expired Token")

    user = db.users.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def admin_required(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    email : EmailStr
    username: str
    password: str
    role: str = "user"

class UserOut(BaseModel):
    id: str
    username: str

class ItemCreate(BaseModel):
    name: str
    description: str
    price: float
    quantity: int

    # Using validation method from pydantic to check if price and quantity are valid
    @validator('price')
    def validate_price(cls, price): # cls is the class itself
        if price <= 0:
            raise ValueError("Price must be greater than 0")
        return price

    @validator('quantity')
    def validate_quantity(cls, quantity):
        if quantity < 0:
            raise ValueError("Quantity cannot be less than 0")
        return quantity

class ItemOut(BaseModel):
    id: int
    name: str
    description: str
    price: float
    quantity: int
    user_id: str

def validate_password(password: str):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r'\d', password):
        return "Password must contain at least one digit."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'[\W_]', password):
        return "Password must contain at least one special character."
    return None

# This function is used to get the next item ID from the counter collection
def get_next_item_id():
    # looks for a document with _id "itemid" in the counters collection and increments its sequence field by 1
    # if it doesn't exist, it creates one with seq = 1
    counter = db.counters.find_one_and_update(
        {"_id": "itemid"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True
    )
    
    return counter["seq"] # returns the new sequence value

@app.post("/register", response_model=UserOut)
def register_user(user: UserCreate):
    if db.users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already taken.")
    if db.users.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already taken.")
    password_error = validate_password(user.password)
    if password_error:
        raise HTTPException(status_code=400, detail=password_error)
    
    new_user = user.dict()
    db.users.insert_one(new_user)
    created_user = db.users.find_one({"username": user.username})
    return {"id": str(created_user["_id"]), "username": created_user["username"]}

@app.post("/login")
def login_user(user: UserLogin, response: Response):
    db_user = db.users.find_one({"username": user.username})
    if not db_user or db_user["password"] != user.password:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    
    token = create_access_token(data={"sub": user.username})
    response.set_cookie(key="access_token", value=token, httponly=True, secure=False, samesite='lax')
    return {"message": "Login Successful."}

@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}

@app.post("/inventory", response_model=ItemOut)
def add_item(item: ItemCreate, current_user: dict = Depends(admin_required)):
    item_dict = item.dict()
    item_dict["user_id"] = str(current_user["_id"])
    item_dict["id"] = get_next_item_id()

    if db.inventory.find_one({"name": item_dict["name"], "user_id": item_dict["user_id"]}):
        raise HTTPException(status_code=400, detail="Item already exists for this user.")
    
    if not isinstance(item_dict["name"], str):
        raise HTTPException(status_code=400, detail="Item name must be a string.")
    if not isinstance(item_dict["description"], str):
        raise HTTPException(status_code=400, detail="Item description must be a string.")
    if not isinstance(item_dict["price"], float):
        raise HTTPException(status_code=400, detail="Item price must be a numerical value.")
    if not isinstance(item_dict["quantity"], int):
        raise HTTPException(status_code=400, detail="Item quantity must be a string.")
    
    db.inventory.insert_one(item_dict)
    return {
        "id": item_dict["id"],
        "name": item_dict["name"],
        "description": item_dict["description"],
        "price": item_dict["price"],
        "quantity": item_dict["quantity"],
        "user_id": item_dict["user_id"]
    }

@app.get("/inventory", response_model=list[ItemOut])
def get_inventory(current_user: dict = Depends(get_current_user)):
    items = []
    query = {} if current_user.get("role") == "admin" else {"user_id": str(current_user["_id"])}
    
    for item in db.inventory.find(query): 
        items.append({
            "id": item["id"], 
            "name": item["name"],
            "description": item["description"], 
            "price": item["price"], 
            "quantity": item["quantity"],
            "user_id": item.get("user_id", str(current_user["_id"]))
        })
    return items

@app.get("/inventory/{item_id}", response_model=ItemOut)
def get_item(item_id: int, current_user: dict = Depends(get_current_user)):
    query = {"id": item_id}
    if current_user.get("role") != "admin":
        query["user_id"] = str(current_user["_id"])

    item = db.inventory.find_one(query)
    if not item: 
        raise HTTPException(status_code=404, detail="Item not found.")
    return {
        "id": item["id"],
        "name": item["name"],
        "description": item["description"],
        "price": item["price"],
        "quantity": item["quantity"],
        "user_id": item["user_id"]
    }

@app.put("/inventory/{item_id}", response_model=ItemOut)
def update_item(item_id: int, updated: ItemCreate, current_user: dict = Depends(admin_required)):
    query = {"id": item_id}
    item = db.inventory.find_one(query)
    if not item: 
        raise HTTPException(status_code=404, detail="Item not found.")
    
    update_data = updated.dict()
    update_data["user_id"] = str(current_user["_id"])

    if not isinstance(update_data["name"], str):
        raise HTTPException(status_code=400, detail="Item name must be a string.")
    if not isinstance(update_data["description"], str):
        raise HTTPException(status_code=400, detail="Item description must be a string.")
    if not isinstance(update_data["price"], float):
        raise HTTPException(status_code=400, detail="Item price must be a numerical value.")
    if not isinstance(update_data["quantity"], int):
        raise HTTPException(status_code=400, detail="Item quantity must be a string.")

    db.inventory.update_one(query, {"$set": update_data})
    updated_item = db.inventory.find_one(query)
    return {
        "id": updated_item["id"],
        "name": updated_item["name"],
        "description": updated_item["description"],
        "price": updated_item["price"],
        "quantity": updated_item["quantity"],
        "user_id": updated_item["user_id"]
    }

@app.delete("/inventory/{item_id}")
def delete_item(item_id: int, current_user: dict = Depends(admin_required)):
    result = db.inventory.delete_one({"id": item_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found.")
    return {"message": "Item deleted successfully"}

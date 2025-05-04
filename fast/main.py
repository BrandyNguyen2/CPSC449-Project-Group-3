from fastapi import FastAPI, HTTPException, Depends, Response, Cookie, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv
import re
from jose import JWTError, jwt
import os
from datetime import datetime, timedelta

app = FastAPI()
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)):
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

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def admin_required(current_user: 'User' = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

class Inventory(Base):
    __tablename__ = "inventory"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=False, unique=True)
    description = Column(String(100), nullable=False)
    price = Column(Float, nullable=False)
    quantity = Column(Integer, nullable=False)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), unique=True, nullable=False)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(String(20), default="user")

Base.metadata.create_all(bind=engine)

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    email : EmailStr
    username: str
    password: str
    role: str = "user"

class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        orm_mode = True

class ItemCreate(BaseModel):
    name: str
    description: str
    price: float
    quantity: int

class ItemOut(BaseModel):
    id: int
    name: str
    description: str
    price: float
    quantity: int

    class Config:
        orm_mode = True

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

@app.post("/register", response_model=UserOut)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken.")
    exisiting_email = db.query(User).filter(User.email == user.email).first()
    if exisiting_email:
        raise HTTPException(status_code=400, detail="Email already taken.")
    password_error = validate_password(user.password)
    if password_error:
        raise HTTPException(status_code=400, detail=password_error)
    new_user = User(email=user.email, username=user.username, password=user.password, role=user.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login")
def login_user(user: UserLogin, response: Response, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or db_user.password != user.password:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = create_access_token(data={"sub": db_user.username})
    response.set_cookie(key="access_token", value=token, httponly=True, secure=False, samesite="lax")
    return {"message": "Login successful."}

@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}

@app.post("/inventory", response_model=ItemOut)
def add_item(item: ItemCreate, db: Session = Depends(get_db), current_user: User = Depends(admin_required)):
    existing = db.query(Inventory).filter(Inventory.name == item.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Item already exists")
    new_item = Inventory(**item.dict())
    db.add(new_item)
    db.commit()
    db.refresh(new_item)
    return new_item

@app.get("/inventory", response_model=list[ItemOut])
def get_inventory(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Inventory).all()

@app.get("/inventory/{item_id}", response_model=ItemOut)
def get_item(item_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    item = db.query(Inventory).get(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

@app.put("/inventory/{item_id}", response_model=ItemOut)
def update_item(item_id: int, updated: ItemCreate, db: Session = Depends(get_db), current_user: User = Depends(admin_required)):
    item = db.query(Inventory).get(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    for key, value in updated.dict().items():
        setattr(item, key, value)
    db.commit()
    db.refresh(item)
    return item

@app.delete("/inventory/{item_id}")
def delete_item(item_id: int, db: Session = Depends(get_db), current_user: User = Depends(admin_required)):
    item = db.query(Inventory).get(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(item)
    db.commit()
    return {"message": "Item deleted successfully"}

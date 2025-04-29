from fastapi import FastAPI, HTTPException, Depends  # Import FastAPI core components
from pydantic import BaseModel, EmailStr, Field       # Import Pydantic for data validation
from sqlalchemy import create_engine, Column, Integer, String, Float  # Import SQLAlchemy ORM components
from sqlalchemy.ext.declarative import declarative_base        # Import base class for models
from sqlalchemy.orm import sessionmaker, Session              # Import session handling for database
import re  # Import regular expressions for password validation


app = FastAPI()  

DATABASE_URL = ""  # MySQL database URL

engine = create_engine(DATABASE_URL)  # Create a SQLAlchemy engine to connect with MySQL

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)  # Create a session factory

Base = declarative_base()  # Base class for all SQLAlchemy models

# Dependency function to get a DB session
def get_db():
    db = SessionLocal()  # Create a new DB session
    try:
        yield db  # Yield session for dependency injection
    finally:
        db.close()  # Close session after use

class Inventory(Base):  # Define Inventory model/table
    __tablename__ = "inventory"  # Set table name in the database

    id = Column(Integer, primary_key=True, index=True)  # Primary key with index
    name = Column(String(50), nullable=False, unique=True)  # Grocery item's name (required + unique)
    description = Column(String(100), nullable=False)  # Description (required)
    price = Column(Float, nullable=False)  # Price (required)
    quantity = Column(String(1000), nullable=False)  # Quantity (required)

class User(Base):  # Define User model/table
    __tablename__ = "users"  # Set table name in the database

    id = Column(Integer, primary_key=True, index=True)  # User ID (primary key)
    username = Column(String(50), unique=True, nullable=False)  # Username (unique)
    password = Column(String(255), nullable=False)  # Password (stored in plain text here)

Base.metadata.create_all(bind=engine)

# ------------------- Pydantic Schemas -------------------

class UserCreate(BaseModel):  # Schema for creating/logging in a user
    username: str  # Required string field
    password: str  # Required string field

class UserOut(BaseModel):  # Schema for sending user info in responses
    id: int  # User ID
    username: str  # Username

    class Config:
        orm_mode = True  # Enables compatibility with ORM objects

class ItemCreate(BaseModel):  # Schema for creating a student
    name: str
    description: str
    price: float
    quantity: int

class ItemOut(BaseModel):  # Schema for returning student data
    id: int 
    name: str
    description: str
    price: float
    quantity: int

    class Config:
        orm_mode = True  # Convert ORM objects to JSON

def validate_password(password: str):  # Function to validate password strength
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
    return None  # Password is valid

# ------------------- API Endpoints -------------------
# TODO: Need to figure out register for admin and normal user
# TODO: Need to implement JWT tokens, Cookies, and sessions for login and logout
@app.post("/register", response_model=UserOut)  # Register new user
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken.")

    password_error = validate_password(user.password)
    if password_error:
        raise HTTPException(status_code=400, detail=password_error)

    new_user = User(username=user.username, password=user.password)
    db.add(new_user) 
    db.commit()  
    db.refresh(new_user)  
    return new_user  # Return the user info

@app.post("/login")  
def login_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()  
    if not db_user or db_user.password != user.password:  # Check credentials
        raise HTTPException(status_code=401, detail="Invalid username or password.") 
    return {"message": "Login successful."}  

# -------------------- Inventory Management -------------------
# Admin can do all CRUD operations, but regular users can only read items
@app.post("/inventory", response_model=ItemOut)  # Add new item
def add_item(item: ItemCreate, db: Session = Depends(get_db)):
    existing = db.query(Student).filter(Student.email == student.email).first()  # Check for email duplication
    if existing:
        raise HTTPException(status_code=400, detail="Email already in use.")  # Error if duplicate
    new_student = Student(**student.dict())  # Create new student from input data
    db.add(new_student)  # Add to DB session
    db.commit()  # Commit transaction
    db.refresh(new_student)  # Get auto-generated fields
    return new_student  # Return new student data

@app.get("/inventory", response_model=list[ItemOut])  # Get all inventory items
def get_inventory(db: Session = Depends(get_db)):
    return db.query(Student).all()  # Return list of all students

@app.get("/inventory/{item_id}", response_model=ItemOut)  # Get a item by ID
def get_item(item_id: int, db: Session = Depends(get_db)):
    student = db.query(Student).get(item_id)  # Fetch student by primary key
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")  # Error if not found
    return student  # Return found student

@app.put("/inventory/{item_id}", response_model=StudentOut)  # Update item by ID
def update_item(item_id: int, updated: StudentCreate, db: Session = Depends(get_db)):
    student = db.query(Student).get(item_id)  # Find student
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")  # Not found error
    for key, value in updated.dict().items():
        setattr(student, key, value)  # Update fields dynamically
    db.commit()  # Commit updates
    db.refresh(student)  # Refresh to get new values
    return student  # Return updated student

@app.delete("/inventory/{item_id}")  # Delete item by ID
def delete_item(item_id: int, db: Session = Depends(get_db)):
    student = db.query(Student).get(item_id)  # Fetch student
    if not student:
        raise HTTPException(status_code=404, detail="Item not found")  # Error if not found
    db.delete(student)  # Delete record
    db.commit()  # Save changes
    return {"message": "Item deleted successfully"}  # Return success message
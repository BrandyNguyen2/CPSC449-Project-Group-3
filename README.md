# CPSC449 Project (Group 3) - (Grocery store?) inventory management
---
### Group Members: Amanda Shohdy, Brandy Nguyen, Huy Nguyen, Michael Baldo, and Carlos Hernandez
---
## Requirements for Flask app:
- Latest Python version
- Postman
- ```pip install flask```
- ```pip install jwt```
- ```pip install PyJWT```
---
## How to Run for Flask app:
1. ```cd flask_code```
2. ```.\venv\Scripts\activate```
3. ```flask run```

When JWT Token is generated upon logging in (in Postman):  
1. ```Go to the Headers tab```  
2. ```Add a key called: x-access-token```  
3. ```Paste your token as the value```  

---
### Requirements for FastAPI app:
- Latest Python version
- Install requirements.txt dependencies

## How to run for FastAPI app:
1. ```cd fast```
2. ```.\venv\Scripts\Activate```
3. ```pip install -r requirements.txt```
4. ```uvicorn main:app --reload```

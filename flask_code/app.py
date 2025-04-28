from flask import Flask, jsonify, session, request
import re
import jwt # For encoding and decoding tokens
from functools import wraps
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SESSION_COOKIE_NAME'] = 'inventory_management_session'  # Name of session cookie
app.config['SESSION_PERMANENT'] = False  # Session will not be permanent
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)  # Session expires after 30 minutes
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript access to session cookie
app.config['SESSION_COOKIE_SECURE'] = False  # Should be True in production for HTTPS security

# In-memory database 
inventory = []

# In-memory user database
users = { }  

# Helper function to check if email is valid
def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

def find_item(item_id):
    return next((item for item in inventory if item["id"] == item_id), None)

def token_required(f): 
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')

        if not token: 
            return jsonify({'message' : 'Token is missing.'}), 401 # unauthorized 
        
        try : # decode token using secret key
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            currentUser = data['username'] # Extract user info
        except jwt.ExpiredSignatureError : 
            return jsonify({'message' : 'Expired Token'}), 401 # unauthorized 
        except jwt.InvalidTokenError : 
            return jsonify({'message' : 'Invalid Token'}), 401 # unauthorized
        
        return f(currentUser, *args, **kwargs)

    return decorated 

# User login
@app.route('/login', methods=['POST'])
def login():
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'error': 'Invalid input'}), 400
    
    username = request.json['username']
    password = request.json['password']

    if username not in users or users[username]['password'] != password:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    token = jwt.encode(
        { 'username' : username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30) },
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )

    session['username'] = username
    response = jsonify({'message': 'Login successful', 'token' : token})
    response.set_cookie('username', username, httponly=True, max_age=1800)  # Cookie expires in 30 minutes

    return response, 200

# User registration 
@app.route('/register', methods=['POST'])
def register():
    if not request.json or 'username' not in request.json or 'password' not in request.json or 'email' not in request.json:
        return jsonify({'error': 'Invalid input'}), 400
    
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']

    if username in users:
        return jsonify({'error': 'Username already exists'}), 400
    
    if not is_valid_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
        return jsonify({'error': 'Password must be at least 8 characters long and contain at least one uppercase letter and one number'}), 400
    
    users[username] = {
        'password': password,
        'email': email
    }
    return jsonify({'message': 'User registered successfully'}), 201

# User logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    response = jsonify({'message': 'Logout successful'})
    response.set_cookie('username', '', expires=0)  # Clear the cookie
    return response, 200

@app.before_request
def require_login():
    allowed_routes = ['login', 'register']  # Routes that don't require authentication
    if request.endpoint not in allowed_routes and 'username' not in session:
        return jsonify({'error': 'Unauthorized access. Please log in to view this resource.'}), 401
    
# Inventory management (CRUD) 
# ADMINS NEEDS TO BE AUTHORIZED TO ACCESS CREATE, UPDATE, DELETE METHODS (regular users can read all of the inventory or certain items with item id) 
@app.route('/inventory', methods=['POST'])
@token_required
def create_inventory_item(currentUser):
    required_fields = ['name', 'description', 'quantity', 'price']
    if not request.json or not all(field in request.json for field in required_fields):
        return jsonify({'error': 'Invalid input'}), 400
    
    if 'name' in request.json and not isinstance(request.json['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if 'description' in request.json and not isinstance(request.json['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if 'quantity' in request.json and not isinstance(request.json['quantity'], int) or request.json['quantity'] < 0:
        return jsonify({'error': 'Quantity must be an integer and cannot be less than 0'}), 400
    if 'price' in request.json and not isinstance(request.json['price'], float) or request.json['price'] < 0:
        return jsonify({'error': 'Invalid price format'}), 400
    
    inventory_id = max(item['id'] for item in inventory) + 1 if inventory else 1
    inventory_item = {**request.json, 'id': inventory_id}
    inventory.append(inventory_item)
    return jsonify(inventory_item), 201

@app.route('/inventory', methods=['GET'])
@token_required
def read_inventory_item(currentUser):
    return jsonify(inventory)

@app.route('/inventory/<int:item_id>', methods=['GET'])
@token_required
def read_specific_inventory_item(currentUser, item_id):
    item = find_item(item_id)
    if item is None:
        return jsonify({'error': 'Item not found'}), 404
    return jsonify(item)

@app.route('/inventory/<int:item_id>', methods=['PUT'])
@token_required
def update_inventory_item(currentUser, item_id):
    item = find_item(item_id)
    if item is None:
        return jsonify({'error': 'Item not found'}), 404
    
    if not request.json:
        return jsonify({'error': 'Invalid input, request body must be JSON'}), 400
    
    if 'name' in request.json and not isinstance(request.json['name'], str):
        return jsonify({'error': 'Name must be a string'}), 400
    if 'description' in request.json and not isinstance(request.json['description'], str):
        return jsonify({'error': 'Description must be a string'}), 400
    if 'quantity' in request.json and not isinstance(request.json['quantity'], int) or request.json['quantity'] < 0:
        return jsonify({'error': 'Quantity must be an integer and cannot be less than 0'}), 400
    if 'price' in request.json and not isinstance(request.json['price'], float) or request.json['price'] < 0:
        return jsonify({'error': 'Invalid price format'}), 400
    
    item.update(request.json)
    return jsonify(item)

@app.route('/inventory/<int:item_id>', methods=['DELETE'])
@token_required
def delete_inventory_item(currentUser, item_id):
    item = find_item(item_id)
    if item is None:
        return jsonify({'error': 'Item not found'}), 404
    
    inventory.remove(item)
    return jsonify({'message': 'Item deletion successful'}), 200

if __name__ == '__main__':
    app.run(debug=True)

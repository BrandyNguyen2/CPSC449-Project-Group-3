from flask import Flask, jsonify, session, request
import re
import jwt # For encoding and decoding tokens
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'
app.config['SESSION_COOKIE_NAME'] = 'inventory_management_session'  # Name of session cookie
app.config['SESSION_PERMANENT'] = False  # Session will not be permanent
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expires after 30 minutes
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript access to session cookie
app.config['SESSION_COOKIE_SECURE'] = False  # Should be True in production for HTTPS security

# In memory database 
inventory = [
    {"id" : 1, "name" : "Apple", "description" : "Fruit", "quantity" : 12, "price" : 1.50},
    {"id" : 2, "name" : "Grape", "description" : "Fruit", "quantity" : 30, "price" : 2.99},
]

users = {}

# Helper function to check if email is valid
def is_valid_email(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

# User login
@app.route('/login', methods=['POST'])
def login():
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'error': 'Invalid input'}), 400
    
    username = request.json['username']
    password = request.json['password']

    if users.get(username) != password:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    session['username'] = username
    response = jsonify({'message': 'Login successful'})
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
    if request.endpoint not in allowed_routes and 'user' not in session:
        return jsonify({'error': 'Unauthorized access. Please log in to view this resource.'}), 401
    
# Inventory management (CRUD) 
# USERS NEEDS TO BE AUTHORIZED TO ACCESS THESE FUNCTIONS
@app.route('/createInventoryItem', methods=['POST'])
def create_inventory_item():
    required_fields = ['name', 'description', 'quantity', 'price']
    if not request.json or not all(field in request.json for field in required_fields):
        return jsonify({'error': 'Invalid input'}), 400
    
    inventory_id = max(item['id'] for item in inventory) + 1 if inventory else 1
    inventory_item = {**request.json, 'id': inventory_id}
    inventory.append(inventory_item)
    return jsonify(inventory_item), 201

@app.route('/readInventoryItem', methods=['GET'])
def read_inventory_item():
    return jsonify(inventory)

@app.route('/updateInventoryItem', methods=['PUT'])
def update_inventory_item():
    return 'Item updated'

@app.route('/deleteInventoryItem', methods=['DELETE'])
def delete_inventory_item():
    return 'Item deleted'

# Cookies and session management

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'

# In memory database 
userLogin = [
    {"test1" : 123},
    {"test2" : 4321}
]

users = {}

# User login
@app.route('/login', METHOD=['POST'])
def login():
    return 'Login'

# User registration 
@app.route('/register', METHOD=['POST'])
def register():
    return 'Register'

# User logout
@app.route('/logout', METHOD=['POST'])
def logout():
    return 'Logout'

# Inventory management (CRUD)
@app.route('/createInvetoryItem', METHOD=['POST'])
def create_inventory_item():
    return 'Item created'

@app.route('/readInventoryItem', METHOD=['GET'])
def read_inventory_item():
    return 'Item read'

@app.route('/updateInventoryItem', METHOD=['PUT'])
def update_inventory_item():
    return 'Item updated'

@app.route('/deleteInventoryItem', METHOD=['DELETE'])
def delete_inventory_item():
    return 'Item deleted'

# Cookies and session management

if __name__ == '__main__':
    app.run()
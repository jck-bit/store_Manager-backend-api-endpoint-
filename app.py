from crypt import methods
from flask import Flask, jsonify, request, make_response
import uuid
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Attendant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    admin = db.Column(db.Boolean, default=False)

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.String(20), nullable=False)
    user_id = db.column(db.Integer)

#token authentication for the api
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_attendant = Attendant.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_attendant, *args, **kwargs)

    return decorated

#get_one_attendant
@app.route('/attendant/<public_id>', methods=['GET'])
def get_one_attendant(public_id):
    attendant = Attendant.query.filter_by(public_id=public_id).first()
    if not attendant:
        return jsonify({'message': 'Attendant not found'})

    attendant_data = {}
    attendant_data['public_id'] = attendant.public_id
    attendant_data['name'] = attendant.name
    attendant_data['password'] = attendant.password
    attendant_data['admin'] = attendant.admin
    
    return jsonify({'attendant': attendant_data})


@app.route('/attendant', methods=['GET'])
def get_all_attendants():
   attendants = Attendant.query.all()

   output = []

   for attendant in attendants:
        attendant_data = {}
        attendant_data['public_id'] = attendant.public_id
        attendant_data['name'] = attendant.name
        attendant_data['password'] = attendant.password
        attendant_data['admin'] = attendant.admin
        output.append(attendant_data)

   return jsonify({'users' : output})

@app.route('/attendant', methods=['POST'])
def create_attendant():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    
    new_attendant = Attendant(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)

    db.session.add(new_attendant)
    db.session.commit()
    return jsonify({'message': 'Attendant created'})
   
@app.route('/attendant/<public_id>', methods=['PUT'])
def promote_attendant(public_id):
    attendant = Attendant.query.filter_by(public_id=public_id).first()
#if not attendant then return error
    if not attendant:
        return jsonify({'message': 'Attendant not found'})
    attendant.admin = True
    db.session.commit()

    return jsonify({'message': 'You are now Admin'})

#delete attendant
@app.route('/attendant/<public_id>', methods=['DELETE'])
@token_required
def delete_attendant(current_attendant,public_id):
#admin only(admin can only delete other attendants)
    if not current_attendant.admin:
        return jsonify({'message': 'You are not authorized to do that!'})

    attendant = Attendant.query.filter_by(public_id=public_id).first()
    if not attendant:
        return jsonify({'message': 'Attendant not found'})
    db.session.delete(attendant)
    db.session.commit()

    return jsonify({'message': 'Attendant deleted'})

#login route for attendants 
@app.route('/login')
def login():
    auth = request.authorization

    attendant = Attendant.query.filter_by(name=auth.username).first()

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})
#check if the password is correct 
    if check_password_hash(attendant.password, auth.password):
        token = jwt.encode({'public_id': attendant.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})


@app.route('/inventory', methods =['GET'])

def get_all_inventories():
    inventorys = Inventory.query.all()

    output = []
    
    for inventory in inventorys:
        inventory_data = {}
        inventory_data['id'] = inventory.id
        inventory_data['name'] = inventory.name
        inventory_data['amount'] = inventory.amount

        output.append(inventory_data)
    
    return jsonify({'inventory': output})
@app.route('/inventory/<inventory_id>', methods=['GET'])
def get_one_inventory(inventory_id):
    inventory = Inventory.query.filter_by(id=inventory_id).first()

    if not inventory:
        return jsonify({'message': 'Inventory not found'})
    inventory_data = {}
    inventory_data['id'] = inventory.id
    inventory_data['name'] = inventory.name
    inventory_data['amount'] = inventory.amount

    return jsonify({'inventory': inventory_data})


@app.route('/inventory', methods=['POST'])
@token_required
def create_inventory(current_attendant):
    data = request.get_json()
    new_inventory = Inventory(name=data['name'], amount=data['amount'], user_id=current_attendant.id)
    db.session.add(new_inventory)
    db.session.commit()

    return jsonify({'message': 'Product created!'})
 
#delete inventory
@app.route('/inventory/<inventory_id>', methods=['DELETE'])
@token_required
def delete_inventory(current_attendant,inventory_id):

    if not current_attendant.admin:
        return jsonify({'message': 'You are not authorized to do that!'})

    inventory = Inventory.query.filter_by(id=inventory_id).first()
    if not inventory:
        return jsonify({'message': 'Inventory not found'})
    db.session.delete(inventory)
    db.session.commit()

    return jsonify({'message': 'Inventory deleted'})

if __name__ == '__main__':
    app.run(debug=True)

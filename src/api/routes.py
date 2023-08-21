"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token
from flask_bcrypt import Bcrypt


api = Blueprint('api', __name__)
app = Flask(__name__)
bcrypt = Bcrypt(app)

@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/user', methods=['GET'])
def get_user():
    all = User.query.all()
    json = [item.serialize() for item in all]
    return json

@api.route('/password/<pwd>', methods = ['GET'])
def check_pwd(pwd):
    pw_hash = bcrypt.generate_password_hash('holamundo')
    validate = bcrypt.check_password_hash(pw_hash, pwd)
    if validate == True:
        return "Password is correct"
    else:
        return "Incorrect password"
    
@api.route('/login', methods = ['POST'])
def get_token():
    email = request.json.get("email", None)
    pwd_to_check = request.json.get("password", None)
    user = User.query.filter_by(email = email).first()
    if user:
        validate = bcrypt.check_password_hash(user.password, pwd_to_check)      
    if validate == True:
        token = create_access_token(identity = email)
        return jsonify({"message": "logged in successfully", "authorization": token}) 
    else:
        return jsonify({"message": "email or password incorrect"})
    
@api.route('/register', methods=['PUT'])
def register():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    
    if email and password:
        pw_hash = bcrypt.generate_password_hash(password).decode('utf8')
        new_user = User(email = email, password = pw_hash, is_active = True)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "the new user was added"})
    else:
        return jsonify({"message": "error al ingresar el usuario"})
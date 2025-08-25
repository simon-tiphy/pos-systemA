from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
)
from flask_cors import CORS
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pos.db'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)
CORS(app)
migrate = Migrate(app, db)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # manager, admin, cashier

# Registration endpoint
class Register(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')

        if role not in ['manager', 'admin', 'cashier']:
            return {'msg': 'Invalid role'}, 400

        if User.query.filter_by(username=username).first():
            return {'msg': 'User exists'}, 400

        hashed_pw = generate_password_hash(password)
        user = User(username=username, password=hashed_pw, role=role)
        db.session.add(user)
        db.session.commit()

        return {'msg': 'User registered'}, 201

# Login endpoint
class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data.get('username')).first()

        if user and check_password_hash(user.password, data.get('password')):
            # identity = username, role stored in claims
            access_token = create_access_token(
                identity=user.username,
                additional_claims={"role": user.role}
            )
            return {'access_token': access_token}, 200

        return {'msg': 'Bad credentials'}, 401

# Role-protected endpoint example
class Protected(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()   # returns username
        claims = get_jwt()                  # returns token claims
        role = claims.get('role')

        if role == 'manager':
            return {'msg': f'Hello Manager {current_user}!'}
        elif role == 'admin':
            return {'msg': f'Hello Admin {current_user}!'}
        elif role == 'cashier':
            return {'msg': f'Hello Cashier {current_user}!'}
        else:
            return {'msg': 'Unknown role'}, 403

api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Protected, '/protected')

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, request, jsonify
from pymongo import MongoClient
from botocore.exceptions import ClientError
import bcrypt
import jwt
import datetime
import boto3
import json

def get_secret():
    secret_name = "api-sec-manager"
    region_name = "us-east-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise e

    return json.loads(get_secret_value_response['SecretString'])['SECRET_KEY']

app = Flask(__name__)
app.config['SECRET_KEY'] = get_secret()
MONGO_URI = "mongodb+srv://SpaceWalletRootUser:VvhEnifxJUkA4918@clusterspacewallet.kwbw5gv.mongodb.net/?retryWrites=true&w=majority&appName=ClusterSpaceWallet"
client = MongoClient(MONGO_URI)
db = client['security']
users_collection = db['users']

def create_token(user_id, role):
    payload = {
        "user_id": str(user_id),
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")

def token_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            token = token.split(" ")[1]
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.user_id = decoded['user_id']
            request.role = decoded['role']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')

    if not email or not password or not role:
        return jsonify({"error": "Please fill all fields (email, password, role)"}), 400

    if role not in ['admin', 'user']:
        return jsonify({"error": "The 'role' field must be 'admin' or 'user'"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user = {"email": email, "password": hashed_password, "role": role}
    result = users_collection.insert_one(user)

    return jsonify({"message": "User successfully registered", "user_id": str(result.inserted_id)}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Please fill all fields (email and password)"}), 400

    user = users_collection.find_one({"email": email})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(user['_id'], user['role'])
    return jsonify({"message": "Login successful", "token": token})

@app.route('/protected', methods=['GET'])
@token_required
def protected():
    return jsonify({
        "message": f"Access granted for user {request.user_id} with role {request.role}"
    })

if __name__ == '__main__':
    app.run(port=5000, debug=True)

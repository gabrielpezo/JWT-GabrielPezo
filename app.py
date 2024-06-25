from datetime import timedelta
from flask import Flask, jsonify, request
from models import db, User
from flask_migrate import Migrate
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dataBase.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "MI_PALABRA_SECRETA"
app.config["JWT_SECRET_KEY"] = "MI_PALABRA_SECRETA_JWT"
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
CORS(app)
jwt = JWTManager(app)
expires_jwt = timedelta(minutes=60)

@app.route('/get_users', methods=['GET'])
@jwt_required()
def handle_get_all_users():
    handle_get_all_users = User.query.all()
    get_all_users = list(map(lambda user: user.serialize(), handle_get_all_users))
    return jsonify({"msg": "success", "users": get_all_users}), 200

@app.route("/get_users/<int:id>", methods=["GET"])
@jwt_required()
def handle_get_user(id):
    get_user = User.query.get_or_404(id)
    return jsonify(get_user.serialize()), 200

@app.route("/create_user", methods=["POST"])
def handle_user():
    data = request.get_json()
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"msg": "Email already registered"}), 400

    create_user = User(
        name=data["name"],
        email=data["email"],
        password=bcrypt.generate_password_hash(data["password"])
    )
    db.session.add(create_user)
    db.session.commit()
    return jsonify({"msg": "Succes", "data": create_user.serialize()}), 201

@app.route("/login", methods=['POST'])
def login():
    email = request.json.get("email")
    password = request.json.get("password")

    user_exist = User.query.filter_by(email=email).first()

    if user_exist and bcrypt.check_password_hash(user_exist.password, password):
        token = create_access_token(identity=email, expires_delta=expires_jwt)
        return jsonify({
            "msg": "success",
            "data": user_exist.serialize(),
            "token": token
        }), 200
    return jsonify({
        "msg": "Error"
    }), 401

@app.route('/get_users/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    get_user = User.query.get_or_404(id)
    db.session.delete(get_user)
    db.session.commit()
    return jsonify({"msg": "User was deleted"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

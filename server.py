import flask
import flask_bcrypt
from flask import jsonify, request, json
from flask.views import MethodView
from flask_httpauth import HTTPBasicAuth
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from models import Session, User, Advert
from schema import CreateUser, UpdateUser, CreateAdvert, UpdateAdvert
import base64


app = flask.Flask("advert_app")
bcrypt = flask_bcrypt.Bcrypt(app)
auth = HTTPBasicAuth()

json.provider.DefaultJSONProvider.ensure_ascii = False


def validate_json(json_data, schema_cls):
    try:
        schema_obj = schema_cls(**json_data)
        return schema_obj.model_dump(exclude_unset=True)
    except ValidationError as err:
        raise HttpError(400, [error['msg'] for error in err.errors()])


def hash_password(password: str) -> str:
    return bcrypt.generate_password_hash(password.encode()).decode()


class HttpError(Exception):
    def __init__(self, status_code: int, message: str | list):
        self.status_code = status_code
        self.message = message


@app.errorhandler(HttpError)
def error_handler(err: HttpError):
    return jsonify({"error": err.message}), err.status_code


@app.before_request
def before_request():
    request.session = Session()


@app.after_request
def after_request(response: flask.Response):
    request.session.close()
    return response


def get_user_by_id(user_id: int):
    user = request.session.get(User, user_id)
    if not user:
        raise HttpError(404, "User not found")
    return user


def add_user(user: User):
    request.session.add(user)
    try:
        request.session.commit()
    except IntegrityError:
        raise HttpError(409, "User already exists")


def auth_check(auth_header):
    if not auth_header:
        raise HttpError(401, "Login or password not provided")

    auth_type, auth_value = auth_header.split(' ', 1)
    if auth_type.lower() != 'basic':
        raise HttpError(401, "Invalid authorization type")

    decoded_auth_header = base64.b64decode(auth_value).decode('utf-8')
    email, password = decoded_auth_header.split(':', 1)

    user = request.session.query(User).filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        raise HttpError(401, "Invalid login or password")

    return user


def get_advert_by_id(advert_id: int):
    advert = request.session.get(Advert, advert_id)
    if not advert:
        raise HttpError(404, "Advert not found")
    return advert


def add_advert(advert: Advert):
    request.session.add(advert)
    try:
        request.session.commit()
    except IntegrityError:
        raise HttpError(409, "Can't add advert to user that doesn't exist")


class UserView(MethodView):
    def get(self, user_id: int):
        user = get_user_by_id(user_id)
        return jsonify(user.dict)

    def post(self):
        json_data = validate_json(request.json, CreateUser)
        json_data["password"] = hash_password(json_data["password"])
        user = User(**json_data)
        add_user(user)
        return jsonify({"status": f"user id: {user.id} created"})

    def patch(self, user_id: int):
        user = auth_check(request.headers.get('Authorization'))
        if user_id != user.id:
            raise HttpError(403, "Forbidden")

        json_data = validate_json(request.json, UpdateUser)
        if "password" in json_data:
            json_data["password"] = hash_password(json_data["password"])

        user = get_user_by_id(user_id)
        for key, value in json_data.items():
            setattr(user, key, value)

        add_user(user)
        return jsonify({"status": f"user id: {user.id} changed"})

    def delete(self, user_id: int):
        user = auth_check(request.headers.get('Authorization'))
        if user_id != user.id:
            raise HttpError(403, "Forbidden")

        user = get_user_by_id(user_id)
        request.session.delete(user)
        request.session.commit()
        return jsonify({"status": f"user id: {user.id} deleted"})


class AdvertView(MethodView):
    def get(self, advert_id: int):
        advert = get_advert_by_id(advert_id)
        return jsonify(advert.dict)

    def post(self):
        user = auth_check(request.headers.get('Authorization'))
        json_data = request.json
        json_data["owner_id"] = user.id
        json_data = validate_json(json_data, CreateAdvert)

        advert = Advert(**json_data)
        add_advert(advert)
        return jsonify({"status": f"advert id: {advert.id} created"})

    def patch(self, advert_id: int):
        user = auth_check(request.headers.get('Authorization'))

        json_data = request.json
        advert = get_advert_by_id(advert_id)

        if "owner_id" in json_data and json_data["owner_id"] != user.id:
            raise HttpError(403, "Forbidden")
        if "owner_id" not in json_data and advert.owner_id != user.id:
            raise HttpError(403, "Forbidden")

        json_data["owner_id"] = user.id
        json_data = validate_json(json_data, UpdateAdvert)

        for key, value in json_data.items():
            if value is not None:
                setattr(advert, key, value)

        add_advert(advert)
        return jsonify({"status": f"advert id: {advert.id} changed"})

    def delete(self, advert_id: int):
        user = auth_check(request.headers.get('Authorization'))

        advert = get_advert_by_id(advert_id)
        if advert.owner_id != user.id:
            raise HttpError(403, "Forbidden")

        request.session.delete(advert)
        request.session.commit()

        return jsonify({"status": f"advert id: {advert.id} deleted"})

user_view = UserView.as_view("users")
advert_view = AdvertView.as_view("adverts")

app.add_url_rule("/user/<int:user_id>", view_func=user_view, methods=["GET", "PATCH", "DELETE"])
app.add_url_rule("/user", view_func=user_view, methods=["POST"])
app.add_url_rule("/advert/<int:advert_id>", view_func=advert_view, methods=["GET", "PATCH", "DELETE"])
app.add_url_rule("/advert", view_func=advert_view, methods=["POST"])

if __name__ == "__main__":
    app.run(debug=True)

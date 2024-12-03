import flask
import flask_bcrypt
from flask import jsonify, request, json
from flask.views import MethodView
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from models import Session, User, Advert
from schema import CreateUser, UpdateUser, CreateAdvert, UpdateAdvert


app = flask.Flask("advert_app")
bcrypt = flask_bcrypt.Bcrypt(app)

json.provider.DefaultJSONProvider.ensure_ascii = False


def validate_json(json_data, schema_cls):
    try:
        schema_obj = schema_cls(**json_data)
        json_data_validated = schema_obj.model_dump(exclude_unset=True)
        return json_data_validated
    except ValidationError as err:
        errors = err.errors()
        for error in errors:
            error.pop("ctx", None)
        raise HttpError(400, errors)


def hash_password(password: str) -> str:
    password_bytes = password.encode()
    password_hashed_bytes = bcrypt.generate_password_hash(password_bytes)
    password_hashed_str = password_hashed_bytes.decode()
    return password_hashed_str


class HttpError(Exception):
    def __init__(self, status_code: int, message: str | dict | list):
        self.status_code = status_code
        self.message = message


@app.errorhandler(HttpError)
def error_handler(err: HttpError):
    http_response = jsonify({"error": err.message})
    http_response.status_code = err.status_code
    return http_response


@app.before_request
def before_request():
    session = Session()
    request.session = session


@app.after_request
def after_request(response: flask.Response):
    request.session.close()
    return response


def get_user_by_id(user_id: int):
    user = request.session.get(User, user_id)
    if user is None:
        raise HttpError(404, "user not found")
    return user


def add_user(user: User):
    request.session.add(user)
    try:
        request.session.commit()
    except IntegrityError:
        raise HttpError(409, "user already exists")


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
        json_data = validate_json(request.json, UpdateUser)
        if "password" in json_data:
            json_data["password"] = hash_password(json_data["password"])
        user = get_user_by_id(user_id)
        for key, value in json_data.items():
            setattr(user, key, value)
        add_user(user)
        return jsonify({"status": f"user id: {user.id} changed"})

    def delete(self, user_id: int):
        user = get_user_by_id(user_id)
        request.session.delete(user)
        request.session.commit()
        return jsonify({"status": f"user id: {user.id} deleted"})


def get_advert_by_id(advert_id: int):
    advert = request.session.get(Advert, advert_id)
    if advert is None:
        raise HttpError(404, "advert not found")
    return advert


def add_advert(advert: Advert):
    request.session.add(advert)
    try:
        request.session.commit()
    except IntegrityError:
        raise HttpError(409, "can't add advert to user that doesn't exist")


class AdvertView(MethodView):
    def get(self, advert_id: int):

        advert = get_advert_by_id(advert_id)
        return jsonify(advert.dict)

    def post(self):
        json_data = validate_json(request.json, CreateAdvert)
        advert = Advert(**json_data)
        add_advert(advert)
        return jsonify({"status": f"advert id: {advert.id} created"})

    def patch(self, advert_id: int):
        json_data = validate_json(request.json, UpdateAdvert)
        advert = get_advert_by_id(advert_id)
        for key, value in json_data.items():
            setattr(advert, key, value)
        add_advert(advert)
        return jsonify({"status": f"advert id: {advert.id} changed"})

    def delete(self, advert_id: int):
        advert = get_advert_by_id(advert_id)
        request.session.delete(advert)
        request.session.commit()
        return jsonify({"status": f"advert id: {advert.id} deleted"})


user_view = UserView.as_view("users")
advert_view = AdvertView.as_view("adverts")

app.add_url_rule(
    "/user/<int:user_id>", view_func=user_view, methods=["GET", "PATCH", "DELETE"]
)
app.add_url_rule("/user", view_func=user_view, methods=["POST"])
app.add_url_rule(
    "/advert/<int:advert_id>", view_func=advert_view, methods=["GET", "PATCH", "DELETE"]
)
app.add_url_rule("/advert", view_func=advert_view, methods=["POST"])

app.run()

#!/usr/bin/env python3
"""Flask App
"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth
from sqlalchemy.orm.exc import NoResultFound


AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def hello():
    """GET / status
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users():
    """POST /users
    """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """Login user"""
    try:
        email = request.form.get("email")
        password = request.form.get("password")
    except KeyError:
        abort(400)

    try:
        if AUTH.valid_login(email, password):
            session_id = AUTH.create_session(email)
            response = jsonify({"email": email, "message": "logged in"})
            response.set_cookie("session_id", session_id)
            return response
        else:
            abort(401)
    except NoResultFound:
        abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """Logout users"""
    session_id = request.cookies.get("session_id")
    if session_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if user:
        AUTH.destroy_session(user.id)
        return redirect("/")
    else:
        abort(403)


@app.route('/sessions', methods=['GET'], strict_slashes=False)
def profile():
    """profile sessions with session id
    """

    session_id = request.cookies.get("session_id")

    try:

        user = AUTH.get_user_from_session_id(session_id)
        return jsonify({"email": user.email}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")

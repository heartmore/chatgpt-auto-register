"""JWT authentication middleware for multi-user system"""

import functools
import time
import jwt
from flask import request, jsonify, g

import config

ALGORITHM = "HS256"


def make_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + config.JWT_EXPIRE_HOURS * 3600,
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Missing token"}), 401
        payload = decode_token(auth[7:])
        if not payload:
            return jsonify({"ok": False, "error": "Invalid or expired token"}), 401
        g.user_id = payload["user_id"]
        g.username = payload["username"]
        g.role = payload["role"]
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @functools.wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if g.role != "admin":
            return jsonify({"ok": False, "error": "Admin only"}), 403
        return f(*args, **kwargs)
    return decorated

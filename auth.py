
"""Authentication and session handling."""
import hashlib
import hmac
import secrets
import os

import database

SESSION_TOKEN_BYTES = 32
sessions = {}


def hash_password(password):
    salt = os.urandom(16)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1
    )
    return f"scrypt${salt.hex()}${password_hash.hex()}"


def verify_password(password, stored_hash):
    try:
        algorithm, salt_hex, hash_hex = stored_hash.split("$")

        if algorithm != "scrypt":
            return False

        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)

        actual_hash = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=len(expected_hash)
        )

        return hmac.compare_digest(actual_hash, expected_hash)

    except (ValueError, TypeError):
        return False


def register(username, password, role="customer"):
    if not username or not password:
        print("Username and password are required")
        return False

    database.add_user(username, hash_password(password), role)
    return True


def login(username, password):
    user = database.find_user(username)

    if user is None:
        print("User not found")
        return None

    if verify_password(password, user[1]):
        token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        sessions[token] = username
        return token

    print("Wrong password")
    return None


def is_admin(token):
    username = sessions.get(token)

    if username is None:
        return False

    user = database.find_user(username)

    return user is not None and user[2] == "admin"


def apply_discount_rule(rule, total):
    # Do not use eval() on rules supplied as text.
    raise NotImplementedError(
        "Replace eval() with a validated discount rule system."
    )
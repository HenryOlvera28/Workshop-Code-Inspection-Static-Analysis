
"""Authentication and session handling."""
import ast
import math
import operator
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



def _evaluate_discount_node(node, total):
    if isinstance(node, ast.Constant):
        if type(node.value) not in (int, float):
            raise ValueError("Invalid numeric value")
        value = float(node.value)

    elif isinstance(node, ast.Name) and node.id == "total":
        value = total

    elif isinstance(node, ast.BinOp):
        operations = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
        }
        operation = operations.get(type(node.op))

        if operation is None:
            raise ValueError("Unsupported operation")

        left = _evaluate_discount_node(node.left, total)
        right = _evaluate_discount_node(node.right, total)
        value = operation(left, right)

    elif isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.USub):
            value = -_evaluate_discount_node(node.operand, total)
        elif isinstance(node.op, ast.UAdd):
            value = _evaluate_discount_node(node.operand, total)
        else:
            raise ValueError("Unsupported operation")

    else:
        raise ValueError("Invalid discount expression")

    if not math.isfinite(value):
        raise ValueError("Result must be finite")

    return value


def apply_discount_rule(rule, total):
    if not isinstance(rule, str) or len(rule) > 200:
        raise ValueError("Invalid discount rule")

    if (
        isinstance(total, bool)
        or not isinstance(total, (int, float))
        or not math.isfinite(total)
    ):
        raise ValueError("Invalid total")

    try:
        tree = ast.parse(rule, mode="eval")

        if sum(1 for _ in ast.walk(tree)) > 50:
            raise ValueError("Discount expression is too complex")

        return _evaluate_discount_node(tree.body, float(total))

    except (SyntaxError, TypeError, ZeroDivisionError, OverflowError) as exc:
        raise ValueError("Invalid discount rule") from exc

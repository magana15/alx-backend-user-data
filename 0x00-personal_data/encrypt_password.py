#!/usr/bin/env python3
""" Password encryption """
import bcrypt


def hash_password(password: str) -> bytes:
    """ Create hashed password """
    pwd = password.encode()
    hashed_pwd = bcrypt.hashpw(pwd, bcrypt.gensalt())
    return hashed_pwd


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Checks hashed password matches
        unhashed password.
    """
    if bcrypt.checkpw(password.encode(), hashed_password):
        return True
    return False

#!/usr/bin/env python3
"""This module contains the authentication logic
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """This function hashes the password
    """
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(bytes, salt)

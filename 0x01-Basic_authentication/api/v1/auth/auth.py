#!/usr/bin/env python3
""" Module of auth views"""

from flask import request
from typing import List, TypeVar


class Auth:
    """Auth class to manage the API authentication."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determine if the given path requires authentication.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): A list of
            paths that do not require authentication.

        Returns:
            bool: Always returns False for now.
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        else:
            # Remove trailing slashes from path and excluded_paths
            path = path.rstrip('/')
            excluded_paths = [p.rstrip('/') for p in excluded_paths]

            # Check if path is in excluded_paths or starts with an excluded
            # path
            for excluded_path in excluded_paths:
                if excluded_path.endswith('*'):
                    if path.startswith(excluded_path[:-1]):
                        return False
                elif path == excluded_path:
                    return False

            return True

    def authorization_header(self, request=None) -> str:
        """
       Retrieve the Authorization header from the request.

       Args:
           request (optional): The Flask request object.

       Returns:
           str: Always returns None for now.
       """
        if request is None or "Authorization" not in request.headers:
            return None
        else:
            return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieve the current user from the request.

        Args:
            request (optional): The Flask request object.

        Returns:
            TypeVar('User'): Always returns None for now.
        """
        return None

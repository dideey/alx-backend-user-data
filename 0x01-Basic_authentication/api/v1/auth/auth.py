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
            excluded_paths (List[str]): A list of paths that do not require authentication.

        Returns:
            bool: Always returns False for now.
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        else:
                # Remove trailing slashes from path and excluded_paths
            path = path.rstrip('/')
            excluded_paths = [p.rstrip('/') for p in excluded_paths]

            # Check if path is in excluded_paths
            return path not in excluded_paths



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


class BasicAuth(Auth):
    """inherits from auth"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """
        Extract the base64 part from the Authorization header.

        Args:
            authorization_header (str): The Authorization header.

        Returns:
            str: Always returns None for now.
        """
        if authorization_header is None or type(authorization_header) is not str or not authorization_header.startswith("Basic "):
            return None
        else:
            return authorization_header[6:]

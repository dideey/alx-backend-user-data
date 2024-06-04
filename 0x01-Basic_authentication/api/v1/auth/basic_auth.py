#!/usr/bin/env python3
""" Basic Auth module
"""

import base64
from typing import TypeVar, Tuple
from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """inherits from auth"""

    def extract_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Extract the base64 part from the Authorization header.

        Args:
            authorization_header (str): The Authorization header.

        Returns:
            str: The base64 string.
        """
        if (base64_authorization_header is None or
                type(base64_authorization_header) is not str
                or not base64_authorization_header.startswith("Basic ")):
            return None
        else:
            return base64_authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decode a base64 string.

        Args:
            base66_authorization_header (str): The base64 string.

        Returns:
            str: The decoded string.

        """
        if base64_authorization_header is None or type(
                base64_authorization_header) is not str:
            return None

        try:
            return base64.b64decode(
                base64_authorization_header).decode('utf-8')
        except BaseException:
            return None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """
        Returns the User instance based on his email and password.

        Args:
            user_email (str): The user email.
            user_pwd (str): The user password.

        Returns:
            User: The user instance.
        """
        if (user_email is None or type(user_email)
                is not str or user_pwd is None
                or type(user_pwd) is not str):
            return None

        # search for the users with the email
        users = User.search({'email': user_email})

        # return none if no user found
        if not users:
            return None
        # select first user with the email
        user = users[0]

        # check if the password is valid
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """
        Extracts user credentials from a decoded base64 string.

        Args:
            decoded_base64_authorization_header (str):
              The decoded base64 string.

        Returns:
            Tuple[str, str]: The user credentials.
        """
        if (decoded_base64_authorization_header is None or
                type(decoded_base64_authorization_header) is not str or
                ':' not in decoded_base64_authorization_header):
            return (None, None)
        email, password = decoded_base64_authorization_header.split(':', 1)
        return (email, password)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Overloads Auth and retrieves the User instance for a request.

        Args:
            request (Request): The request.

        Returns:
            User: The user instance.
        """
        # get the Authorization header from the request
        auth_header = self.authorization_header(request)
        # extract the base64 part from the Authorization header
        base64_header = self.extract_base64_authorization_header(auth_header)
        # decode the base64 string
        decoded_header = self.decode_base64_authorization_header(base64_header)
        # extract the user credentials
        user_credentials = self.extract_user_credentials(decoded_header)
        # return the user object
        return self.user_object_from_credentials(
            user_credentials[0], user_credentials[1])

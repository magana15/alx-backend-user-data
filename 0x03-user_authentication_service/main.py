#!/usr/bin/env python3
"""Module for simple (E2E) integration tests
"""

import requests

from app import AUTH

EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"
BASE_URL = "http://0.0.0.0:5000"


def register_user(email: str, password: str) -> None:
    """Testing the registration of a user

    Args:
        email (str): The user's email.
        password (str): The user password.
    """
    url = "{}/users".format(BASE_URL)
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "user created"}
    response = requests.post(url, data=data)
    assert response.status_code == 400
    assert response.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Test logging in with a wrong password.

    Args:
        email (str): The email address of the user to log in.
        password (str): The user password.
    """
    url = "{}/sessions".format(BASE_URL)
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(url, data=data)
    assert response.status_code == 401


def profile_unlogged() -> None:
    """Tests behavior of trying to retrieve profile info
    while being logged out.
    """
    url = "{}/profile".format(BASE_URL)
    response = requests.get(url)
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """Tests retrieving profile information whilst
    logged in

    Args:
        session_id (str): The session ID of the logged in user
    """
    url = "{}/profile".format(BASE_URL)
    cookies = {
        "session_id": session_id
    }
    response = requests.get(url, cookies=cookies)
    assert response.status_code == 200
    payload = response.json()
    assert "email" in payload
    user = AUTH.get_user_from_session_id(session_id)
    assert user.email == payload["email"]


def log_out(session_id: str) -> None:
    """Tests test th process of logging out from a session.

    Args:
        session_id (str): the session ID of the user to log out.
    """
    # request to log out the user
    url = "{}/sessions".format(BASE_URL)
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "session_id": session_id
    }
    response = requests.delete(url, headers=headers, cookies=data)
    # print("RESPONSE.STATUSCODE: {}".format(response.status_code))
    # Assert that the response has the expected status code and payload
    assert response.status_code == 200


def reset_password_token(email: str) -> str:
    """Test the process of requesting a password reset.

    Args:
        email (str): The email to request password reset for.
    """
    # Make  POST request to the "/reset_password" endpoint
    url = "{}/reset_password".format(BASE_URL)
    data = {
        "email": email
    }
    response = requests.post(url, data=data)
    # Assert that the response has a 200 status code
    assert response.status_code == 200
    # Assert that the response contains the email & reset token as JSON payload
    assert "email" in response.json()
    assert response.json()["email"] == email
    # assert response.json() == {"email": email}
    # Extract the reset token from the response
    reset_token = response.json()["reset_token"]
    # Return the reset_token
    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Test updating user's password.

    Args:
        email (str): The email of the user whose password should be updated.
        reset_token (str): The reset token generated for the user.
        new_password (str): The new password to set for the user.
    """
    url = "{}/reset_password".format(BASE_URL)
    data = {
        "email": email,
        "reset_token": reset_token,
        "new_password": new_password
    }
    response = requests.put(url, data=data)
    # Assert the status code of the response is 200
    assert response.status_code == 200
    # Assert the message in the response matches the expected message
    assert response.json()["message"] == "Password updated"
    # Assert  email in the response matches the email passed in
    assert response.json()["email"] == email


def log_in(email: str, password: str) -> str:
    """Test logging in.

    Args:
        email (str): The email address of the user to log in.
        password (str): The user password.
    """
    url = "{}/sessions".format(BASE_URL)
    data = {
        "email": email,
        "password": password
    }
    # Make a POST request to the login endpoint with user credentials
    response = requests.post(url, data=data)
    # Check if the response status code is 401 in case of invalid credentials
    if response.status_code == 401:
        return "Invalid credentials"
    # Check if the response status code is 200 in case of valid credentials
    assert response.status_code == 200
    # Check if email & message keys are present in the response JSON payload
    response_json = response.json()
    assert "email" in response_json
    assert "message" in response_json
    # Check if email in response JSON payload matches email in the request
    assert response_json["email"] == email
    # Return the session ID from the response cookie.
    return response.cookies.get("session_id")


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)

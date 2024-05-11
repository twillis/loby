def test_login(test_app):
    """
    Tests the login functionality of the web application.

    This function performs the following tests:
    1. Attempts to login with incorrect credentials to validate that unauthorized access is prevented.
    2. Asserts that the server returns a 401 Unauthorized status code, indicating the login attempt was unsuccessful.
    3. Verifies that the response contains an appropriate error message indicating login failure.
    4. Attempts to login with correct credentials to confirm that authorized access is granted.
    5. Checks that the server correctly redirects after a successful login, following the redirection to the target page.
    6. Verifies that the response to a successful login contains a welcome message, indicating a successful login and correct page rendering.

    Args:
        test_app (TestApp): The WebTest TestApp instance configured to test the web application.

    Raises:
        AssertionError: If any of the conditions tested by the asserts are not met, indicating a failure in login handling.
    """
    # Fetch the login page first to get the form
    response = test_app.get('/login')
    form = response.form  # Get the form object from the response

    # Fill out the form fields with incorrect credentials
    form['username'] = 'testuser'
    form['password'] = 'testpass'

    # Submit the form and expect a 401 Unauthorized status
    response = form.submit('submit', status=401)
    assert 'server could not verify that you are authorized' in response.text, "Expected error message for invalid login not present"

    # Fill the form with correct credentials
    form['username'] = 'admin'
    form['password'] = 'Password123$'

    # Submit the form and expect a redirection (302), then follow to final page
    response = form.submit('submit', status=302).follow()
    assert 'Welcome' in response.text, "Expected welcome message after successful login not present"

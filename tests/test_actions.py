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
    assert 'Invalid username or password' in response.text, "Expected error message for invalid login not present"

    # Fill the form with correct credentials
    form['username'] = 'admin'
    form['password'] = 'Password123$'

    # Submit the form and expect a redirection (302), then follow to final page
    response = form.submit('submit', status=302).follow()
    assert 'Welcome' in response.text, "Expected welcome message after successful login not present"


def test_register_action(test_app):
    """
    Tests the registration process of the web application.

    This function performs the following tests:
    - Submits a registration form with valid user data and verifies successful registration.
    - Checks that the server responds with a correct redirection after a successful registration.
    - Optionally, test with invalid data to ensure that validation errors are handled correctly.

    """
    # Define the path for your registration page and the form data
    register_url = '/register'  # Adjust the URL if necessary
    form_data = {
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password': 'securepassword123',
        'password_confirm': 'securepassword123',
        # Include other fields as necessary
    }

    # Fetch the registration page to get the CSRF token if your form requires it
    response = test_app.get(register_url)
    form = response.form

    # Fill out the form fields
    form['username'] = form_data['username']
    form['email'] = form_data['email']
    form['password'] = form_data['password']
    form['password_confirm'] = form_data['password_confirm']

    # Submit the form
    response = form.submit('submit')

    # Check if the registration was successful (usually a redirect to a login page or user profile)
    assert response.status_code == 302, "Expected a redirect after successful registration"

    # Follow the redirect and check the response
    follow_response = response.follow()
    assert 'Registration successful' in follow_response.text, "Expected confirmation message not found"

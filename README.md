# Comporta Ethics

A brief description of what this project does and who it's for

# Comporta Ethics Web Application

Welcome to the Comporta Ethics web application!
This application is built using Flask and provides a platform for users to register, log in, send messages, and submit consultations. It features a messaging system, user authentication, and an admin interface for managing messages.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Usage](#usage)
- [File Structure](#file-structure)
- [License](#license)

## Features
- User registration and login
- Admin and user roles
- Messaging system with real-time updates via SocketIO
- Consultation submission with status tracking
- Static and dynamic content pages

## Requirements
The project requires the following Python packages:
- Flask
- Flask-SQLAlchemy
- Flask-WTF
- Flask-Login
- Flask-Bcrypt
- Flask-SocketIO
- Flask-Migrate

These dependencies are listed in `requirements.txt`:

- flask
- sqlalchemy
- flask-SocketIO
- flask-wtf
- flask-login
- flask-bcrypt
- flask-migrate



## Installation

1. Clone the repository:
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2. Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate   # On Windows, use `venv\Scripts\activate`
    ```

3. Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Set up the database:
    - Update the `app.config['SQLALCHEMY_DATABASE_URI']` in `app.py` with your PostgreSQL database URI.
    - Initialize the database:
        ```bash
        flask db init
        flask db migrate
        flask db upgrade
        ```

## Configuration
Update the following configuration settings in `app.py`:
- **SQLAlchemy Database URI**: Set `app.config['SQLALCHEMY_DATABASE_URI']` to your PostgreSQL database URI.
- **Secret Key**: Ensure `app.config['SECRET_KEY']` is set to a secure value for session management.

## Running the Application
Start the Flask application:
```bash
python3 comporta_ethics/app.py
 ```
Visit http://127.0.0.1:5001 in your web browser.

## Usage

### User Registration
- Navigate to `/register` to create a new account.
- Enter a username, email, password, and confirm your password.

### User Login
- Navigate to `/login` to log in with your credentials.

### Messaging
- Access the messaging system at `/messages`.
- Admin users can send messages to any user, while regular users can only message the admin.

### Consultations
- Submit consultation requests via the `/submit_search` route.

### Static Pages
- Visit various static pages including:
  - `/news` - News and updates
  - `/your_search` - Search results
  - `/our_mission` - Information about our mission
  - And other pages for additional content

## File Structure

Here is an overview of the key files and directories in the project:

```bash
/app.py # Main application file
/forms.py # Flask-WTF forms
/models.py # SQLAlchemy models
/requirements.txt # List of dependencies
/templates/ # HTML templates
/index2.html # Home page
/register2.html # Registration page
/login2.html # Login page
...
/static/ # Static files (CSS, images)
/styles2.css # CSS for the main page
/images/ # Image assets
...
```


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## About me
- LinkedIn: https://www.linkedin.com/in/leo-cheneviere-24a53b235/
- Blog post: https://www.linkedin.com/feed/update/urn:li:ugcPost:7220030183355871233/

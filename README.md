# Flask Auth Skeleton 🔐

A production-ready Flask authentication skeleton with OAuth integration, role-based access control, and a responsive Tailwind CSS frontend.
Great starting point for your vibe-coding project. Save some prompts with this prebuilt template. 

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

- **Email/Password Authentication** - Secure registration and login with bcrypt password hashing
- **OAuth Integration** - Login with Google, Facebook, or GitHub via Authlib
- **Role-Based Access Control** - Admin and User roles with protected routes
- **Admin Panel** - Manage users, edit roles, and delete accounts
- **Responsive UI** - Clean Tailwind CSS design that works on all devices
- **Docker Ready** - Containerized for easy deployment
- **Comprehensive Tests** - Unit tests and property-based tests with Hypothesis

## 📸 Screenshots

### Login Page
<img width="1200"  alt="image" src="https://github.com/user-attachments/assets/845e3c9f-ed71-48f5-ace1-9e8a44e7a252" />


### Admin Panel
<img width="1200"  alt="image" src="https://github.com/user-attachments/assets/1b58c122-3b69-430b-9172-cce32f8def98" />


## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- pip or Docker

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/jkolarov/FlaskLogin.git
   cd FlaskLogin
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

5. **Initialize the database**
   ```bash
   python scripts/init_db.py
   ```

6. **Run the application**
   ```bash
   python run.py
   ```

7. **Open your browser**
   ```
   http://localhost:5000
   ```

### Docker Installation

```bash
# Build and run with Docker Compose
docker-compose up --build

# Access at http://localhost:5000
```

## ⚙️ Configuration

Create a `.env` file with the following variables:

```env
# Flask
SECRET_KEY=your-secret-key-here
FLASK_ENV=development

# Database
DATABASE_URL=sqlite:///instance/dev.db

# OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
FACEBOOK_CLIENT_ID=your-facebook-client-id
FACEBOOK_CLIENT_SECRET=your-facebook-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

## 📁 Project Structure

```
flask-auth-skeleton/
├── app/
│   ├── auth/           # Authentication blueprint
│   ├── admin/          # Admin panel blueprint
│   ├── main/           # Main routes blueprint
│   ├── services/       # Business logic
│   ├── templates/      # Jinja2 templates
│   ├── utils/          # Utility functions
│   ├── models.py       # SQLAlchemy models
│   └── __init__.py     # App factory
├── tests/              # Test suite
├── scripts/            # Utility scripts
├── config.py           # Configuration
├── run.py              # Entry point
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## 🧪 Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run property-based tests only
pytest -m property

# Run specific test file
pytest tests/test_auth_routes.py -v
```

## 🔒 Security Features

- **Password Hashing** - bcrypt with automatic salt
- **CSRF Protection** - Flask-WTF on all forms
- **Input Sanitization** - Protection against XSS and injection
- **Secure Sessions** - Server-side session management
- **Role-Based Access** - Decorator-based route protection

## 📝 API Routes

| Route | Method | Description | Auth Required |
|-------|--------|-------------|---------------|
| `/auth/register` | GET, POST | User registration | No |
| `/auth/login` | GET, POST | User login | No |
| `/auth/logout` | GET | User logout | Yes |
| `/auth/oauth/<provider>` | GET | OAuth login | No |
| `/dashboard` | GET | User dashboard | Yes |
| `/admin/users` | GET | List all users | Admin |
| `/admin/users/<id>/edit` | GET, POST | Edit user role | Admin |
| `/admin/users/<id>/delete` | POST | Delete user | Admin |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/) - The web framework
- [Authlib](https://authlib.org/) - OAuth library
- [Tailwind CSS](https://tailwindcss.com/) - CSS framework
- [Hypothesis](https://hypothesis.readthedocs.io/) - Property-based testing

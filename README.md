# Flask JWT Authentication API with MongoDB and AWS Secrets Manager

This project is a RESTful API built with Flask for user authentication using JWT, integrated with MongoDB for user data storage, and AWS Secrets Manager for securely storing the secret key.

## Features

- User registration with `email`, `password`, and `role` (`admin` or `user`).
- Login endpoint with JWT token generation.
- Protected routes accessible only with a valid JWT.
- Securely fetches `SECRET_KEY` from AWS Secrets Manager.
- Passwords are hashed using `bcrypt`.

---

## Prerequisites

- Python 3.8 or higher
- MongoDB instance (e.g., MongoDB Atlas)
- AWS Secrets Manager with a stored secret key
- `pip` for package management

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/your-repo.git
   cd your-repo

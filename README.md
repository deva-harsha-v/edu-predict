# Student Performance Predictor (SPP)

## Project Structure

```
frontend/
  landing.html   — Marketing / home page
  login.html     — Login & account creation
  app.html       — Main application (dashboard, predict, students, accounts)

backend/
  app.py         — Flask REST API
  requirements.txt
  data/          — Auto-created on first run
    users.json   — User accounts (passwords hashed)
    students.json— Student academic records
```

---

## Quick Start

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Server starts at **http://localhost:5000**

### 2. Frontend

Open `frontend/landing.html` in your browser — or serve the `frontend/` folder with any static server:

```bash
# Python quick server
cd frontend
python -m http.server 8080
# Then visit http://localhost:8080/landing.html
```

---

## Default Accounts

| Role    | Email               | Password  | Student ID |
|---------|---------------------|-----------|------------|
| Admin   | admin@spp.edu       | admin123  | —          |
| Teacher | teacher@spp.edu     | teach123  | —          |
| Student | student@spp.edu     | stud123   | S001       |

Accounts are seeded automatically into `backend/data/users.json` on first run.
Passwords are stored as PBKDF2-SHA256 hashes.

---

## Authentication Flow

1. User fills login form in `login.html`
2. Frontend calls `POST /api/login` with `{ email, password, role, studentId }`
3. Backend verifies credentials, returns a signed token + user profile
4. Token is stored in `sessionStorage` / `localStorage`
5. `app.html` reads the token, attaches it as `Authorization: Bearer <token>` on all API calls
6. If the backend is offline, the frontend falls back to `localStorage` (accounts seeded locally in `login.html`)

---

## API Endpoints

| Method | Path                     | Auth Required | Description              |
|--------|--------------------------|---------------|--------------------------|
| POST   | /api/login               | No            | Authenticate & get token |
| POST   | /api/register            | No            | Create new account       |
| GET    | /api/profile             | Yes           | Get current user profile |
| GET    | /api/users               | Admin/Teacher | List all users           |
| PUT    | /api/users/:id           | Admin         | Update user              |
| DELETE | /api/users/:id           | Admin         | Delete user              |
| GET    | /api/students            | Admin/Teacher | List all student records |
| GET    | /api/students/:studentId | Yes           | Get one student record   |
| POST   | /api/students            | Admin/Teacher | Create student record    |
| PUT    | /api/students/:studentId | Yes           | Update student record    |
| DELETE | /api/students/:studentId | Admin         | Delete student record    |
| GET    | /api/health              | No            | Backend health check     |

---

## Environment Variables

| Variable     | Default                          | Description              |
|--------------|----------------------------------|--------------------------|
| SPP_SECRET   | change-me-in-production-use-env-var | Token signing secret  |

For production, always set `SPP_SECRET` to a long random string:
```bash
export SPP_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

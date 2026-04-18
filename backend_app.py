"""
Student Performance Predictor — Backend
========================================
Flask REST API with local JSON-file user store.
No external auth service required.

Setup:
  pip install flask flask-cors
  python app.py

The server runs on http://localhost:5000
Frontend files (landing.html, login.html, app.html) can be served
from any static host or simply opened as local files.
"""

import json
import os
import uuid
import hashlib
import hmac
import base64
import time
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ── File-based storage ─────────────────────────────────────────────────────
DATA_DIR   = os.path.join(os.path.dirname(__file__), 'data')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
STUDENTS_FILE = os.path.join(DATA_DIR, 'students.json')

SECRET_KEY = os.environ.get('SPP_SECRET', 'change-me-in-production-use-env-var')

os.makedirs(DATA_DIR, exist_ok=True)

# ── Helpers ────────────────────────────────────────────────────────────────
def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def hash_password(password: str) -> str:
    """Simple PBKDF2 hash."""
    salt = SECRET_KEY.encode()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
    return base64.b64encode(dk).decode()

def check_password(password: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_password(password), hashed)

def make_token(user_id: str) -> str:
    """Simple signed token: base64(user_id:timestamp):signature"""
    payload = f"{user_id}:{int(time.time())}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    encoded = base64.b64encode(payload.encode()).decode()
    return f"{encoded}.{sig}"

def verify_token(token: str):
    """Returns user_id if token is valid, else None."""
    try:
        encoded, sig = token.rsplit('.', 1)
        payload = base64.b64decode(encoded).decode()
        expected_sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        user_id, _ = payload.split(':', 1)
        return user_id
    except Exception:
        return None

def get_users():
    return load_json(USERS_FILE, [])

def save_users(users):
    save_json(USERS_FILE, users)

def get_students():
    return load_json(STUDENTS_FILE, [])

def save_students(students):
    save_json(STUDENTS_FILE, students)

def seed_default_users():
    """Create default accounts if the users file doesn't exist yet."""
    if os.path.exists(USERS_FILE):
        return
    defaults = [
        {
            'id': 'u-admin',
            'email': 'admin@spp.edu',
            'password': hash_password('admin123'),
            'role': 'admin',
            'name': 'Admin User',
            'studentId': None,
            'dept': None,
            'year': None,
            'semester': None,
            'designation': 'System Administrator',
        },
        {
            'id': 'u-teacher',
            'email': 'teacher@spp.edu',
            'password': hash_password('teach123'),
            'role': 'teacher',
            'name': 'Dr. Meena Iyer',
            'studentId': None,
            'dept': 'CSE',
            'year': None,
            'semester': None,
            'designation': 'Associate Professor',
        },
        {
            'id': 'u-student',
            'email': 'student@spp.edu',
            'password': hash_password('stud123'),
            'role': 'student',
            'name': 'Arjun Sharma',
            'studentId': 'S001',
            'dept': 'CSE',
            'year': '2',
            'semester': '4',
            'designation': None,
        },
    ]
    save_users(defaults)
    print("[SPP] Default accounts seeded. See data/users.json")

seed_default_users()

# ── Auth decorator ─────────────────────────────────────────────────────────
def require_auth(roles=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            token = auth.removeprefix('Bearer ').strip()
            user_id = verify_token(token)
            if not user_id:
                return jsonify({'error': 'Unauthorized'}), 401
            users = get_users()
            user = next((u for u in users if u['id'] == user_id), None)
            if not user:
                return jsonify({'error': 'User not found'}), 401
            if roles and user['role'] not in roles:
                return jsonify({'error': 'Forbidden'}), 403
            request.current_user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def safe_user(u):
    """Return user dict without password field."""
    return {k: v for k, v in u.items() if k != 'password'}

# ══════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(force=True) or {}
    email     = (data.get('email') or '').strip().lower()
    password  = data.get('password', '')
    role      = data.get('role', '')
    student_id = (data.get('studentId') or '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    users = get_users()
    user = next((u for u in users if u['email'].lower() == email), None)

    if not user or not check_password(password, user['password']):
        return jsonify({'error': 'Invalid credentials.'}), 401

    if role and user['role'] != role:
        return jsonify({'error': f'This account is registered as "{user["role"]}", not "{role}".'}), 401

    if user['role'] == 'student' and student_id and user.get('studentId') != student_id:
        return jsonify({'error': 'Student ID does not match this account.'}), 401

    token = make_token(user['id'])
    return jsonify({'token': token, 'user': safe_user(user)}), 200


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(force=True) or {}
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password', '')
    name     = (data.get('name') or '').strip()
    role     = data.get('role', 'student')

    if not email or not password or not name:
        return jsonify({'error': 'Email, password, and name are required.'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400
    if role not in ('student', 'teacher'):
        return jsonify({'error': 'Invalid role. Must be student or teacher.'}), 400

    users = get_users()
    if any(u['email'].lower() == email for u in users):
        return jsonify({'error': 'An account with this email already exists.'}), 409

    new_user = {
        'id':          'u-' + str(uuid.uuid4())[:8],
        'email':       email,
        'password':    hash_password(password),
        'role':        role,
        'name':        name,
        'studentId':   (data.get('studentId') or '').strip() or None,
        'dept':        data.get('dept') or None,
        'year':        data.get('year') or None,
        'semester':    data.get('semester') or None,
        'employeeId':  data.get('employeeId') or None,
        'designation': data.get('designation') or None,
        'createdAt':   datetime.utcnow().isoformat(),
    }
    users.append(new_user)
    save_users(users)
    return jsonify({'message': 'Account created successfully.', 'user': safe_user(new_user)}), 201


@app.route('/api/profile', methods=['GET'])
@require_auth()
def get_profile():
    return jsonify(safe_user(request.current_user)), 200

# ══════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT (admin only)
# ══════════════════════════════════════════════════════════════════════════

@app.route('/api/users', methods=['GET'])
@require_auth(roles=['admin', 'teacher'])
def list_users():
    users = get_users()
    return jsonify([safe_user(u) for u in users]), 200


@app.route('/api/users/<user_id>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_user(user_id):
    data = request.get_json(force=True) or {}
    users = get_users()
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return jsonify({'error': 'User not found.'}), 404

    # Only allow updating these fields
    allowed = ['name', 'dept', 'year', 'semester', 'designation', 'employeeId', 'studentId']
    for field in allowed:
        if field in data:
            user[field] = data[field]
    if 'password' in data and data['password']:
        if len(data['password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters.'}), 400
        user['password'] = hash_password(data['password'])

    save_users(users)
    return jsonify(safe_user(user)), 200


@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_auth(roles=['admin'])
def delete_user(user_id):
    users = get_users()
    original_len = len(users)
    # Prevent self-deletion
    if request.current_user['id'] == user_id:
        return jsonify({'error': 'You cannot delete your own account.'}), 400
    users = [u for u in users if u['id'] != user_id]
    if len(users) == original_len:
        return jsonify({'error': 'User not found.'}), 404
    save_users(users)
    return jsonify({'message': 'User deleted.'}), 200

# ══════════════════════════════════════════════════════════════════════════
# STUDENT DATA ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════

@app.route('/api/students', methods=['GET'])
@require_auth(roles=['admin', 'teacher'])
def list_students():
    return jsonify(get_students()), 200


@app.route('/api/students/<student_id>', methods=['GET'])
@require_auth()
def get_student(student_id):
    user = request.current_user
    # Students can only access their own record
    if user['role'] == 'student' and user.get('studentId') != student_id:
        return jsonify({'error': 'Forbidden'}), 403
    students = get_students()
    record = next((s for s in students if s['studentId'] == student_id), None)
    if not record:
        return jsonify({'error': 'Student not found.'}), 404
    return jsonify(record), 200


@app.route('/api/students', methods=['POST'])
@require_auth(roles=['admin', 'teacher'])
def create_student():
    data = request.get_json(force=True) or {}
    students = get_students()
    sid = (data.get('studentId') or '').strip()
    if not sid:
        return jsonify({'error': 'studentId is required.'}), 400
    if any(s['studentId'] == sid for s in students):
        return jsonify({'error': f'Student {sid} already exists.'}), 409

    record = {
        'id':          'rec-' + str(uuid.uuid4())[:8],
        'studentId':   sid,
        'name':        data.get('name', ''),
        'dept':        data.get('dept', ''),
        'year':        data.get('year', ''),
        'semester':    data.get('semester', ''),
        'sgpa':        data.get('sgpa', 0),
        'cgpa':        data.get('cgpa', 0),
        'attendance':  data.get('attendance', 0),
        'assignments': data.get('assignments', 0),
        'projects':    data.get('projects', 0),
        'extracurriculars': data.get('extracurriculars', 0),
        'prediction':  data.get('prediction', None),
        'updatedAt':   datetime.utcnow().isoformat(),
    }
    students.append(record)
    save_students(students)
    return jsonify(record), 201


@app.route('/api/students/<student_id>', methods=['PUT'])
@require_auth()
def update_student(student_id):
    user = request.current_user
    # Students can only update their own record
    if user['role'] == 'student' and user.get('studentId') != student_id:
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json(force=True) or {}
    students = get_students()
    record = next((s for s in students if s['studentId'] == student_id), None)

    if not record:
        # Auto-create if student is saving their own data for the first time
        if user['role'] == 'student':
            record = {'id': 'rec-' + str(uuid.uuid4())[:8], 'studentId': student_id}
            students.append(record)
        else:
            return jsonify({'error': 'Student not found.'}), 404

    updatable = ['name', 'dept', 'year', 'semester', 'sgpa', 'cgpa',
                 'attendance', 'assignments', 'projects', 'extracurriculars', 'prediction']
    for field in updatable:
        if field in data:
            record[field] = data[field]
    record['updatedAt'] = datetime.utcnow().isoformat()

    save_students(students)
    return jsonify(record), 200


@app.route('/api/students/<student_id>', methods=['DELETE'])
@require_auth(roles=['admin'])
def delete_student(student_id):
    students = get_students()
    original_len = len(students)
    students = [s for s in students if s['studentId'] != student_id]
    if len(students) == original_len:
        return jsonify({'error': 'Student not found.'}), 404
    save_students(students)
    return jsonify({'message': 'Student deleted.'}), 200

# ══════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'version': '1.0.0'}), 200


# ══════════════════════════════════════════════════════════════════════════
# RUN
# ══════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    import os
    print("=" * 55)
    print("  Student Performance Predictor — Backend")
    print("  Running on Railway / Production Mode")
    print("=" * 55)
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
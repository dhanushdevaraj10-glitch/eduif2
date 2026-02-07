from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
import hashlib
import re

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Database initialization
def init_db():
    conn = sqlite3.connect('eduif.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT NOT NULL,
                  is_locked INTEGER DEFAULT 0,
                  failed_attempts INTEGER DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Students table (encrypted data)
    c.execute('''CREATE TABLE IF NOT EXISTS students
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  student_id TEXT UNIQUE NOT NULL,
                  name_encrypted TEXT NOT NULL,
                  email_encrypted TEXT NOT NULL,
                  phone_encrypted TEXT NOT NULL,
                  address_encrypted TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Activity logs table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  username TEXT,
                  action TEXT NOT NULL,
                  ip_address TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  details TEXT)''')
    
    # File uploads table (for malware scanning)
    c.execute('''CREATE TABLE IF NOT EXISTS file_uploads
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename TEXT NOT NULL,
                  user_id INTEGER,
                  scan_status TEXT,
                  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Attendance table
    c.execute('''CREATE TABLE IF NOT EXISTS attendance
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  student_id TEXT NOT NULL,
                  date DATE NOT NULL,
                  status TEXT NOT NULL,
                  marked_by TEXT,
                  marked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  notes TEXT,
                  UNIQUE(student_id, date))''')
    
    # Create default admin user if not exists
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        admin_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('admin', admin_password, 'admin'))
        
        # Create sample staff and student users
        staff_password = generate_password_hash('staff123')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('staff', staff_password, 'staff'))
        
        student_password = generate_password_hash('student123')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('student', student_password, 'student'))
    
    conn.commit()
    conn.close()

# Simple encryption/decryption (XOR-based for demonstration)
def encrypt_data(data, key='eduif_secret_key'):
    """Simple XOR encryption for demonstration"""
    key_hash = hashlib.sha256(key.encode()).digest()
    encrypted = []
    for i, char in enumerate(data):
        encrypted.append(chr(ord(char) ^ key_hash[i % len(key_hash)]))
    return ''.join(encrypted).encode('utf-8').hex()

def decrypt_data(encrypted_hex, key='eduif_secret_key'):
    """Simple XOR decryption for demonstration"""
    try:
        encrypted = bytes.fromhex(encrypted_hex).decode('utf-8')
        key_hash = hashlib.sha256(key.encode()).digest()
        decrypted = []
        for i, char in enumerate(encrypted):
            decrypted.append(chr(ord(char) ^ key_hash[i % len(key_hash)]))
        return ''.join(decrypted)
    except:
        return "Error decrypting"

# Malware scanner (basic file name check)
def scan_file(filename):
    """Basic malware detection based on suspicious patterns"""
    suspicious_patterns = [
        r'\.exe$', r'\.bat$', r'\.cmd$', r'\.vbs$', r'\.js$',
        r'malware', r'virus', r'trojan', r'ransomware', r'hack'
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, filename.lower()):
            return 'SUSPICIOUS'
    return 'CLEAN'

# Activity logging
def log_activity(user_id, username, action, details=''):
    conn = sqlite3.connect('eduif.db')
    c = conn.cursor()
    ip_address = request.remote_addr
    c.execute('''INSERT INTO activity_logs (user_id, username, action, ip_address, details)
                 VALUES (?, ?, ?, ?, ?)''',
              (user_id, username, action, ip_address, details))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('eduif.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        
        if user:
            user_id, db_username, db_password, role, is_locked, failed_attempts, created_at = user
            
            # Check if account is locked
            if is_locked:
                flash('Account is locked due to multiple failed login attempts. Contact administrator.', 'danger')
                log_activity(user_id, username, 'LOGIN_FAILED', 'Account locked')
                conn.close()
                return redirect(url_for('login'))
            
            # Verify password
            if check_password_hash(db_password, password):
                # Reset failed attempts
                c.execute("UPDATE users SET failed_attempts=0 WHERE id=?", (user_id,))
                conn.commit()
                
                # Set session
                session['user_id'] = user_id
                session['username'] = username
                session['role'] = role
                session.permanent = True
                
                log_activity(user_id, username, 'LOGIN_SUCCESS', f'Role: {role}')
                flash(f'Welcome {username}!', 'success')
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                # Increment failed attempts
                failed_attempts += 1
                if failed_attempts >= 3:
                    c.execute("UPDATE users SET failed_attempts=?, is_locked=1 WHERE id=?",
                              (failed_attempts, user_id))
                    flash('Account locked after 3 failed attempts. Contact administrator.', 'danger')
                    log_activity(user_id, username, 'ACCOUNT_LOCKED', f'Failed attempts: {failed_attempts}')
                else:
                    c.execute("UPDATE users SET failed_attempts=? WHERE id=?",
                              (failed_attempts, user_id))
                    flash(f'Invalid password. {3 - failed_attempts} attempts remaining.', 'warning')
                    log_activity(user_id, username, 'LOGIN_FAILED', f'Failed attempts: {failed_attempts}')
                conn.commit()
        else:
            flash('Invalid username or password.', 'danger')
            log_activity(None, username, 'LOGIN_FAILED', 'Username not found')
        
        conn.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session.get('user_id'), session.get('username'), 'LOGOUT', '')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role')
    username = session.get('username')
    
    conn = sqlite3.connect('eduif.db')
    c = conn.cursor()
    
    # Get statistics
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM students")
    total_students = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM activity_logs WHERE DATE(timestamp) = DATE('now')")
    today_activities = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM file_uploads WHERE scan_status='SUSPICIOUS'")
    suspicious_files = c.fetchone()[0]
    
    conn.close()
    
    log_activity(session.get('user_id'), username, 'DASHBOARD_ACCESS', f'Role: {role}')
    
    return render_template('dashboard.html', 
                           role=role, 
                           username=username,
                           total_users=total_users,
                           total_students=total_students,
                           today_activities=today_activities,
                           suspicious_files=suspicious_files)

@app.route('/students', methods=['GET', 'POST'])
def students():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role')
    
    # Role-based access control
    if role not in ['admin', 'staff']:
        flash('Access denied. Insufficient permissions.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        
        # Encrypt student data
        name_enc = encrypt_data(name)
        email_enc = encrypt_data(email)
        phone_enc = encrypt_data(phone)
        address_enc = encrypt_data(address)
        
        conn = sqlite3.connect('eduif.db')
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO students (student_id, name_encrypted, email_encrypted, 
                         phone_encrypted, address_encrypted) VALUES (?, ?, ?, ?, ?)''',
                      (student_id, name_enc, email_enc, phone_enc, address_enc))
            conn.commit()
            flash('Student added successfully! Data encrypted.', 'success')
            log_activity(session.get('user_id'), session.get('username'), 
                        'STUDENT_ADDED', f'Student ID: {student_id}')
        except sqlite3.IntegrityError:
            flash('Student ID already exists.', 'danger')
        conn.close()
    
    # Fetch students
    conn = sqlite3.connect('eduif.db')
    c = conn.cursor()
    c.execute("SELECT * FROM students ORDER BY created_at DESC")
    students_data = c.fetchall()
    conn.close()
    
    # Decrypt data for authorized users
    decrypted_students = []
    for student in students_data:
        sid, student_id, name_enc, email_enc, phone_enc, address_enc, created_at = student
        decrypted_students.append({
            'id': sid,
            'student_id': student_id,
            'name': decrypt_data(name_enc),
            'email': decrypt_data(email_enc),
            'phone': decrypt_data(phone_enc),
            'address': decrypt_data(address_enc),
            'created_at': created_at
        })
    
    log_activity(session.get('user_id'), session.get('username'), 
                'STUDENTS_VIEW', f'Viewed {len(decrypted_students)} students')
    
    return render_template('students.html', students=decrypted_students, role=role)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'warning')
            return redirect(url_for('upload'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'warning')
            return redirect(url_for('upload'))
        
        # Scan file
        scan_result = scan_file(file.filename)
        
        conn = sqlite3.connect('eduif.db')
        c = conn.cursor()
        c.execute('''INSERT INTO file_uploads (filename, user_id, scan_status)
                     VALUES (?, ?, ?)''',
                  (file.filename, session.get('user_id'), scan_result))
        conn.commit()
        conn.close()
        
        if scan_result == 'SUSPICIOUS':
            flash(f'⚠️ File "{file.filename}" flagged as SUSPICIOUS! Upload blocked.', 'danger')
            log_activity(session.get('user_id'), session.get('username'), 
                        'FILE_UPLOAD_BLOCKED', f'Suspicious file: {file.filename}')
        else:
            flash(f'✓ File "{file.filename}" scanned and approved!', 'success')
            log_activity(session.get('user_id'), session.get('username'), 
                        'FILE_UPLOAD_SUCCESS', f'Clean file: {file.filename}')
    
    return render_template('upload.html')

@app.route('/logs')
def logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role')
    
    # Only admin can view logs
    if role != 'admin':
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('eduif.db')
    c = conn.cursor()
    c.execute("SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT 100")
    logs_data = c.fetchall()
    conn.close()
    
    log_activity(session.get('user_id'), session.get('username'), 
                'LOGS_VIEW', f'Viewed {len(logs_data)} log entries')
    
    return render_template('logs.html', logs=logs_data)

@app.route('/users')
def users():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role')
    
    # Only admin can manage users
    if role != 'admin':
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('eduif.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role, is_locked, failed_attempts, created_at FROM users")
    users_data = c.fetchall()
    conn.close()
    
    log_activity(session.get('user_id'), session.get('username'), 
                'USERS_VIEW', f'Viewed {len(users_data)} users')
    
    return render_template('users.html', users=users_data)

@app.route('/unlock_user/<int:user_id>')
def unlock_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('eduif.db')
    c = conn.cursor()
    c.execute("UPDATE users SET is_locked=0, failed_attempts=0 WHERE id=?", (user_id,))
    conn.commit()
    c.execute("SELECT username FROM users WHERE id=?", (user_id,))
    username = c.fetchone()[0]
    conn.close()
    
    flash(f'User {username} has been unlocked.', 'success')
    log_activity(session.get('user_id'), session.get('username'), 
                'USER_UNLOCKED', f'Unlocked user ID: {user_id}')
    
    return redirect(url_for('users'))

@app.route('/attendance', methods=['GET', 'POST'])
def attendance():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role')
    
    # Only admin and staff can manage attendance
    if role not in ['admin', 'staff']:
        flash('Access denied. Staff/Admin only.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('eduif.db')
    c = conn.cursor()
    
    # Handle attendance marking
    if request.method == 'POST':
        student_id = request.form['student_id']
        date = request.form['date']
        status = request.form['status']
        notes = request.form.get('notes', '')
        
        try:
            c.execute('''INSERT INTO attendance (student_id, date, status, marked_by, notes)
                         VALUES (?, ?, ?, ?, ?)''',
                      (student_id, date, status, session.get('username'), notes))
            conn.commit()
            flash(f'Attendance marked for {student_id} on {date} as {status}', 'success')
            log_activity(session.get('user_id'), session.get('username'), 
                        'ATTENDANCE_MARKED', f'Student: {student_id}, Date: {date}, Status: {status}')
        except sqlite3.IntegrityError:
            # Update existing attendance
            c.execute('''UPDATE attendance SET status=?, marked_by=?, notes=?, marked_at=CURRENT_TIMESTAMP
                         WHERE student_id=? AND date=?''',
                      (status, session.get('username'), notes, student_id, date))
            conn.commit()
            flash(f'Attendance updated for {student_id} on {date}', 'success')
            log_activity(session.get('user_id'), session.get('username'), 
                        'ATTENDANCE_UPDATED', f'Student: {student_id}, Date: {date}, Status: {status}')
    
    # Get filter date (default to today)
    from datetime import date as dt_date
    filter_date = request.args.get('date', str(dt_date.today()))
    
    # Fetch all students
    c.execute("SELECT student_id, name_encrypted FROM students ORDER BY student_id")
    students_data = c.fetchall()
    
    # Fetch attendance for the selected date
    c.execute("""SELECT student_id, status, marked_by, marked_at, notes 
                 FROM attendance WHERE date=?""", (filter_date,))
    attendance_data = c.fetchall()
    
    conn.close()
    
    # Create attendance dictionary
    attendance_dict = {}
    for att in attendance_data:
        attendance_dict[att[0]] = {
            'status': att[1],
            'marked_by': att[2],
            'marked_at': att[3],
            'notes': att[4]
        }
    
    # Prepare student list with attendance
    students_with_attendance = []
    for student in students_data:
        student_id, name_enc = student
        students_with_attendance.append({
            'student_id': student_id,
            'name': decrypt_data(name_enc),
            'attendance': attendance_dict.get(student_id, None)
        })
    
    log_activity(session.get('user_id'), session.get('username'), 
                'ATTENDANCE_VIEW', f'Viewed attendance for {filter_date}')
    
    return render_template('attendance.html', 
                          students=students_with_attendance, 
                          filter_date=filter_date,
                          role=role)

@app.route('/attendance/report')
def attendance_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role')
    
    # Only admin and staff can view reports
    if role not in ['admin', 'staff']:
        flash('Access denied. Staff/Admin only.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('eduif.db')
    c = conn.cursor()
    
    # Get date range from query params
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    if start_date and end_date:
        c.execute("""SELECT a.student_id, a.date, a.status, a.marked_by, a.marked_at, a.notes, s.name_encrypted
                     FROM attendance a
                     JOIN students s ON a.student_id = s.student_id
                     WHERE a.date BETWEEN ? AND ?
                     ORDER BY a.date DESC, a.student_id""", (start_date, end_date))
    else:
        c.execute("""SELECT a.student_id, a.date, a.status, a.marked_by, a.marked_at, a.notes, s.name_encrypted
                     FROM attendance a
                     JOIN students s ON a.student_id = s.student_id
                     ORDER BY a.date DESC, a.student_id
                     LIMIT 100""")
    
    attendance_records = c.fetchall()
    conn.close()
    
    # Decrypt student names
    records_with_names = []
    for record in attendance_records:
        student_id, date, status, marked_by, marked_at, notes, name_enc = record
        records_with_names.append({
            'student_id': student_id,
            'name': decrypt_data(name_enc),
            'date': date,
            'status': status,
            'marked_by': marked_by,
            'marked_at': marked_at,
            'notes': notes
        })
    
    log_activity(session.get('user_id'), session.get('username'), 
                'ATTENDANCE_REPORT_VIEW', f'Viewed attendance report')
    
    return render_template('attendance_report.html', 
                          records=records_with_names,
                          start_date=start_date,
                          end_date=end_date,
                          role=role)

@app.route('/design')
def design_preview():
    """Design preview page to showcase all UI components"""
    return render_template('design_preview.html')

# Initialize database on startup
init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

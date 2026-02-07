# 🎓 EduIF - Educational Institution Information Security Platform

A comprehensive, colorful, and secure web application for managing educational institution data with advanced security features.

## 🌟 Features

### 🔐 Security Features

1. **User Login with Attempt Limiting**
   - Account automatically locks after 3 failed login attempts
   - Prevents brute force attacks
   - Admin can unlock accounts

2. **Role-Based Access Control (RBAC)**
   - **Admin**: Full system access (users, students, logs, all features)
   - **Staff**: Academic access (student management, file uploads)
   - **Student**: Limited access (personal data, file uploads)

3. **Data Encryption**
   - All student data is encrypted before storage
   - Uses XOR-based encryption with SHA-256 key hashing
   - Data remains secure even if database is compromised

4. **Data Decryption**
   - Only authorized users (Admin/Staff) can decrypt student data
   - Automatic decryption for viewing
   - Maintains data confidentiality

5. **Malware Scanner**
   - Real-time file scanning during upload
   - Detects suspicious file extensions (.exe, .bat, .cmd, .vbs, .js)
   - Blocks files with malicious keywords
   - Automatic threat blocking

6. **Activity Logging**
   - Every user action is logged with timestamp
   - IP address tracking
   - Complete audit trail
   - Admin-only log access

## 🎨 Design Features

- **Modern, Colorful UI** with vibrant gradients
- **Animated backgrounds** and smooth transitions
- **Responsive design** for all devices
- **Google Fonts** (Poppins) for premium typography
- **Glassmorphism** effects
- **Micro-animations** for enhanced UX
- **Color-coded badges** and status indicators

## 📋 Default Login Credentials

**Admin Account:**
- Username: `admin`
- Password: `admin123`

**Staff Account:**
- Username: `staff`
- Password: `staff123`

**Student Account:**
- Username: `student`
- Password: `student123`

⚠️ **IMPORTANT**: Change these credentials in production!

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run the Application
```bash
python app.py
```

### Step 3: Access the Application
Open your browser and navigate to:
```
http://localhost:5000
```

## 📁 Project Structure

```
info2/
├── app.py                 # Flask backend with all security features
├── requirements.txt       # Python dependencies
├── eduif.db              # SQLite database (auto-created)
├── static/
│   └── style.css         # Modern, colorful CSS styling
└── templates/
    ├── index.html        # Homepage with features
    ├── login.html        # Secure login page
    ├── dashboard.html    # Role-based dashboard
    ├── students.html     # Student management (encrypted)
    ├── upload.html       # File upload with malware scan
    ├── users.html        # User management (admin only)
    └── logs.html         # Activity logs (admin only)
```

## 🔒 Security Implementation Details

### 1. Login Attempt Limiting
- Tracks failed login attempts in database
- Locks account after 3 failures
- Resets counter on successful login
- All attempts logged with IP address

### 2. Role-Based Access Control
```python
Admin → Full access to all features
Staff → Student management + File uploads
Student → Personal data + File uploads
```

### 3. Encryption Algorithm
- XOR-based encryption with SHA-256 key derivation
- Each data field encrypted separately
- Stored as hexadecimal strings in database

### 4. Malware Detection
- Pattern matching for suspicious extensions
- Keyword detection (malware, virus, trojan, etc.)
- Immediate blocking of flagged files
- All scans logged for audit

### 5. Activity Logging
- User ID and username tracking
- Action type categorization
- IP address recording
- Timestamp with timezone
- Additional details field

## 🎯 Usage Guide

### For Administrators
1. Login with admin credentials
2. View dashboard statistics
3. Manage users (unlock accounts)
4. View all activity logs
5. Manage student records
6. Upload files with scanning

### For Staff
1. Login with staff credentials
2. Add/view student records (encrypted)
3. Upload files with malware scanning
4. View personal dashboard

### For Students
1. Login with student credentials
2. View limited dashboard
3. Upload files with malware scanning

## 🛡️ Security Best Practices

1. **Change default passwords** immediately
2. **Use strong passwords** (min 12 characters)
3. **Enable HTTPS** in production
4. **Regular database backups**
5. **Monitor activity logs** regularly
6. **Update dependencies** periodically
7. **Use environment variables** for secrets

## 🔧 Configuration

### Change Secret Key
Edit `app.py` line 9:
```python
app.secret_key = 'your-secret-key-change-this-in-production'
```

### Change Session Timeout
Edit `app.py` line 10:
```python
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
```

### Change Encryption Key
Edit encryption functions in `app.py`:
```python
def encrypt_data(data, key='your-custom-key'):
def decrypt_data(encrypted_hex, key='your-custom-key'):
```

## 📊 Database Schema

### Users Table
- id, username, password (hashed), role, is_locked, failed_attempts, created_at

### Students Table
- id, student_id, name_encrypted, email_encrypted, phone_encrypted, address_encrypted, created_at

### Activity Logs Table
- id, user_id, username, action, ip_address, timestamp, details

### File Uploads Table
- id, filename, user_id, scan_status, uploaded_at

## 🎨 Color Scheme

- Primary: `#6366f1` (Indigo)
- Secondary: `#8b5cf6` (Purple)
- Success: `#10b981` (Green)
- Danger: `#ef4444` (Red)
- Warning: `#f59e0b` (Amber)
- Info: `#3b82f6` (Blue)

## 📝 License

This project is created for educational purposes.

## 🤝 Support

For issues or questions, please contact your system administrator.

---

**Made with ❤️ for Educational Institution Security**

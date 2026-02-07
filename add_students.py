import sqlite3
import hashlib

# Simple encryption function (same as in app.py)
def encrypt_data(data, key='eduif_secret_key'):
    """Simple XOR encryption for demonstration"""
    key_hash = hashlib.sha256(key.encode()).digest()
    encrypted = []
    for i, char in enumerate(data):
        encrypted.append(chr(ord(char) ^ key_hash[i % len(key_hash)]))
    return ''.join(encrypted).encode('utf-8').hex()

# Student data
students = [
    {
        'student_id': 'STU001',
        'name': 'Dhanush',
        'email': 'dhanush@eduif.edu',
        'phone': '+91-9876543210',
        'address': '123 Main Street, Chennai, Tamil Nadu, India'
    },
    {
        'student_id': 'STU002',
        'name': 'Panchatcharam',
        'email': 'panchatcharam@eduif.edu',
        'phone': '+91-9876543211',
        'address': '456 Park Avenue, Coimbatore, Tamil Nadu, India'
    },
    {
        'student_id': 'STU003',
        'name': 'Srinath',
        'email': 'srinath@eduif.edu',
        'phone': '+91-9876543212',
        'address': '789 Lake Road, Bangalore, Karnataka, India'
    }
]

# Connect to database
conn = sqlite3.connect('eduif.db')
c = conn.cursor()

# Add students
for student in students:
    # Encrypt data
    name_enc = encrypt_data(student['name'])
    email_enc = encrypt_data(student['email'])
    phone_enc = encrypt_data(student['phone'])
    address_enc = encrypt_data(student['address'])
    
    try:
        c.execute('''INSERT INTO students (student_id, name_encrypted, email_encrypted, 
                     phone_encrypted, address_encrypted) VALUES (?, ?, ?, ?, ?)''',
                  (student['student_id'], name_enc, email_enc, phone_enc, address_enc))
        print(f"[SUCCESS] Added student: {student['name']} (ID: {student['student_id']})")
    except sqlite3.IntegrityError:
        print(f"[WARNING] Student {student['name']} (ID: {student['student_id']}) already exists - skipping")

conn.commit()
conn.close()

print("\n[COMPLETE] Student records added successfully!")
print("You can now view them at: http://localhost:5000/students")
print("Login as 'admin' or 'staff' to see the encrypted data decrypted")

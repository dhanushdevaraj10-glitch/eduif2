import sqlite3
import hashlib

# Decryption function (same as in app.py)
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

# Connect to database
conn = sqlite3.connect('eduif.db')
c = conn.cursor()

# Fetch all students
c.execute("SELECT * FROM students ORDER BY created_at DESC")
students = c.fetchall()

print("\n" + "="*80)
print("STUDENT RECORDS IN DATABASE (DECRYPTED VIEW)")
print("="*80)

for student in students:
    sid, student_id, name_enc, email_enc, phone_enc, address_enc, created_at = student
    
    print(f"\nStudent ID: {student_id}")
    print(f"Name: {decrypt_data(name_enc)}")
    print(f"Email: {decrypt_data(email_enc)}")
    print(f"Phone: {decrypt_data(phone_enc)}")
    print(f"Address: {decrypt_data(address_enc)}")
    print(f"Added on: {created_at}")
    print("-" * 80)

print(f"\nTotal Students: {len(students)}")
print("="*80)

conn.close()

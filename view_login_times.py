import sqlite3
from datetime import datetime

# Connect to database
conn = sqlite3.connect('eduif.db')
c = conn.cursor()

# Fetch all login activities
c.execute("""
    SELECT username, action, timestamp, ip_address, details 
    FROM activity_logs 
    WHERE action LIKE '%LOGIN%' 
    ORDER BY timestamp DESC
""")

login_logs = c.fetchall()

print("\n" + "="*100)
print("LOGIN ACTIVITY REPORT - EduIF Platform")
print("="*100)

if login_logs:
    print(f"\nTotal Login Activities: {len(login_logs)}\n")
    
    # Separate successful and failed logins
    successful_logins = []
    failed_logins = []
    locked_accounts = []
    
    for log in login_logs:
        username, action, timestamp, ip_address, details = log
        
        if action == 'LOGIN_SUCCESS':
            successful_logins.append(log)
        elif action == 'LOGIN_FAILED':
            failed_logins.append(log)
        elif action == 'ACCOUNT_LOCKED':
            locked_accounts.append(log)
    
    # Display successful logins
    if successful_logins:
        print("-" * 100)
        print("SUCCESSFUL LOGINS")
        print("-" * 100)
        print(f"{'Username':<15} {'Login Time':<25} {'IP Address':<20} {'Details':<30}")
        print("-" * 100)
        
        for log in successful_logins:
            username, action, timestamp, ip_address, details = log
            print(f"{username:<15} {timestamp:<25} {ip_address:<20} {details:<30}")
    
    # Display failed logins
    if failed_logins:
        print("\n" + "-" * 100)
        print("FAILED LOGIN ATTEMPTS")
        print("-" * 100)
        print(f"{'Username':<15} {'Attempt Time':<25} {'IP Address':<20} {'Details':<30}")
        print("-" * 100)
        
        for log in failed_logins:
            username, action, timestamp, ip_address, details = log
            print(f"{username:<15} {timestamp:<25} {ip_address:<20} {details:<30}")
    
    # Display locked accounts
    if locked_accounts:
        print("\n" + "-" * 100)
        print("ACCOUNT LOCKOUTS")
        print("-" * 100)
        print(f"{'Username':<15} {'Lockout Time':<25} {'IP Address':<20} {'Details':<30}")
        print("-" * 100)
        
        for log in locked_accounts:
            username, action, timestamp, ip_address, details = log
            print(f"{username:<15} {timestamp:<25} {ip_address:<20} {details:<30}")
    
    # Summary
    print("\n" + "="*100)
    print("SUMMARY")
    print("="*100)
    print(f"Successful Logins: {len(successful_logins)}")
    print(f"Failed Attempts: {len(failed_logins)}")
    print(f"Account Lockouts: {len(locked_accounts)}")
    print("="*100)
    
else:
    print("\nNo login activities found in the database.")
    print("="*100)

# Get current active users (those who logged in but haven't logged out)
c.execute("""
    SELECT DISTINCT username, MAX(timestamp) as last_login
    FROM activity_logs 
    WHERE action = 'LOGIN_SUCCESS'
    AND username NOT IN (
        SELECT username FROM activity_logs WHERE action = 'LOGOUT'
    )
    GROUP BY username
""")

active_users = c.fetchall()

if active_users:
    print("\n" + "="*100)
    print("CURRENTLY ACTIVE USERS (Logged in but not logged out)")
    print("="*100)
    print(f"{'Username':<15} {'Last Login Time':<25}")
    print("-" * 100)
    
    for user in active_users:
        username, last_login = user
        print(f"{username:<15} {last_login:<25}")
    
    print("="*100)

conn.close()

print("\n[INFO] To view this in the web interface, login as 'admin' and visit:")
print("       http://localhost:5000/logs")

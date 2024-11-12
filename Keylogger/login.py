import bcrypt
import sqlite3
import smtplib
import re
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Database setup (SQLite for simplicity)
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    is_locked INTEGER DEFAULT 0
)
''')
conn.commit()

# Function to send OTP email for 2FA
def send_otp(email):
    otp = ''.join(random.choices(string.digits, k=6))
    sender_email = "youremail@example.com"
    sender_password = "yourpassword"
    receiver_email = email
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = "Your OTP for Login"

    body = f"Your OTP is: {otp}"
    message.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = message.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        return otp
    except Exception as e:
        print(f"Error sending email: {e}")
        return None

# Password validation
def is_valid_password(password):
    if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[A-Za-z]", password):
        return False
    return True

# Email validation
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

# User Registration
def register_user(username, email, password):
    if not is_valid_password(password):
        return "Password must be at least 8 characters long, contain at least one number and one letter."
    
    if not is_valid_email(email):
        return "Invalid email format."
    
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        cursor.execute('''
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
        ''', (username, email, hashed_pw))
        conn.commit()
        return "User registered successfully."
    except sqlite3.IntegrityError:
        return "Username or email already exists."

# Login Function
def login_user(username, password):
    cursor.execute('SELECT password_hash, failed_attempts, is_locked, email FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    if result is None:
        return "Invalid username or password."

    password_hash, failed_attempts, is_locked, email = result

    if is_locked:
        return "Account is locked due to too many failed attempts. Contact support."

    if bcrypt.checkpw(password.encode('utf-8'), password_hash):
        otp = send_otp(email)
        if otp:
            user_otp = input("Enter the OTP sent to your email: ")
            if user_otp == otp:
                cursor.execute('UPDATE users SET failed_attempts = 0 WHERE username = ?', (username,))
                conn.commit()
                return "Login successful!"
            else:
                return "Invalid OTP. Login failed."
        else:
            return "Failed to send OTP. Login failed."
    else:
        # Increment failed attempts and possibly lock account
        failed_attempts += 1
        if failed_attempts >= 5:
            cursor.execute('UPDATE users SET is_locked = 1 WHERE username = ?', (username,))
            conn.commit()
            return "Too many failed attempts. Your account is locked."
        else:
            cursor.execute('UPDATE users SET failed_attempts = ? WHERE username = ?', (failed_attempts, username))
            conn.commit()
            return f"Invalid password. {5 - failed_attempts} attempts remaining."

# Account Unlock (For Admin or Support Usage)
def unlock_account(username):
    cursor.execute('UPDATE users SET failed_attempts = 0, is_locked = 0 WHERE username = ?', (username,))
    conn.commit()
    return "Account unlocked successfully."

# Example usage:
# Registration
print(register_user("john_doe", "arjith.anand1@gmail.com", "password123"))

# Login
print(login_user("john_doe", "password123"))

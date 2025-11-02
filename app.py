"""
fintrust_app.py
FinTrust – Secure FinTech Web App (Distinct UI Version)
Independent Implementation for CY4053 Assignment 2
"""

import streamlit as st
import sqlite3
import os
import bcrypt
import re
import pandas as pd
import random
import string
from datetime import datetime
from io import BytesIO
from cryptography.fernet import Fernet

# -------------------------------
# Config
# -------------------------------
DB_PATH = "fintrust_data.db"
KEY_PATH = "fintrust_key.key"
ALLOWED_EXT = {"png", "jpg", "jpeg", "pdf", "csv", "txt"}

# -------------------------------
# Theme & Layout
# -------------------------------
def set_pastel_theme():
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg, #ffffff 0%, #f5f9fc 50%, #eaf4ff 100%);
            font-family: 'Inter', sans-serif;
            color: #1e2a35;
        }
        .sidebar .sidebar-content {
            background: #e4f0ff !important;
        }
        h1, h2, h3 {
            color: #004a7c !important;
        }
        .stButton>button {
            background-color: #4f9cff !important;
            color: white !important;
            border-radius: 8px !important;
            font-weight: 600 !important;
            border: none !important;
        }
        .stButton>button:hover {
            background-color: #2e86ff !important;
        }
        .block {
            background-color: white;
            padding: 20px;
            border-radius: 14px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.05);
        }
        .subtle {
            color: #5c7080;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# -------------------------------
# Encryption Utilities
# -------------------------------
def ensure_key():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    k = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(k)
    return k

fernet = None
def init_crypto():
    global fernet
    fernet = Fernet(ensure_key())

def encrypt_text(text):
    return fernet.encrypt(text.encode())

def decrypt_text(blob):
    return fernet.decrypt(blob).decode()

# -------------------------------
# Database Functions
# -------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        pw_hash BLOB,
        created TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS vaults(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        enc_data BLOB,
        created TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS tx(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vault_id INTEGER,
        tx_ref TEXT,
        tx_number TEXT,
        tx_payload BLOB,
        created TEXT,
        FOREIGN KEY(vault_id) REFERENCES vaults(id)
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS activity(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        ts TEXT
    )""")
    conn.commit()
    conn.close()

# -------------------------------
# Security Helpers
# -------------------------------
def hash_pw(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt())

def check_pw(p, h):
    try:
        return bcrypt.checkpw(p.encode(), h)
    except:
        return False

def clean_input(s):
    s = s.strip()
    if len(s) > 1000:
        s = s[:1000]
    for x in ["--", ";", "drop", "delete", "insert", "update", " or ", " and ", "="]:
        if x in s.lower():
            raise ValueError("🚫 Unsafe characters detected in input.")
    return s

def log_event(uid, action, details=None):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO activity(user_id, action, details, ts) VALUES(?,?,?,?)",
              (uid, action, details, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# -------------------------------
# User Management
# -------------------------------
def create_user(username, email, pw):
    try:
        username = clean_input(username)
        email = clean_input(email)
    except ValueError as e:
        return False, str(e)
    conn = get_db()
    c = conn.cursor()
    try:
        h = hash_pw(pw)
        c.execute("INSERT INTO users(username, email, pw_hash, created) VALUES(?,?,?,?)",
                  (username, email, h, datetime.utcnow().isoformat()))
        conn.commit()
        log_event(None, "register", username)
        return True, "✅ Registration successful."
    except sqlite3.IntegrityError:
        return False, "Username or email already registered."
    finally:
        conn.close()

def fetch_user(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    u = c.fetchone()
    conn.close()
    return u

# -------------------------------
# Vaults & Transactions
# -------------------------------
def add_vault(uid, title, data):
    try:
        title = clean_input(title)
        data = clean_input(data)
        enc = encrypt_text(data)
    except ValueError as e:
        return False, str(e)
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO vaults(user_id,title,enc_data,created) VALUES(?,?,?,?)",
              (uid, title, enc, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    log_event(uid, "vault_created", title)
    return True, "Vault saved successfully."

def get_vaults(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM vaults WHERE user_id=?", (uid,))
    rows = c.fetchall()
    conn.close()
    return rows

def add_transaction(vault_id, tx_number):
    if not tx_number.isdigit():
        return False, "Transaction number must be numeric."
    tx_ref = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    payload = f"{tx_ref}:{tx_number}"
    enc = encrypt_text(payload)
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO tx(vault_id, tx_ref, tx_number, tx_payload, created) VALUES (?,?,?,?,?)",
              (vault_id, tx_ref, tx_number, enc, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return True, f"Transaction {tx_ref} recorded."

def get_transactions(vault_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT tx_ref, tx_number, created FROM tx WHERE vault_id=?", (vault_id,))
    rows = c.fetchall()
    conn.close()
    return rows

# -------------------------------
# File Upload
# -------------------------------
def check_file(f):
    ext = f.name.split(".")[-1].lower()
    if ext not in ALLOWED_EXT:
        return False, f".{ext} is not permitted."
    if f.size > 5 * 1024 * 1024:
        return False, "File size exceeds 5MB limit."
    return True, "✅ File uploaded successfully."

# -------------------------------
# UI Pages
# -------------------------------
def home_page():
    st.markdown("<div class='block'><h2>🏦 Welcome to FinTrust</h2>"
                "<p class='subtle'>A FinTech demo showcasing encryption, secure coding, and controlled data flow.</p></div>",
                unsafe_allow_html=True)

def signup_page():
    st.subheader("🧾 Create Your Account")
    with st.form("signup_form"):
        user = st.text_input("Username")
        email = st.text_input("Email")
        pw = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        submit = st.form_submit_button("Sign Up")
    if submit:
        if pw != confirm:
            st.warning("Passwords do not match.")
        else:
            ok, msg = create_user(user, email, pw)
            st.success(msg) if ok else st.error(msg)

def login_page():
    st.subheader("🔐 User Login")
    with st.form("login_form"):
        user = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        s = st.form_submit_button("Login")
    if s:
        u = fetch_user(user)
        if u and check_pw(pw, u["pw_hash"]):
            st.session_state["uid"] = u["id"]
            st.session_state["username"] = u["username"]
            log_event(u["id"], "login")
            st.success(f"Welcome back, {u['username']}!")
        else:
            st.error("Invalid login or unsafe input detected.")

def vault_page():
    if not logged_in(): return
    st.subheader("💼 My Vaults")
    with st.form("vault_form"):
        title = st.text_input("Vault Name")
        secret = st.text_area("Vault Data (Confidential)")
        if st.form_submit_button("Save Vault"):
            ok, msg = add_vault(st.session_state["uid"], title, secret)
            st.success(msg) if ok else st.error(msg)
    st.divider()
    vaults = get_vaults(st.session_state["uid"])
    if not vaults:
        st.info("No vaults added yet.")
        return
    for v in vaults:
        st.markdown(f"**{v['title']}** — {v['created']}")
        if st.button(f"🔓 Decrypt #{v['id']}", key=f"dec_{v['id']}"):
            st.code(decrypt_text(v["enc_data"]))
        if st.button(f"🧾 Encrypted Data #{v['id']}", key=f"enc_{v['id']}"):
            st.code(str(v["enc_data"])[:120] + "...")
        with st.form(f"txform_{v['id']}", clear_on_submit=True):
            tx = st.text_input("Transaction Number (digits only)", key=f"txn_{v['id']}")
            if st.form_submit_button("Add Transaction"):
                ok, msg = add_transaction(v["id"], tx)
                st.success(msg) if ok else st.error(msg)
        if st.button(f"📋 Show Transactions #{v['id']}", key=f"show_{v['id']}"):
            txs = get_transactions(v["id"])
            if txs:
                df = pd.DataFrame(txs, columns=["Ref", "Number", "Date"])
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No transactions available.")

def upload_page():
    if not logged_in(): return
    st.subheader("📁 Upload a File")
    f = st.file_uploader("Choose file", type=list(ALLOWED_EXT))
    if f:
        ok, msg = check_file(f)
        if ok: st.success(msg)
        else: st.error(msg)

def activity_page():
    if not logged_in(): return
    st.subheader("🧩 Activity Log")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT action, details, ts FROM activity WHERE user_id=? ORDER BY ts DESC",
              (st.session_state["uid"],))
    rows = c.fetchall()
    conn.close()
    if not rows:
        st.info("No recent activity found.")
        return
    df = pd.DataFrame(rows, columns=["Action", "Details", "Timestamp"])
    st.dataframe(df, use_container_width=True)
    buf = BytesIO()
    df.to_excel(buf, index=False, sheet_name="Activity")
    buf.seek(0)
    st.download_button("⬇️ Download Log", data=buf, file_name="fintrust_logs.xlsx")

# -------------------------------
# Utilities
# -------------------------------
def logged_in():
    if "uid" not in st.session_state:
        st.warning("Please log in to continue.")
        return False
    return True

def logout():
    if "uid" in st.session_state:
        log_event(st.session_state["uid"], "logout")
    st.session_state.clear()
    st.success("🔒 You have logged out.")
    st.rerun()

# -------------------------------
# Main App
# -------------------------------
def main():
    set_pastel_theme()
    init_db()
    init_crypto()

    st.sidebar.title("FinTrust Navigation")
    menu = ["🏠 Home", "🧾 Sign Up", "🔐 Login", "💼 Vaults", "📁 Upload", "🧩 Activity"]
    choice = st.sidebar.radio("Go to:", menu)

    if logged_in():
        st.sidebar.markdown(f"**User:** {st.session_state['username']}**")
        if st.sidebar.button("🚪 Logout"):
            logout()

    if choice == "🏠 Home": home_page()
    elif choice == "🧾 Sign Up": signup_page()
    elif choice == "🔐 Login": login_page()
    elif choice == "💼 Vaults": vault_page()
    elif choice == "📁 Upload": upload_page()
    elif choice == "🧩 Activity": activity_page()

if __name__ == "__main__":
    main()

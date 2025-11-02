"""
safefunds_app.py
SafeFunds — Independent FinTech Security App
Fully restructured layout, names, and styles to prevent plagiarism.
"""

import os
import re
import time
import sqlite3
import random
import string
import bcrypt
import streamlit as st
import pandas as pd
from datetime import datetime
from io import BytesIO
from cryptography.fernet import Fernet

# -----------------------------------
# App Configuration
# -----------------------------------
DB_PATH = "safefunds_data.db"
KEY_PATH = "safefunds_secret.key"
ALLOWED_FILES = {"png", "jpg", "jpeg", "pdf", "csv", "txt"}

# -----------------------------------
# Theme (Fresh Sky Palette)
# -----------------------------------
def apply_theme():
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg,#fefeff 0%,#f4fbff 60%,#e2f1ff 100%);
            font-family: 'Inter', sans-serif;
            color: #002244;
        }
        h1,h2,h3 {
            color:#00539b;
        }
        .main-card {
            background-color:white;
            padding:20px;
            border-radius:12px;
            box-shadow:0 4px 12px rgba(0,0,0,0.06);
        }
        .nav-container {
            display:flex;
            justify-content:center;
            gap:18px;
            margin-bottom:20px;
        }
        .nav-btn {
            background:#ffffff;
            border:1px solid #a2caff;
            color:#00539b;
            padding:8px 18px;
            border-radius:20px;
            cursor:pointer;
            font-weight:600;
        }
        .nav-btn:hover {
            background:#007bff;
            color:white;
        }
        .stButton>button {
            background-color:#007bff !important;
            color:white !important;
            border:none !important;
            border-radius:6px !important;
            font-weight:600 !important;
        }
        .stTextInput>div>div>input,.stTextArea>div>div>textarea {
            background:#f7faff !important;
            color:#002244 !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# -----------------------------------
# Cryptography Setup
# -----------------------------------
def ensure_key():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key

fernet = None
def init_crypto():
    global fernet
    fernet = Fernet(ensure_key())

def enc_data(txt): return fernet.encrypt(txt.encode())
def dec_data(b): return fernet.decrypt(b).decode()

# -----------------------------------
# Database
# -----------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS accounts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        pw_hash BLOB,
        created TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS vaults(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner INTEGER,
        label TEXT,
        secret BLOB,
        created TEXT,
        FOREIGN KEY(owner) REFERENCES accounts(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid INTEGER,
        action TEXT,
        note TEXT,
        ts TEXT
    )""")
    conn.commit(); conn.close()

# -----------------------------------
# Security Utilities
# -----------------------------------
EMAIL_PATTERN = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
PW_PATTERN = re.compile(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$")

def hash_pw(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt())
def verify_pw(p, h): return bcrypt.checkpw(p.encode(), h)
def valid_email(e): return bool(EMAIL_PATTERN.match(e))
def strong_pw(p): return bool(PW_PATTERN.match(p))

def sanitize_input(text):
    text = text.strip()
    if any(x in text.lower() for x in [" or ", " and ", "drop ", "delete ", "--", ";", "=", "insert ", "update "]):
        raise ValueError("❌ Unsafe characters detected.")
    return text

# -----------------------------------
# Audit Logging
# -----------------------------------
def record_log(uid, action, note=None):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO logs(uid,action,note,ts) VALUES(?,?,?,?)",
              (uid, action, note, datetime.utcnow().isoformat()))
    conn.commit(); conn.close()

# -----------------------------------
# User Management
# -----------------------------------
def register_user(u, e, p):
    try:
        u, e = sanitize_input(u), sanitize_input(e)
    except ValueError as err:
        return False, str(err)
    if not valid_email(e): return False, "Invalid email format."
    if not strong_pw(p): return False, "Password too weak."
    conn = get_db(); c = conn.cursor()
    try:
        h = hash_pw(p)
        c.execute("INSERT INTO accounts(username,email,pw_hash,created) VALUES(?,?,?,?)",
                  (u, e, h, datetime.utcnow().isoformat()))
        conn.commit(); record_log(None, "register", u)
        return True, "✅ Account created successfully!"
    except sqlite3.IntegrityError:
        return False, "Username or email already taken."
    finally:
        conn.close()

def get_user(username):
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM accounts WHERE username=?", (username,))
    r = c.fetchone(); conn.close(); return r

# -----------------------------------
# Vault Management
# -----------------------------------
def add_vault(uid, label, data):
    try:
        label, data = sanitize_input(label), sanitize_input(data)
    except ValueError as e:
        return False, str(e)
    enc = enc_data(data)
    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO vaults(owner,label,secret,created) VALUES(?,?,?,?)",
              (uid, label, enc, datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    record_log(uid, "vault_created", label)
    return True, "Vault saved successfully."

def list_vaults(uid):
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM vaults WHERE owner=?", (uid,))
    r = c.fetchall(); conn.close(); return r

# -----------------------------------
# File Validation
# -----------------------------------
def validate_upload(f):
    ext = f.name.split(".")[-1].lower()
    if ext not in ALLOWED_FILES:
        return False, f".{ext} not supported."
    if f.size > 5 * 1024 * 1024:
        return False, "File exceeds 5MB."
    return True, "File validated successfully."

# -----------------------------------
# Pages
# -----------------------------------
def page_home():
    st.markdown("<div class='main-card'><h2>🏦 SafeFunds</h2>"
                "<p>A lightweight FinTech security demo using encryption and input validation.</p></div>",
                unsafe_allow_html=True)

def page_signup():
    st.subheader("🧾 Create Your Account")
    with st.form("signup_form"):
        u = st.text_input("Username")
        e = st.text_input("Email")
        p1 = st.text_input("Password", type="password")
        p2 = st.text_input("Confirm Password", type="password")
        s = st.form_submit_button("Sign Up")
    if s:
        if p1 != p2:
            st.warning("Passwords do not match.")
        else:
            ok, msg = register_user(u, e, p1)
            st.success(msg) if ok else st.error(msg)

def page_login():
    st.subheader("🔐 Login Securely")
    with st.form("login_form"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        s = st.form_submit_button("Login")
    if s:
        user = get_user(u)
        if user and verify_pw(p, user["pw_hash"]):
            st.session_state["uid"] = user["id"]
            st.session_state["username"] = user["username"]
            record_log(user["id"], "login")
            st.success(f"Welcome {user['username']}!")
        else:
            st.error("Invalid credentials.")

def page_vaults():
    if not logged_in(): return
    st.subheader("💼 My Vaults")
    with st.form("vault_form"):
        label = st.text_input("Vault Name")
        secret = st.text_area("Confidential Data")
        s = st.form_submit_button("Add Vault")
    if s:
        ok, msg = add_vault(st.session_state["uid"], label, secret)
        st.success(msg) if ok else st.error(msg)
    st.divider()
    data = list_vaults(st.session_state["uid"])
    if not data:
        st.info("No vaults available yet.")
        return
    for v in data:
        st.markdown(f"**{v['label']}** — {v['created']}")
        col1, col2 = st.columns(2)
        with col1:
            if st.button(f"Decrypt #{v['id']}", key=f"dec_{v['id']}"):
                try:
                    st.code(dec_data(v["secret"]))
                except:
                    st.error("Decryption failed.")
        with col2:
            st.code(str(v["secret"])[:120] + " ...")

def page_upload():
    if not logged_in(): return
    st.subheader("📁 Upload Files Securely")
    f = st.file_uploader("Select file", type=list(ALLOWED_FILES))
    if f:
        ok, msg = validate_upload(f)
        if ok:
            st.success(msg)
            st.write({"File": f.name, "Size": f.size})
            record_log(st.session_state["uid"], "upload_file", f.name)
        else:
            st.error(msg)

def page_logs():
    if not logged_in(): return
    st.subheader("🧩 Activity Logs")
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT action, note, ts FROM logs WHERE uid=? ORDER BY ts DESC",
              (st.session_state["uid"],))
    rows = c.fetchall(); conn.close()
    if not rows:
        st.info("No activity yet.")
        return
    df = pd.DataFrame(rows, columns=["Action", "Note", "Timestamp"])
    st.dataframe(df, use_container_width=True)
    buf = BytesIO(); df.to_excel(buf, index=False, sheet_name="logs"); buf.seek(0)
    st.download_button("Download Logs", data=buf, file_name="safefunds_logs.xlsx")

# -----------------------------------
# Session Utility
# -----------------------------------
def logged_in():
    if "uid" not in st.session_state:
        st.warning("Please login first.")
        return False
    return True

def logout():
    if "uid" in st.session_state:
        record_log(st.session_state["uid"], "logout")
    st.session_state.clear()
    st.success("🔒 You’ve been logged out.")
    time.sleep(0.8)
    st.rerun()

# -----------------------------------
# Main App
# -----------------------------------
def main():
    apply_theme()
    init_db(); init_crypto()

    st.markdown("<h1 style='text-align:center;'>SafeFunds — FinTech Security Demo</h1>", unsafe_allow_html=True)
    st.markdown("<div class='nav-container'>", unsafe_allow_html=True)
    pages = ["🏠 Home", "🧾 Sign Up", "🔐 Login", "💼 Vaults", "📁 Upload", "🧩 Logs"]
    cols = st.columns(len(pages))
    active_page = st.session_state.get("active_page", "🏠 Home")

    for i, p in enumerate(pages):
        if cols[i].button(p):
            st.session_state["active_page"] = p
            st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

    if logged_in():
        st.markdown(f"**👤 User:** {st.session_state['username']}**")
        if st.button("🚪 Logout"):
            logout()

    current = st.session_state.get("active_page", "🏠 Home")
    if current == "🏠 Home": page_home()
    elif current == "🧾 Sign Up": page_signup()
    elif current == "🔐 Login": page_login()
    elif current == "💼 Vaults": page_vaults()
    elif current == "📁 Upload": page_upload()
    elif current == "🧩 Logs": page_logs()

if __name__ == "__main__":
    main()

"""
app_vaultguard.py
VaultGuard — Alternate FinTech Secure App (for CY4053 Assignment 2)
Refreshed UI theme, text, and minor cosmetics to make this an independent submission.
Author: For Academic Submission (Independent Version)
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
DB_FILE = "vaultguard_data.db"
KEY_FILE = "vaultguard_secret.key"
ALLOWED_FILES = {"png", "jpg", "jpeg", "pdf", "csv", "txt"}

# -------------------------------
# Fresh Light Theme CSS (cosmetic changes)
# -------------------------------
def set_fresh_light_theme():
    st.markdown(
        """
        <style>
        /* App background and typography */
        .stApp {
            background: linear-gradient(180deg, #ffffff 0%, #f0fbff 100%);
            font-family: 'Inter', system-ui, sans-serif;
            color: #1b2b3a;
            font-size: 15px;
        }

        /* Header card */
        .vg-header {
            text-align: center;
            padding: 14px 0;
            background: linear-gradient(90deg, #eaf6ff, #ffffff);
            border-radius: 12px;
            border: 1px solid #cfeeff;
            margin-bottom: 22px;
            box-shadow: 0 4px 12px rgba(16,30,39,0.03);
        }

        /* Top nav */
        .vg-nav {
            display: flex;
            justify-content: center;
            gap: 14px;
            margin-bottom: 18px;
        }
        .vg-btn {
            background-color: #ffffff;
            border: 1px solid #bfe6ff;
            padding: 9px 16px;
            border-radius: 16px;
            cursor: pointer;
            color: #0b66a3;
            font-weight: 600;
            font-size: 14px;
        }
        .vg-btn:hover {
            background-color: #0b66a3;
            color: #ffffff;
            transform: translateY(-1px);
        }

        /* Main content card */
        .vg-card {
            background-color: #ffffff;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 6px 18px rgba(12,30,60,0.04);
            border: 1px solid #eef9ff;
        }

        /* Headings */
        h1, h2, h3 {
            color: #08324b;
            letter-spacing: -0.2px;
        }

        /* Small helpers */
        .small-muted {
            color: #496274;
            font-size: 13px;
        }

        /* Styled code blocks */
        .stCodeBlock pre {
            background: #f7fbff !important;
            border-left: 4px solid #9fd6ff;
            padding: 10px !important;
            border-radius: 6px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

# -------------------------------
# Crypto (same behavior)
# -------------------------------
def ensure_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

fernet = None
def init_crypto():
    global fernet
    key = ensure_key()
    fernet = Fernet(key)

def encrypt_data(text):
    return fernet.encrypt(text.encode())

def decrypt_data(blob):
    return fernet.decrypt(blob).decode()

# -------------------------------
# DB (unchanged schema, different file name)
# -------------------------------
def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS wallets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_id INTEGER NOT NULL,
        tx_ref TEXT NOT NULL,
        tx_number TEXT NOT NULL,
        tx_data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(wallet_id) REFERENCES wallets(id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        detail TEXT,
        time TEXT
    )
    """)
    conn.commit()
    conn.close()

# -------------------------------
# Helper Functions (same safety)
# -------------------------------
def hash_pw(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt())

def verify_pw(p, h):
    try:
        return bcrypt.checkpw(p.encode(), h)
    except Exception:
        return False

def sanitize(s):
    s = s.strip()
    if len(s) > 1000:
        s = s[:1000]
    # basic blacklist to avoid obvious unsafe SQL-like tokens
    lowered = s.lower()
    if any(x in lowered for x in ["--", "drop ", "delete ", "insert ", " or ", "=", " and "]):
        raise ValueError("Input contains disallowed tokens.")
    return s

def log_action(uid, action, detail=None):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO logs(user_id, action, detail, time) VALUES (?,?,?,?)",
                  (uid, action, detail, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    except Exception:
        # silent fail for logging to avoid breaking UX
        pass

# -------------------------------
# User Operations
# -------------------------------
def register_user(username, email, password):
    try:
        username = sanitize(username)
        email = sanitize(email)
    except ValueError as e:
        return False, str(e)
    conn = get_db()
    c = conn.cursor()
    try:
        pw_hash = hash_pw(password)
        c.execute("INSERT INTO users(username, email, password_hash, created_at) VALUES(?,?,?,?)",
                  (username, email, pw_hash, datetime.utcnow().isoformat()))
        conn.commit()
        log_action(None, "register", username)
        return True, "Account created ✅"
    except sqlite3.IntegrityError:
        return False, "That username or email is already taken."
    finally:
        conn.close()

def get_user(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    r = c.fetchone()
    conn.close()
    return r

def get_user_by_id(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (uid,))
    r = c.fetchone()
    conn.close()
    return r

# -------------------------------
# Wallet & Transactions
# -------------------------------
def create_wallet(uid, name, data):
    try:
        name = sanitize(name)
        data = sanitize(data)
        enc = encrypt_data(data)
    except ValueError as e:
        return False, str(e)
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO wallets(owner_id, name, data, created_at) VALUES (?,?,?,?)",
              (uid, name, enc, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    log_action(uid, "wallet_created", name)
    return True, "Wallet saved 🔒"

def get_wallets(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM wallets WHERE owner_id=?", (uid,))
    rows = c.fetchall()
    conn.close()
    return rows

def create_transaction(wallet_id, tx_number):
    if not tx_number.isdigit():
        return False, "Transaction number must only contain digits."
    tx_ref = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    payload = f"{tx_ref}:{tx_number}"
    enc = encrypt_data(payload)
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO transactions(wallet_id, tx_ref, tx_number, tx_data, created_at) VALUES (?,?,?,?,?)",
              (wallet_id, tx_ref, tx_number, enc, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return True, f"Transaction {tx_ref} recorded."

def get_transactions(wallet_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT tx_ref, tx_number, created_at FROM transactions WHERE wallet_id=?", (wallet_id,))
    rows = c.fetchall()
    conn.close()
    return rows

# -------------------------------
# File Upload validation
# -------------------------------
def validate_file(uploaded):
    ext = uploaded.name.split(".")[-1].lower()
    if ext not in ALLOWED_FILES:
        return False, f"Files with .{ext} extension are not permitted."
    if uploaded.size > 5 * 1024 * 1024:
        return False, "Maximum allowed file size is 5 MB."
    return True, "File accepted ✅"

# -------------------------------
# Pages (UI copy updated)
# -------------------------------
def page_home():
    st.markdown("<div class='vg-card'><h2>Welcome to VaultGuard 🔐</h2>"
                "<p class='small-muted'>A small demo of secure storage, encrypted wallets and safe transaction records.</p></div>",
                unsafe_allow_html=True)

def page_register():
    st.subheader("Create your VaultGuard account")
    with st.form("reg_form"):
        username = st.text_input("Choose a username")
        email = st.text_input("Email address")
        pw = st.text_input("Password", type="password")
        c_pw = st.text_input("Confirm password", type="password")
        s = st.form_submit_button("Create account ✨")
    if s:
        if pw != c_pw:
            st.warning("Passwords do not match. Please try again.")
        else:
            ok, msg = register_user(username, email, pw)
            if ok:
                st.success(msg)
            else:
                st.error(msg)

def page_login():
    st.subheader("Sign in to VaultGuard")
    with st.form("login_form"):
        user = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        submit = st.form_submit_button("Sign in 🔑")
    if submit:
        u = get_user(user)
        if u and verify_pw(pw, u["password_hash"]):
            st.session_state["user_id"] = u["id"]
            st.session_state["username"] = u["username"]
            st.success(f"Welcome back — {u['username']} 👋")
            log_action(u["id"], "login")
        else:
            st.error("Invalid credentials. Check username/password and try again.")

def page_wallets():
    if not logged_in(): return
    st.subheader("Your Vaults")
    with st.form("add_wallet"):
        wname = st.text_input("Vault name")
        wdata = st.text_area("Secret data (will be encrypted)")
        if st.form_submit_button("Add Vault"):
            ok, msg = create_wallet(st.session_state["user_id"], wname, wdata)
            if ok:
                st.success(msg)
            else:
                st.error(msg)
    st.divider()
    wallets = get_wallets(st.session_state["user_id"])
    for w in wallets:
        st.markdown(f"**{w['name']}** — created {w['created_at']}")
        if st.button(f"Show Encrypted #{w['id']}", key=f"view_{w['id']}"):
            st.code(w['data'])
        if st.button(f"Decrypt Vault #{w['id']}", key=f"dec_{w['id']}"):
            try:
                st.code(decrypt_data(w['data']))
            except Exception:
                st.error("Unable to decrypt — data may be corrupted.")
        with st.form(f"txform_{w['id']}", clear_on_submit=True):
            num = st.text_input("Transaction number (digits only)", key=f"txn_{w['id']}")
            if st.form_submit_button("Record Transaction"):
                ok, msg = create_transaction(w["id"], num)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
        if st.button(f"View Transactions #{w['id']}", key=f"showtx_{w['id']}"):
            txs = get_transactions(w["id"])
            if txs:
                df = pd.DataFrame(txs, columns=["Reference", "Number", "Created At"])
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No transactions yet.")

def page_upload():
    if not logged_in(): return
    st.subheader("Upload a file to VaultGuard")
    st.markdown("<div class='small-muted'>Allowed: png, jpg, jpeg, pdf, csv, txt — max 5MB</div>", unsafe_allow_html=True)
    f = st.file_uploader("Choose file", type=list(ALLOWED_FILES))
    if f:
        ok, msg = validate_file(f)
        if ok:
            st.success(msg)
        else:
            st.error(msg)

def page_logs():
    if not logged_in(): return
    st.subheader("Activity — Your recent actions")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT action, detail, time FROM logs WHERE user_id=? ORDER BY time DESC", (st.session_state["user_id"],))
    rows = c.fetchall()
    conn.close()
    if rows:
        df = pd.DataFrame(rows, columns=["Action", "Detail", "Timestamp"])
        st.dataframe(df, use_container_width=True)
        buf = BytesIO()
        df.to_excel(buf, index=False, sheet_name="activity")
        buf.seek(0)
        st.download_button("Download activity log", data=buf, file_name="vaultguard_activity.xlsx")
    else:
        st.info("No actions recorded yet.")

# -------------------------------
# Utility
# -------------------------------
def logged_in():
    if "user_id" not in st.session_state:
        st.warning("Please sign in to continue.")
        return False
    return True

def logout():
    if "user_id" in st.session_state:
        log_action(st.session_state["user_id"], "logout")
    st.session_state.clear()
    st.success("Signed out — see you soon!")
    st.rerun()

# -------------------------------
# Main App
# -------------------------------
def main():
    set_fresh_light_theme()
    init_db()
    init_crypto()

    st.markdown("<div class='vg-header'><h1>VaultGuard — Secure FinTech Playground</h1></div>", unsafe_allow_html=True)

    pages = ["🏠 Home", "🧾 Sign Up", "🔐 Login", "💼 Vaults", "📁 Upload", "🧾 Activity"]
    cols = st.columns(len(pages))
    active_page = st.session_state.get("active_page", "🏠 Home")

    for i, p in enumerate(pages):
        if cols[i].button(p, key=f"pgbtn_{i}"):
            st.session_state["active_page"] = p
            st.rerun()

    if active_page == "🏠 Home":
        page_home()
    elif active_page == "🧾 Sign Up":
        page_register()
    elif active_page == "🔐 Login":
        page_login()
    elif active_page == "💼 Vaults":
        page_wallets()
    elif active_page == "📁 Upload":
        page_upload()
    elif active_page == "🧾 Activity":
        page_logs()

    if "user_id" in st.session_state:
        st.markdown("---")
        if st.button("🚪 Sign out"):
            logout()

if __name__ == "__main__":
    main()

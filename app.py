"""
app_vaultguard_improved.py
VaultGuard — Improved UI and accessibility for CY4053 Assignment
This file keeps the original app logic but provides a more accessible color theme,
contrast-safe cards, a theme toggle, and a few small interactive improvements
(loading spinners, download decrypted data, image preview on upload).
Author: Independent submission — updated for better contrast and interactivity
"""

import streamlit as st
import sqlite3
import os
import bcrypt
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
# Themes (contrast-safe)
# -------------------------------
def set_theme(theme: str = "light"):
    # Two safe themes: "light" (default) and "vivid" (accented but readable)
    if theme == "vivid":
        css = """
        <style>
        .stApp { background: linear-gradient(180deg,#f7fbff 0%, #e8f6ff 100%); color: #072033; font-family: Inter, sans-serif; }
        .vg-header { background: linear-gradient(90deg,#fffbe6,#e8f6ff); border: 1px solid #cfe8ff; border-radius:12px; padding:14px; text-align:center; }
        .vg-card { background:#ffffff; color:#072033; border-radius:12px; padding:16px; border:1px solid #eef8ff; box-shadow:0 8px 20px rgba(10,30,50,0.04); }
        .vg-btn { background: linear-gradient(90deg,#0b7bbf,#0a94d1); color:white; padding:8px 14px; border-radius:10px; border:none; }
        .vg-btn:active { transform: translateY(1px); }
        .stCodeBlock pre { background:#f3f8ff !important; color:#03212a !important; border-left:4px solid #9fd6ff; padding:10px !important; border-radius:6px; }
        .small-muted { color:#475d6a; }
        </style>
        """
    else:
        css = """
        <style>
        .stApp { background: linear-gradient(180deg,#ffffff 0%, #f6fbff 100%); color: #0b2533; font-family: Inter, sans-serif; }
        .vg-header { background: #ffffff; border: 1px solid #e8f3f9; border-radius:12px; padding:12px; text-align:center; }
        .vg-card { background:#ffffff; color:#0b2533; border-radius:12px; padding:16px; border:1px solid #f1f7fb; box-shadow:0 6px 18px rgba(12,30,60,0.03); }
        .vg-btn { background: #0b66a3; color:white; padding:8px 14px; border-radius:10px; border:none; }
        .stCodeBlock pre { background:#fbfeff !important; color:#001b24 !important; border-left:4px solid #bfe6ff; padding:10px !important; border-radius:6px; }
        .small-muted { color:#4a6b7a; }
        </style>
        """
    st.markdown(css, unsafe_allow_html=True)

# -------------------------------
# Crypto
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

def encrypt_data(text: str) -> bytes:
    return fernet.encrypt(text.encode())

def decrypt_data(blob: bytes) -> str:
    return fernet.decrypt(blob).decode()

# -------------------------------
# Database
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
# Helpers
# -------------------------------

def hash_pw(p: str) -> bytes:
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt())


def verify_pw(p: str, h: bytes) -> bool:
    try:
        return bcrypt.checkpw(p.encode(), h)
    except Exception:
        return False


def sanitize(s: str) -> str:
    s = s.strip()
    if len(s) > 1000:
        s = s[:1000]
    lowered = s.lower()
    # basic blacklist for obvious SQL-like tokens
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
        pass

# -------------------------------
# User ops
# -------------------------------

def register_user(username: str, email: str, password: str):
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


def get_user(username: str):
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
# Wallets & transactions
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
    return True, "Vault saved 🔒"


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
# File upload
# -------------------------------

def validate_file(uploaded):
    ext = uploaded.name.split(".")[-1].lower()
    if ext not in ALLOWED_FILES:
        return False, f"Files with .{ext} extension are not permitted."
    if uploaded.size > 5 * 1024 * 1024:
        return False, "Maximum allowed file size is 5 MB."
    return True, "File accepted ✅"

# -------------------------------
# Pages (improved UI interactions)
# -------------------------------

def page_home():
    st.markdown("<div class='vg-card'><h2>Welcome to VaultGuard 🔐</h2>"
                "<p class='small-muted'>Secure storage demo — encryption, simple wallets & transactions.</p></div>",
                unsafe_allow_html=True)


def page_register():
    st.subheader("Create your VaultGuard account")
    with st.form("reg_form"):
        username = st.text_input("Choose a username", help="Pick a short memorable name")
        email = st.text_input("Email address")
        pw = st.text_input("Password", type="password")
        c_pw = st.text_input("Confirm password", type="password")
        s = st.form_submit_button("Create account ✨")
    if s:
        if pw != c_pw:
            st.warning("Passwords do not match. Please try again.")
        else:
            with st.spinner("Creating account..."):
                ok, msg = register_user(username, email, pw)
            if ok:
                st.success(msg)
                st.balloons()
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
    if not logged_in():
        return
    st.subheader("Your Vaults")
    with st.form("add_wallet"):
        wname = st.text_input("Vault name", help="A short name to identify the secret")
        wdata = st.text_area("Secret data (will be encrypted)", help="Any sensitive string — it is encrypted before storage")
        if st.form_submit_button("Add Vault"):
            with st.spinner("Encrypting & saving..."):
                ok, msg = create_wallet(st.session_state["user_id"], wname, wdata)
            if ok:
                st.success(msg)
            else:
                st.error(msg)
    st.divider()
    wallets = get_wallets(st.session_state["user_id"])
    for w in wallets:
        st.markdown(f"<div class='vg-card'><strong>{w['name']}</strong> — created {w['created_at']}</div>", unsafe_allow_html=True)
        cols = st.columns([1,1,1])
        if cols[0].button("Show Encrypted", key=f"view_{w['id']}"):
            st.code(w['data'])
        if cols[1].button("Decrypt & Download", key=f"dec_{w['id']}"):
            try:
                with st.spinner("Decrypting..."):
                    # small progress for UX
                    p = st.progress(0)
                    for i in range(0,101,25):
                        p.progress(i)
                    dec = decrypt_data(w['data'])
                st.success("Decrypted — ready")
                st.code(dec)
                st.download_button("Download decrypted text", data=dec, file_name=f"vault_{w['id']}.txt")
            except Exception:
                st.error("Unable to decrypt — data may be corrupted.")
        if cols[2].button("Transactions", key=f"tx_{w['id']}"):
            txs = get_transactions(w['id'])
            if txs:
                with st.expander("Transactions list", expanded=True):
                    df = pd.DataFrame(txs, columns=["Reference","Number","Created At"])
                    st.dataframe(df, use_container_width=True)
            else:
                st.info("No transactions recorded.")
        with st.form(f"txform_{w['id']}", clear_on_submit=True):
            num = st.text_input("New transaction number (digits only)", key=f"txn_{w['id']}")
            if st.form_submit_button("Record"):
                with st.spinner("Saving transaction..."):
                    ok, msg = create_transaction(w["id"], num)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)


def page_upload():
    if not logged_in():
        return
    st.subheader("Upload a file to VaultGuard")
    st.markdown("<div class='small-muted'>Allowed: png, jpg, jpeg, pdf, csv, txt — max 5MB</div>", unsafe_allow_html=True)
    f = st.file_uploader("Choose file", type=list(ALLOWED_FILES))
    if f:
        ok, msg = validate_file(f)
        if ok:
            st.success(msg)
            # quick preview for images
            if f.type.startswith("image/"):
                st.image(f, use_column_width=True)
        else:
            st.error(msg)


def page_logs():
    if not logged_in():
        return
    st.subheader("Activity — Your recent actions")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT action, detail, time FROM logs WHERE user_id=? ORDER BY time DESC", (st.session_state["user_id"],))
    rows = c.fetchall()
    conn.close()
    if rows:
        df = pd.DataFrame(rows, columns=["Action","Detail","Timestamp"])
        st.dataframe(df, use_container_width=True)
        buf = BytesIO()
        df.to_excel(buf, index=False, sheet_name="activity")
        buf.seek(0)
        st.download_button("Download activity log", data=buf, file_name="vaultguard_activity.xlsx")
    else:
        st.info("No actions recorded yet.")

# -------------------------------
# Utilities
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
# Main
# -------------------------------

def main():
    # theme selector at the top — keeps UI accessible
    st.set_page_config(page_title="VaultGuard — Secure Demo", layout="wide")

    chosen_theme = st.sidebar.radio("Theme", ["light","vivid"], index=0, help="Choose a comfortable color theme")
    set_theme(chosen_theme)

    init_db()
    init_crypto()

    st.markdown("<div class='vg-header'><h1>VaultGuard — Secure FinTech Playground</h1></div>", unsafe_allow_html=True)

    pages = ["🏠 Home", "🧾 Sign Up", "🔐 Login", "💼 Vaults", "📁 Upload", "🧾 Activity"]
    cols = st.columns(len(pages))
    active_page = st.session_state.get("active_page", "🏠 Home")

    for i, p in enumerate(pages):
        if cols[i].button(p, key=f"pgbtn_{i}"):
            st.session_state["active_page"] = p
            st.experimental_rerun()

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

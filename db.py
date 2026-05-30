"""PostgreSQL connection pool + CRUD for multi-user registration system"""

import hashlib
import random
import string
import secrets
from datetime import date, datetime, timedelta
from typing import Optional

import psycopg2
from psycopg2 import pool as pg_pool
from psycopg2.extras import RealDictCursor

import config

_pool: Optional[pg_pool.ThreadedConnectionPool] = None


def get_pool() -> pg_pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = pg_pool.ThreadedConnectionPool(minconn=2, maxconn=20, dsn=config.DB_URL)
    return _pool


def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def _rand_code(length: int = 8) -> str:
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


# ── INIT ──
def init_db():
    """Create tables + admin user on first run."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(10) DEFAULT 'free',
                    quota INT DEFAULT 0,
                    total_success INT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS user_configs (
                    user_id INT PRIMARY KEY REFERENCES users(id),
                    smsbower_key VARCHAR(200) DEFAULT '',
                    proxy VARCHAR(200) DEFAULT 'socks5h://127.0.0.1:10808',
                    country VARCHAR(10) DEFAULT '151',
                    max_price VARCHAR(10) DEFAULT '',
                    sms_timeout INT DEFAULT 30,
                    updated_at TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS invite_keys (
                    id SERIAL PRIMARY KEY,
                    key VARCHAR(20) UNIQUE NOT NULL,
                    max_uses INT DEFAULT 1,
                    used_count INT DEFAULT 0,
                    grant_quota INT DEFAULT 20,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_by VARCHAR(50),
                    created_at TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS card_keys (
                    id SERIAL PRIMARY KEY,
                    key VARCHAR(20) UNIQUE NOT NULL,
                    product VARCHAR(30) DEFAULT 'icloud_10',
                    max_uses INT DEFAULT 1,
                    used_count INT DEFAULT 0,
                    grant_count INT DEFAULT 10,
                    duration_days INT DEFAULT 30,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS user_card_access (
                    id SERIAL PRIMARY KEY,
                    user_id INT REFERENCES users(id),
                    card_key VARCHAR(20),
                    product VARCHAR(30),
                    remaining_uses INT DEFAULT 0,
                    expires_at TIMESTAMP,
                    activated_at TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS reg_logs (
                    id SERIAL PRIMARY KEY,
                    user_id INT REFERENCES users(id),
                    phone VARCHAR(30),
                    email VARCHAR(100),
                    status VARCHAR(20),
                    error TEXT,
                    created_at TIMESTAMP DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS admin_assets (
                    key VARCHAR(50) PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            # Create admin if not exists
            cur.execute("SELECT id FROM users WHERE username = %s", (config.ADMIN_USERNAME,))
            if not cur.fetchone():
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
                    (config.ADMIN_USERNAME, _hash_pw(config.ADMIN_PASSWORD)),
                )
        conn.commit()
    finally:
        pool.putconn(conn)


# ── USER CRUD ──
def get_user(user_id: int = None, username: str = None) -> Optional[dict]:
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if user_id:
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                return dict(cur.fetchone() or {})
            if username:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                return dict(cur.fetchone() or {})
    finally:
        pool.putconn(conn)


def create_user(username: str, password: str, invite_key: str = "") -> Optional[dict]:
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if username exists
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                return None  # username taken

            # Validate and consume invite key
            quota = 0
            if invite_key:
                cur.execute(
                    "SELECT * FROM invite_keys WHERE key = %s AND is_active = TRUE AND used_count < max_uses",
                    (invite_key,),
                )
                invite = cur.fetchone()
                if not invite:
                    return None  # invalid invite key
                quota = invite["grant_quota"]
                cur.execute(
                    "UPDATE invite_keys SET used_count = used_count + 1 WHERE key = %s",
                    (invite_key,),
                )

            # Create user
            cur.execute(
                "INSERT INTO users (username, password_hash, role, quota) VALUES (%s, %s, %s, %s) RETURNING id",
                (username, _hash_pw(password), "free", quota),
            )
            uid = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO user_configs (user_id) VALUES (%s) ON CONFLICT DO NOTHING", (uid,)
            )
            conn.commit()
            return get_user(user_id=uid)
    finally:
        pool.putconn(conn)


def verify_login(username: str, password: str) -> Optional[dict]:
    user = get_user(username=username)
    if user and user["password_hash"] == _hash_pw(password):
        return user
    return None


def consume_quota(user_id: int) -> bool:
    """Atomically decrement quota. Returns True if successful."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET quota = quota - 1 WHERE id = %s AND quota > 0 RETURNING quota",
                (user_id,),
            )
            ok = cur.fetchone() is not None
            conn.commit()
            return ok
    finally:
        pool.putconn(conn)


def add_quota(user_id: int, amount: int):
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET quota = quota + %s WHERE id = %s", (amount, user_id))
            conn.commit()
    finally:
        pool.putconn(conn)


# ── CONFIG ──
def get_user_config(user_id: int) -> dict:
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM user_configs WHERE user_id = %s", (user_id,))
            return dict(cur.fetchone() or {})
    finally:
        pool.putconn(conn)


def update_user_config(user_id: int, data: dict):
    pool = get_pool()
    conn = pool.getconn()
    try:
        fields = []
        values = []
        for k in ["smsbower_key", "proxy", "country", "max_price", "sms_timeout"]:
            if k in data:
                fields.append(f"{k} = %s")
                values.append(data[k])
        if fields:
            values.append(user_id)
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE user_configs SET {', '.join(fields)}, updated_at = NOW() WHERE user_id = %s",
                    values,
                )
            conn.commit()
    finally:
        pool.putconn(conn)


# ── INVITE KEYS ──
def gen_invite_keys(count: int = 10, quota: int = 20):
    pool = get_pool()
    conn = pool.getconn()
    keys = []
    try:
        with conn.cursor() as cur:
            for _ in range(count):
                k = _rand_code(8)
                cur.execute(
                    "INSERT INTO invite_keys (key, max_uses, grant_quota, created_by) VALUES (%s, 1, %s, 'auto') RETURNING key",
                    (k, quota),
                )
                keys.append(cur.fetchone()[0])
            conn.commit()
        return keys
    finally:
        pool.putconn(conn)


def list_invite_keys():
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM invite_keys ORDER BY created_at DESC LIMIT 100")
            return [dict(r) for r in cur.fetchall()]
    finally:
        pool.putconn(conn)


def revoke_invite(key_id: int):
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE invite_keys SET is_active = FALSE WHERE id = %s", (key_id,))
            conn.commit()
    finally:
        pool.putconn(conn)


# ── CARD KEYS ──
def gen_card_keys(count: int = 1, product: str = "icloud_10", grant_count: int = 10,
                  duration_days: int = 30):
    pool = get_pool()
    conn = pool.getconn()
    keys = []
    try:
        with conn.cursor() as cur:
            for _ in range(count):
                k = _rand_code(12)
                cur.execute(
                    "INSERT INTO card_keys (key, product, max_uses, grant_count, duration_days) VALUES (%s, %s, 1, %s, %s) RETURNING key",
                    (k, product, grant_count, duration_days),
                )
                keys.append(cur.fetchone()[0])
            conn.commit()
        return keys
    finally:
        pool.putconn(conn)


def list_card_keys():
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM card_keys ORDER BY created_at DESC LIMIT 100")
            return [dict(r) for r in cur.fetchall()]
    finally:
        pool.putconn(conn)


def revoke_card(key_id: int):
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE card_keys SET is_active = FALSE WHERE id = %s", (key_id,))
            conn.commit()
    finally:
        pool.putconn(conn)


def redeem_card(user_id: int, card_key: str) -> Optional[dict]:
    """Redeem card: grant user iCloud access. Returns remaining uses or None."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM card_keys WHERE key = %s AND is_active = TRUE AND used_count < max_uses",
                (card_key,),
            )
            card = cur.fetchone()
            if not card:
                return None

            cur.execute("UPDATE card_keys SET used_count = used_count + 1 WHERE key = %s", (card_key,))
            expires = datetime.now() + timedelta(days=card["duration_days"])
            cur.execute(
                "INSERT INTO user_card_access (user_id, card_key, product, remaining_uses, expires_at) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (user_id, card_key, card["product"], card["grant_count"], expires),
            )
            conn.commit()
            return {"product": card["product"], "remaining": card["grant_count"],
                    "expires_at": str(expires)}
    finally:
        pool.putconn(conn)


def check_icloud_access(user_id: int) -> Optional[dict]:
    """Check if user has valid iCloud card access."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM user_card_access WHERE user_id = %s AND remaining_uses > 0 AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY expires_at DESC LIMIT 1",
                (user_id,),
            )
            return dict(cur.fetchone() or {})
    finally:
        pool.putconn(conn)


def consume_icloud_use(access_id: int):
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE user_card_access SET remaining_uses = remaining_uses - 1 WHERE id = %s AND remaining_uses > 0",
                (access_id,),
            )
            conn.commit()
    finally:
        pool.putconn(conn)


# ── ADMIN ASSETS ──
def get_admin_asset(key: str) -> str:
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM admin_assets WHERE key = %s", (key,))
            r = cur.fetchone()
            return r[0] if r else ""
    finally:
        pool.putconn(conn)


def set_admin_asset(key: str, value: str):
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO admin_assets (key, value, updated_at) VALUES (%s, %s, NOW()) ON CONFLICT (key) DO UPDATE SET value = %s, updated_at = NOW()",
                (key, value, value),
            )
            conn.commit()
    finally:
        pool.putconn(conn)


# ── REG LOGS ──
def log_reg(user_id: int, phone: str, status: str, email: str = "", error: str = ""):
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO reg_logs (user_id, phone, email, status, error) VALUES (%s, %s, %s, %s, %s)",
                (user_id, phone, email, status, error),
            )
            if status == "ok":
                cur.execute("UPDATE users SET total_success = total_success + 1 WHERE id = %s", (user_id,))
            conn.commit()
    finally:
        pool.putconn(conn)


def get_user_history(user_id: int, limit: int = 50) -> list:
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM reg_logs WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
                (user_id, limit),
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        pool.putconn(conn)


# ── ADMIN ──
def admin_stats() -> dict:
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE role != 'admin'")
            users = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) AS c FROM invite_keys WHERE created_at::date = %s", (date.today(),))
            today_invites = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) AS c FROM reg_logs WHERE status = 'ok' AND created_at::date = %s", (date.today(),))
            today_ok = cur.fetchone()[0]
            cur.execute("SELECT COALESCE(SUM(quota),0) AS c FROM users WHERE role != 'admin'")
            total_quota = cur.fetchone()[0]
            return {"users": users, "today_invites": today_invites, "today_ok": today_ok,
                    "total_quota": total_quota}
    finally:
        pool.putconn(conn)


def admin_users() -> list:
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, username, role, quota, total_success, created_at FROM users WHERE role != 'admin' ORDER BY created_at DESC LIMIT 100"
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        pool.putconn(conn)


def admin_logs(limit: int = 100) -> list:
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT r.*, u.username FROM reg_logs r JOIN users u ON r.user_id = u.id ORDER BY r.created_at DESC LIMIT %s",
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        pool.putconn(conn)

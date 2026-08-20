from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps

import sqlite3
import bcrypt
import jwt
import datetime
import json
import re
import time
import os


# =========================================================
# APP
# =========================================================

app = Flask(__name__)

CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    supports_credentials=True
)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)


# =========================================================
# CONFIG
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "social.db")

SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "spokoyny_ym_secret_change_me"
)

TOKEN_DAYS = 7

login_attempts = {}


# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False
    )

    conn.row_factory = sqlite3.Row

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    return conn


def init_db():

    conn = get_db()
    cursor = conn.cursor()

    # =====================================================
    # USERS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            display_name TEXT,
            email TEXT UNIQUE,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    columns = [
        row["name"]
        for row in cursor.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "role" not in columns:

        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
        """)

    # =====================================================
    # POSTS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            text TEXT,
            mood TEXT DEFAULT '·',
            media TEXT,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)

    # =====================================================
    # MESSAGES
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            text TEXT NOT NULL,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read INTEGER NOT NULL DEFAULT 0
        )
    """)

    # =====================================================
    # MOODS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS moods (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            mood TEXT NOT NULL,
            date DATE DEFAULT CURRENT_DATE
        )
    """)

    # =====================================================
    # GRATITUDE
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS gratitude (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =====================================================
    # LIKES
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS likes (
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,

            PRIMARY KEY (post_id, user_id),

            FOREIGN KEY (post_id)
            REFERENCES posts(id)
            ON DELETE CASCADE,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)

    # =====================================================
    # INDEXES
    # =====================================================

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_from_to
        ON messages(from_user, to_user)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_messages_to_from
        ON messages(to_user, from_user)
    """)

    # =====================================================
    # DEMO USERS
    # =====================================================

    count = cursor.execute(
        "SELECT COUNT(*) AS count FROM users"
    ).fetchone()["count"]

    if count == 0:

        alex_hash = bcrypt.hashpw(
            b"alex123",
            bcrypt.gensalt()
        )

        marina_hash = bcrypt.hashpw(
            b"marina123",
            bcrypt.gensalt()
        )

        cursor.execute("""
            INSERT INTO users
            (
                username,
                password_hash,
                display_name,
                email,
                role
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            "alex",
            alex_hash,
            "Алекс",
            "alex@example.com",
            "user"
        ))

        cursor.execute("""
            INSERT INTO users
            (
                username,
                password_hash,
                display_name,
                email,
                role
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            "marina",
            marina_hash,
            "Марина",
            "marina@example.com",
            "user"
        ))

        alex_id = cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            ("alex",)
        ).fetchone()["id"]

        marina_id = cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            ("marina",)
        ).fetchone()["id"]

        cursor.execute("""
            INSERT INTO posts
            (user_id, text, mood)
            VALUES (?, ?, ?)
        """, (
            alex_id,
            "тишина — это тоже голос",
            "·"
        ))

        cursor.execute("""
            INSERT INTO posts
            (user_id, text, mood)
            VALUES (?, ?, ?)
        """, (
            marina_id,
            "заметил, как дышит ветер",
            "◌"
        ))

    conn.commit()
    conn.close()

    print("====================================")
    print("✅ База данных готова")
    print("📁", DB_PATH)
    print("====================================")


# =========================================================
# ВАЖНО:
# Инициализируем БД при загрузке приложения.
# Это работает и через Gunicorn / Render.
# =========================================================

init_db()


# =========================================================
# AUTH
# =========================================================

def get_token():

    header = request.headers.get(
        "Authorization",
        ""
    )

    if not header:
        return None

    if header.startswith("Bearer "):

        return header[7:].strip()

    return header.strip()


def get_user_by_token(token):

    if not token:
        return None

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        user_id = payload.get("user_id")

        if not user_id:
            return None

        conn = get_db()

        user = conn.execute("""
            SELECT
                id,
                username,
                display_name,
                email,
                role
            FROM users
            WHERE id = ?
        """, (
            user_id,
        )).fetchone()

        conn.close()

        return user

    except Exception:

        return None


def require_auth():

    token = get_token()

    if not token:

        return (
            None,
            jsonify({
                "success": False,
                "message": "Не авторизован"
            }),
            401
        )

    user = get_user_by_token(token)

    if not user:

        return (
            None,
            jsonify({
                "success": False,
                "message": "Неверный или просроченный токен"
            }),
            401
        )

    if user["role"] == "banned":

        return (
            None,
            jsonify({
                "success": False,
                "message": "Ваш аккаунт заблокирован"
            }),
            403
        )

    return user, None, None


def admin_required(func):

    @wraps(func)
    def decorated(*args, **kwargs):

        user, error, status = require_auth()

        if error:
            return error, status

        if user["role"] not in (
            "admin",
            "moderator"
        ):

            return jsonify({
                "success": False,
                "message": "Нет прав"
            }), 403

        return func(*args, **kwargs)

    return decorated


# =========================================================
# LOGIN PROTECTION
# =========================================================

def is_blocked(ip):

    data = login_attempts.get(ip)

    if not data:
        return False

    if (
        data["blocked_until"]
        and
        data["blocked_until"] > time.time()
    ):

        return True

    return False


def record_failed_attempt(ip):

    if ip not in login_attempts:

        login_attempts[ip] = {
            "attempts": 0,
            "blocked_until": None
        }

    login_attempts[ip]["attempts"] += 1

    if login_attempts[ip]["attempts"] >= 5:

        login_attempts[ip]["blocked_until"] = (
            time.time() + 300
        )


def reset_attempts(ip):

    login_attempts.pop(
        ip,
        None
    )


# =========================================================
# USER HELPERS
# =========================================================

def get_user_by_username(username):

    conn = get_db()

    user = conn.execute("""
        SELECT
            id,
            username,
            password_hash,
            display_name,
            email,
            role
        FROM users
        WHERE username = ?
    """, (
        username,
    )).fetchone()

    conn.close()

    return user


def get_user_by_email(email):

    conn = get_db()

    user = conn.execute("""
        SELECT
            id,
            username,
            password_hash,
            display_name,
            email,
            role
        FROM users
        WHERE email = ?
    """, (
        email,
    )).fetchone()

    conn.close()

    return user


def get_user_by_login(login):

    if "@" in login:

        return get_user_by_email(login)

    return get_user_by_username(login)


def user_public(user):

    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "email": user["email"]
    }


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/api/register",
    methods=["POST"]
)
def register():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get(
            "username",
            ""
        )
    ).strip().lower()

    password = str(
        data.get(
            "password",
            ""
        )
    )

    display_name = str(
        data.get(
            "display_name",
            username
        )
    ).strip()

    email = str(
        data.get(
            "email",
            ""
        )
    ).strip().lower()

    if not username or not password or not email:

        return jsonify({
            "success": False,
            "message": "Заполните все поля"
        }), 400

    if len(username) > 32:

        return jsonify({
            "success": False,
            "message": "Юзернейм слишком длинный"
        }), 400

    if len(password) < 8:

        return jsonify({
            "success": False,
            "message": "Пароль минимум 8 символов"
        }), 400

    if not re.search(
        r"[A-Z]",
        password
    ):

        return jsonify({
            "success": False,
            "message": "Пароль должен содержать заглавную букву"
        }), 400

    if not re.search(
        r"\d",
        password
    ):

        return jsonify({
            "success": False,
            "message": "Пароль должен содержать цифру"
        }), 400

    if not re.match(
        r"^[a-zA-Z0-9_]+$",
        username
    ):

        return jsonify({
            "success": False,
            "message": "Юзернейм: только латиница, цифры и _"
        }), 400

    if not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ):

        return jsonify({
            "success": False,
            "message": "Введите корректный email"
        }), 400

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )

    conn = get_db()

    try:

        conn.execute("""
            INSERT INTO users
            (
                username,
                password_hash,
                display_name,
                email,
                role
            )
            VALUES (?, ?, ?, ?, 'user')
        """, (
            username,
            password_hash,
            display_name,
            email
        ))

        conn.commit()

    except sqlite3.IntegrityError:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Пользователь или email уже существует"
        }), 409

    conn.close()

    return jsonify({
        "success": True,
        "message": "Регистрация успешна!"
    })


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/api/login",
    methods=["POST"]
)
def login():

    try:

        ip = request.remote_addr or "unknown"

        data = request.get_json(
            silent=True
        ) or {}

        # Поддерживаем оба варианта:
        # { login: "...", password: "..." }
        # и
        # { username: "...", password: "..." }

        login_value = str(
            data.get(
                "login",
                data.get(
                    "username",
                    ""
                )
            )
        ).strip().lower()

        password = str(
            data.get(
                "password",
                ""
            )
        )

        if not login_value or not password:

            return jsonify({
                "success": False,
                "message": "Заполните все поля"
            }), 400

        if is_blocked(ip):

            return jsonify({
                "success": False,
                "message": "Слишком много попыток. Подождите 5 минут."
            }), 429

        user = get_user_by_login(
            login_value
        )

        if not user:

            record_failed_attempt(ip)

            return jsonify({
                "success": False,
                "message": "Пользователь не найден"
            }), 401

        if user["role"] == "banned":

            return jsonify({
                "success": False,
                "message": "Ваш аккаунт заблокирован"
            }), 403

        try:

            password_hash = user["password_hash"]

            if isinstance(
                password_hash,
                memoryview
            ):

                password_hash = (
                    password_hash.tobytes()
                )

            elif isinstance(
                password_hash,
                str
            ):

                password_hash = (
                    password_hash.encode()
                )

            valid_password = bcrypt.checkpw(
                password.encode("utf-8"),
                password_hash
            )

        except Exception as e:

            print(
                "❌ BCRYPT ERROR:",
                repr(e)
            )

            valid_password = False

        if not valid_password:

            record_failed_attempt(ip)

            return jsonify({
                "success": False,
                "message": "Неверный пароль"
            }), 401

        reset_attempts(ip)

        token = jwt.encode(
            {
                "user_id": user["id"],
                "username": user["username"],
                "exp": (
                    datetime.datetime.now(
                        datetime.timezone.utc
                    )
                    +
                    datetime.timedelta(
                        days=TOKEN_DAYS
                    )
                )
            },
            SECRET_KEY,
            algorithm="HS256"
        )

        return jsonify({
            "success": True,
            "token": token,
            "user": user_public(user)
        })

    except Exception as e:

        print(
            "===================================="
        )

        print(
            "❌ LOGIN ERROR:"
        )

        print(
            repr(e)
        )

        print(
            "===================================="
        )

        return jsonify({
            "success": False,
            "message": "Внутренняя ошибка сервера"
        }), 500


# =========================================================
# ME
# =========================================================

@app.route(
    "/api/me",
    methods=["GET"]
)
def get_me():

    user, error, status = require_auth()

    if error:
        return error, status

    return jsonify(
        user_public(user)
    )


# =========================================================
# USERS
# =========================================================

@app.route(
    "/api/users",
    methods=["GET"]
)
def get_users():

    conn = get_db()

    users = conn.execute("""
        SELECT
            username,
            display_name,
            email
        FROM users
        WHERE role != 'banned'
        ORDER BY id
    """).fetchall()

    conn.close()

    return jsonify([
        {
            "username": u["username"],
            "display_name": u["display_name"],
            "email": u["email"]
        }
        for u in users
    ])


# =========================================================
# SEARCH
# =========================================================

@app.route(
    "/api/search",
    methods=["GET"]
)
def search_users():

    query = request.args.get(
        "q",
        ""
    ).strip().lower()

    if not query:
        return jsonify([])

    conn = get_db()

    users = conn.execute("""
        SELECT
            username,
            display_name,
            email
        FROM users
        WHERE role != 'banned'
        AND (
            LOWER(username) LIKE ?
            OR LOWER(display_name) LIKE ?
        )
        ORDER BY username
        LIMIT 20
    """, (
        f"%{query}%",
        f"%{query}%"
    )).fetchall()

    conn.close()

    return jsonify([
        {
            "username": u["username"],
            "display_name": u["display_name"],
            "email": u["email"]
        }
        for u in users
    ])


# =========================================================
# POSTS GET
# =========================================================

@app.route(
    "/api/posts",
    methods=["GET"]
)
def get_posts():

    conn = get_db()

    posts = conn.execute("""
        SELECT
            users.username,
            users.display_name,
            posts.text,
            posts.mood,
            posts.media,
            posts.time,
            posts.id,
            COUNT(likes.post_id) AS likes
        FROM posts

        JOIN users
        ON posts.user_id = users.id

        LEFT JOIN likes
        ON posts.id = likes.post_id

        GROUP BY posts.id

        ORDER BY posts.time DESC
    """).fetchall()

    conn.close()

    result = []

    for p in posts:

        try:

            media = (
                json.loads(p["media"])
                if p["media"]
                else []
            )

        except Exception:

            media = []

        result.append({
            "username": p["username"],
            "display_name": p["display_name"],
            "text": p["text"],
            "mood": p["mood"] or "·",
            "media": media,
            "time": p["time"],
            "id": p["id"],
            "likes": p["likes"] or 0
        })

    return jsonify(result)


# =========================================================
# CREATE POST
# =========================================================

@app.route(
    "/api/posts",
    methods=["POST"]
)
def create_post():

    user, error, status = require_auth()

    if error:
        return error, status

    data = request.get_json(
        silent=True
    ) or {}

    text = str(
        data.get(
            "text",
            ""
        )
    ).strip()

    mood = str(
        data.get(
            "mood",
            "·"
        )
    ).strip()

    if not text:

        return jsonify({
            "success": False,
            "message": "Напишите что-нибудь"
        }), 400

    if len(text) > 5000:

        return jsonify({
            "success": False,
            "message": "Пост слишком длинный"
        }), 400

    conn = get_db()

    cursor = conn.execute("""
        INSERT INTO posts
        (user_id, text, mood)
        VALUES (?, ?, ?)
    """, (
        user["id"],
        text,
        mood
    ))

    post_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Пост опубликован",
        "id": post_id
    })


# =========================================================
# DELETE POST
# =========================================================

@app.route(
    "/api/posts/<int:post_id>",
    methods=["DELETE"]
)
def delete_post(post_id):

    user, error, status = require_auth()

    if error:
        return error, status

    conn = get_db()

    post = conn.execute("""
        SELECT user_id
        FROM posts
        WHERE id = ?
    """, (
        post_id,
    )).fetchone()

    if not post:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Пост не найден"
        }), 404

    if post["user_id"] != user["id"]:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Нельзя удалить чужой пост"
        }), 403

    conn.execute(
        "DELETE FROM posts WHERE id = ?",
        (post_id,)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Пост удалён"
    })


# =========================================================
# LIKE POST
# =========================================================

@app.route(
    "/api/posts/<int:post_id>/like",
    methods=["POST"]
)
def like_post(post_id):

    user, error, status = require_auth()

    if error:
        return error, status

    conn = get_db()

    post = conn.execute(
        "SELECT id FROM posts WHERE id = ?",
        (post_id,)
    ).fetchone()

    if not post:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Пост не найден"
        }), 404

    existing = conn.execute("""
        SELECT 1
        FROM likes
        WHERE post_id = ?
        AND user_id = ?
    """, (
        post_id,
        user["id"]
    )).fetchone()

    if existing:

        conn.execute("""
            DELETE FROM likes
            WHERE post_id = ?
            AND user_id = ?
        """, (
            post_id,
            user["id"]
        ))

        liked = False

    else:

        conn.execute("""
            INSERT INTO likes
            (post_id, user_id)
            VALUES (?, ?)
        """, (
            post_id,
            user["id"]
        ))

        liked = True

    count = conn.execute("""
        SELECT COUNT(*)
        FROM likes
        WHERE post_id = ?
    """, (
        post_id,
    )).fetchone()[0]

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "liked": liked,
        "likes": count
    })


# =========================================================
# CHATS
# =========================================================

@app.route(
    "/api/chats",
    methods=["GET"]
)
def get_chats():

    user, error, status = require_auth()

    if error:
        return error, status

    username = user["username"]

    conn = get_db()

    partners = conn.execute("""
        SELECT DISTINCT

            CASE
                WHEN from_user = ?
                THEN to_user
                ELSE from_user
            END AS partner

        FROM messages

        WHERE from_user = ?
        OR to_user = ?
    """, (
        username,
        username,
        username
    )).fetchall()

    result = []

    for row in partners:

        partner = row["partner"]

        last = conn.execute("""
            SELECT
                text,
                time
            FROM messages

            WHERE
                (
                    from_user = ?
                    AND to_user = ?
                )

                OR

                (
                    from_user = ?
                    AND to_user = ?
                )

            ORDER BY id DESC
            LIMIT 1
        """, (
            username,
            partner,
            partner,
            username
        )).fetchone()

        unread = conn.execute("""
            SELECT COUNT(*) AS count
            FROM messages

            WHERE from_user = ?
            AND to_user = ?
            AND read = 0
        """, (
            partner,
            username
        )).fetchone()["count"]

        result.append({
            "username": partner,
            "last_message": (
                last["text"]
                if last
                else ""
            ),
            "last_time": (
                last["time"]
                if last
                else None
            ),
            "unread": unread
        })

    conn.close()

    result.sort(
        key=lambda x: x["last_time"] or "",
        reverse=True
    )

    return jsonify(result)


# =========================================================
# SEND MESSAGE
# =========================================================

@app.route(
    "/api/messages",
    methods=["POST"]
)
def send_message():

    user, error, status = require_auth()

    if error:
        return error, status

    data = request.get_json(
        silent=True
    ) or {}

    to_user = str(
        data.get(
            "to_user",
            ""
        )
    ).strip().lower()

    text = str(
        data.get(
            "text",
            ""
        )
    ).strip()

    if not to_user or not text:

        return jsonify({
            "success": False,
            "message": "Заполните все поля"
        }), 400

    if to_user == user["username"]:

        return jsonify({
            "success": False,
            "message": "Нельзя написать самому себе"
        }), 400

    if len(text) > 5000:

        return jsonify({
            "success": False,
            "message": "Сообщение слишком длинное"
        }), 400

    recipient = get_user_by_username(
        to_user
    )

    if not recipient:

        return jsonify({
            "success": False,
            "message": "Пользователь не найден"
        }), 404

    if recipient["role"] == "banned":

        return jsonify({
            "success": False,
            "message": "Пользователь заблокирован"
        }), 403

    conn = get_db()

    cursor = conn.execute("""
        INSERT INTO messages
        (
            from_user,
            to_user,
            text,
            read
        )
        VALUES (?, ?, ?, 0)
    """, (
        user["username"],
        to_user,
        text
    ))

    message_id = cursor.lastrowid

    row = conn.execute("""
        SELECT
            id,
            from_user,
            to_user,
            text,
            time,
            read
        FROM messages
        WHERE id = ?
    """, (
        message_id,
    )).fetchone()

    conn.commit()
    conn.close()

    message = {
        "id": row["id"],
        "from": row["from_user"],
        "to": row["to_user"],
        "text": row["text"],
        "time": row["time"],
        "read": bool(row["read"])
    }

    socketio.emit(
        "new_message",
        message,
        room=f"user:{to_user}"
    )

    socketio.emit(
        "message_sent",
        message,
        room=f"user:{user['username']}"
    )

    return jsonify({
        "success": True,
        "message": "Сообщение отправлено",
        "data": message
    })


# =========================================================
# MESSAGE HISTORY
# =========================================================

@app.route(
    "/api/messages/<username>",
    methods=["GET"]
)
def get_messages(username):

    user, error, status = require_auth()

    if error:
        return error, status

    username = username.strip().lower()

    partner = get_user_by_username(
        username
    )

    if not partner:

        return jsonify({
            "success": False,
            "message": "Пользователь не найден"
        }), 404

    conn = get_db()

    messages = conn.execute("""
        SELECT
            id,
            from_user,
            to_user,
            text,
            time,
            read
        FROM messages

        WHERE
            (
                from_user = ?
                AND to_user = ?
            )

            OR

            (
                from_user = ?
                AND to_user = ?
            )

        ORDER BY id ASC
    """, (
        user["username"],
        username,
        username,
        user["username"]
    )).fetchall()

    conn.execute("""
        UPDATE messages
        SET read = 1

        WHERE from_user = ?
        AND to_user = ?
        AND read = 0
    """, (
        username,
        user["username"]
    ))

    conn.commit()
    conn.close()

    return jsonify([
        {
            "id": m["id"],
            "from": m["from_user"],
            "to": m["to_user"],
            "text": m["text"],
            "time": m["time"],
            "read": bool(m["read"])
        }
        for m in messages
    ])


# =========================================================
# MOOD
# =========================================================

@app.route(
    "/api/mood",
    methods=["POST"]
)
def save_mood():

    user, error, status = require_auth()

    if error:
        return error, status

    data = request.get_json(
        silent=True
    ) or {}

    mood = str(
        data.get(
            "mood",
            ""
        )
    ).strip()

    if not mood:

        return jsonify({
            "success": False,
            "message": "Укажите состояние"
        }), 400

    conn = get_db()

    conn.execute("""
        DELETE FROM moods

        WHERE username = ?
        AND date = DATE('now')
    """, (
        user["username"],
    ))

    conn.execute("""
        INSERT INTO moods
        (
            username,
            mood,
            date
        )
        VALUES (?, ?, DATE('now'))
    """, (
        user["username"],
        mood
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Состояние сохранено"
    })


@app.route(
    "/api/mood/<username>",
    methods=["GET"]
)
def get_mood(username):

    user, error, status = require_auth()

    if error:
        return error, status

    if username.lower() != user["username"].lower():

        return jsonify({
            "success": False,
            "message": "Нет доступа"
        }), 403

    conn = get_db()

    mood = conn.execute("""
        SELECT mood
        FROM moods

        WHERE username = ?
        AND date = DATE('now')

        ORDER BY id DESC

        LIMIT 1
    """, (
        user["username"],
    )).fetchone()

    conn.close()

    return jsonify({
        "mood": mood["mood"]
        if mood
        else None
    })


# =========================================================
# GRATITUDE
# =========================================================

@app.route(
    "/api/gratitude",
    methods=["POST"]
)
def save_gratitude():

    user, error, status = require_auth()

    if error:
        return error, status

    data = request.get_json(
        silent=True
    ) or {}

    text = str(
        data.get(
            "text",
            ""
        )
    ).strip()

    if not text:

        return jsonify({
            "success": False,
            "message": "Введите текст"
        }), 400

    if len(text) > 2000:

        return jsonify({
            "success": False,
            "message": "Запись слишком длинная"
        }), 400

    conn = get_db()

    conn.execute("""
        INSERT INTO gratitude
        (
            username,
            text
        )
        VALUES (?, ?)
    """, (
        user["username"],
        text
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Благодарность сохранена"
    })


@app.route(
    "/api/gratitude/<username>",
    methods=["GET"]
)
def get_gratitude(username):

    user, error, status = require_auth()

    if error:
        return error, status

    if username.lower() != user["username"].lower():

        return jsonify({
            "success": False,
            "message": "Нет доступа"
        }), 403

    conn = get_db()

    entries = conn.execute("""
        SELECT
            text,
            date
        FROM gratitude

        WHERE username = ?

        ORDER BY date DESC

        LIMIT 10
    """, (
        user["username"],
    )).fetchall()

    conn.close()

    return jsonify([
        {
            "text": e["text"],
            "date": e["date"]
        }
        for e in entries
    ])


# =========================================================
# PASSWORD RECOVERY
# =========================================================

@app.route(
    "/api/recover",
    methods=["POST"]
)
def recover_password():

    data = request.get_json(
        silent=True
    ) or {}

    email = str(
        data.get(
            "email",
            ""
        )
    ).strip().lower()

    if not email:

        return jsonify({
            "success": False,
            "message": "Введите email"
        }), 400

    user = get_user_by_email(
        email
    )

    if not user:

        return jsonify({
            "success": False,
            "message": "Пользователь с таким email не найден"
        }), 404

    return jsonify({
        "success": True,
        "message": "Восстановление пока работает в демо-режиме"
    })


# =========================================================
# ADMIN - MAKE MODERATOR
# =========================================================

@app.route(
    "/api/admin/make_moderator",
    methods=["POST"]
)
@admin_required
def make_moderator():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get(
            "username",
            ""
        )
    ).strip().lower()

    if not username:

        return jsonify({
            "success": False,
            "message": "Укажите пользователя"
        }), 400

    conn = get_db()

    user = conn.execute("""
        SELECT id
        FROM users
        WHERE username = ?
    """, (
        username,
    )).fetchone()

    if not user:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Пользователь не найден"
        }), 404

    conn.execute("""
        UPDATE users

        SET role = 'moderator'

        WHERE username = ?
    """, (
        username,
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"{username} теперь модератор"
    })


# =========================================================
# ADMIN - BAN
# =========================================================

@app.route(
    "/api/admin/ban",
    methods=["POST"]
)
@admin_required
def ban_user():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get(
            "username",
            ""
        )
    ).strip().lower()

    if not username:

        return jsonify({
            "success": False,
            "message": "Укажите пользователя"
        }), 400

    conn = get_db()

    user = conn.execute("""
        SELECT id
        FROM users
        WHERE username = ?
    """, (
        username,
    )).fetchone()

    if not user:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Пользователь не найден"
        }), 404

    conn.execute("""
        UPDATE users

        SET role = 'banned'

        WHERE username = ?
    """, (
        username,
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": f"{username} заблокирован"
    })


# =========================================================
# SOCKET.IO
# =========================================================

connected_users = {}


@socketio.on("connect")
def socket_connect(auth):

    if not auth:
        return False

    token = auth.get(
        "token"
    )

    user = get_user_by_token(
        token
    )

    if not user:
        return False

    username = user["username"]

    join_room(
        f"user:{username}"
    )

    connected_users[
        request.sid
    ] = username

    print(
        f"🟢 WebSocket: {username} подключился"
    )

    emit(
        "connected",
        {
            "success": True,
            "username": username
        }
    )


@socketio.on("disconnect")
def socket_disconnect():

    username = connected_users.pop(
        request.sid,
        None
    )

    if username:

        leave_room(
            f"user:{username}"
        )

        print(
            f"🔴 WebSocket: {username} отключился"
        )


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    return jsonify({
        "success": True,
        "server": "online",
        "websocket": True,
        "time": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()
    })


# =========================================================
# ROOT
# =========================================================

@app.route("/")
def root():

    return jsonify({
        "success": True,
        "message": "Спокойный ум API работает"
    })


# =========================================================
# ERROR HANDLER
# =========================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "success": False,
        "message": "Маршрут не найден"
    }), 404


@app.errorhandler(500)
def internal_error(error):

    print(
        "❌ GLOBAL 500:",
        repr(error)
    )

    return jsonify({
        "success": False,
        "message": "Внутренняя ошибка сервера"
    }), 500


# =========================================================
# LOCAL START
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    print("")
    print("====================================")
    print("🌿 СПОКОЙНЫЙ УМ")
    print("====================================")
    print("🚀 PORT:", port)
    print("📡 API: /api/")
    print("💬 WebSocket: ENABLED")
    print("🗄️ SQLite:", DB_PATH)
    print("====================================")
    print("")

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=False,
        allow_unsafe_werkzeug=True
    )

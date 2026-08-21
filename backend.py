import os
import datetime
import bcrypt
import jwt
import psycopg2
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room


# =========================================================
# APP
# =========================================================

app = Flask(__name__)

SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key"
)

DATABASE_URL = os.environ.get("DATABASE_URL")

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
# DATABASE
# =========================================================

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL не задан")

    return psycopg2.connect(DATABASE_URL)


def table_columns(cur, table_name):
    """Возвращает набор колонок таблицы PostgreSQL."""
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = %s
    """, (table_name,))
    return {row[0] for row in cur.fetchall()}


def init_db():
    conn = get_db()
    cur = conn.cursor()

    try:
        # USERS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash BYTEA NOT NULL,
                display_name VARCHAR(150),
                email VARCHAR(255),
                role VARCHAR(50) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # POSTS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                content TEXT,
                mood TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # LIKES
        cur.execute("""
            CREATE TABLE IF NOT EXISTS likes (
                post_id INTEGER,
                user_id INTEGER
            )
        """)

        # CHATS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                id SERIAL PRIMARY KEY,
                user1_id INTEGER,
                user2_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # MESSAGES
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER,
                receiver_id INTEGER,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # MOODS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS moods (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                mood TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # GRATITUDE
        cur.execute("""
            CREATE TABLE IF NOT EXISTS gratitude (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # -----------------------------------------------------
        # БЕЗОПАСНАЯ МИГРАЦИЯ СУЩЕСТВУЮЩЕЙ БАЗЫ
        # CREATE TABLE IF NOT EXISTS НЕ МЕНЯЕТ СТАРУЮ ТАБЛИЦУ.
        # Поэтому добавляем недостающие поля, если они отсутствуют.
        # Ничего не удаляем и данные пользователей не трогаем.
        # -----------------------------------------------------

        cur.execute("""
            ALTER TABLE users
                ADD COLUMN IF NOT EXISTS display_name VARCHAR(150),
                ADD COLUMN IF NOT EXISTS email VARCHAR(255),
                ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user',
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        cur.execute("""
            ALTER TABLE posts
                ADD COLUMN IF NOT EXISTS user_id INTEGER,
                ADD COLUMN IF NOT EXISTS content TEXT,
                ADD COLUMN IF NOT EXISTS mood TEXT,
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        cur.execute("""
            ALTER TABLE chats
                ADD COLUMN IF NOT EXISTS user1_id INTEGER,
                ADD COLUMN IF NOT EXISTS user2_id INTEGER,
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        cur.execute("""
            ALTER TABLE messages
                ADD COLUMN IF NOT EXISTS sender_id INTEGER,
                ADD COLUMN IF NOT EXISTS receiver_id INTEGER,
                ADD COLUMN IF NOT EXISTS content TEXT,
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        cur.execute("""
            ALTER TABLE moods
                ADD COLUMN IF NOT EXISTS user_id INTEGER,
                ADD COLUMN IF NOT EXISTS mood TEXT,
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        cur.execute("""
            ALTER TABLE gratitude
                ADD COLUMN IF NOT EXISTS user_id INTEGER,
                ADD COLUMN IF NOT EXISTS content TEXT,
                ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        conn.commit()

        print("DATABASE INITIALIZED SUCCESSFULLY")

    except Exception as e:
        conn.rollback()
        print("DATABASE INIT ERROR:", repr(e))
        raise

    finally:
        cur.close()
        conn.close()


# =========================================================
# HELPERS
# =========================================================

def make_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=30)
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm="HS256"
    )


def get_token_from_request():
    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Bearer "):
        return None

    return auth.replace("Bearer ", "", 1).strip()


def get_user_by_id(user_id):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                username,
                display_name,
                email,
                role
            FROM users
            WHERE id = %s
        """, (user_id,))

        return cur.fetchone()

    finally:
        cur.close()
        conn.close()


def get_user_by_username(username):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                username,
                password_hash,
                display_name,
                email,
                role
            FROM users
            WHERE LOWER(username) = LOWER(%s)
        """, (username,))

        return cur.fetchone()

    finally:
        cur.close()
        conn.close()


def get_user_by_email(email):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                username,
                password_hash,
                display_name,
                email,
                role
            FROM users
            WHERE LOWER(email) = LOWER(%s)
        """, (email,))

        return cur.fetchone()

    finally:
        cur.close()
        conn.close()


def get_user_by_token():
    token = get_token_from_request()

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

        return get_user_by_id(user_id)

    except Exception as e:
        print("TOKEN ERROR:", repr(e))
        return None


def check_password(password, hashed_password):
    try:
        if isinstance(hashed_password, memoryview):
            hashed_password = hashed_password.tobytes()

        elif isinstance(hashed_password, bytearray):
            hashed_password = bytes(hashed_password)

        elif isinstance(hashed_password, str):
            hashed_password = hashed_password.encode("utf-8")

        return bcrypt.checkpw(
            password.encode("utf-8"),
            hashed_password
        )

    except Exception as e:
        print("PASSWORD CHECK ERROR:", repr(e))
        return False


def user_json(user):
    if not user:
        return None

    return {
        "id": user[0],
        "username": user[1],
        "display_name": user[2] or user[1],
        "email": user[3] or "",
        "role": user[4] or "user"
    }


def unauthorized():
    return jsonify({
        "success": False,
        "message": "Не авторизован"
    }), 401


# =========================================================
# REGISTER
# =========================================================

@app.route("/api/register", methods=["POST"])
def register():

    try:
        data = request.get_json(silent=True) or {}

        username = str(
            data.get("username")
            or data.get("login")
            or ""
        ).strip()

        password = str(
            data.get("password")
            or ""
        )

        email = str(
            data.get("email")
            or ""
        ).strip()

        display_name = str(
            data.get("display_name")
            or data.get("displayName")
            or username
        ).strip()

        if not username or not password:
            return jsonify({
                "success": False,
                "message": "Введите логин и пароль"
            }), 400

        if len(username) < 3:
            return jsonify({
                "success": False,
                "message": "Логин должен содержать минимум 3 символа"
            }), 400

        if len(password) < 6:
            return jsonify({
                "success": False,
                "message": "Пароль минимум 6 символов"
            }), 400

        conn = get_db()
        cur = conn.cursor()

        try:
            # Проверяем логин
            cur.execute("""
                SELECT id
                FROM users
                WHERE LOWER(username) = LOWER(%s)
            """, (username,))

            if cur.fetchone():
                return jsonify({
                    "success": False,
                    "message": "Такой пользователь уже существует"
                }), 409

            # Проверяем email
            if email:
                cur.execute("""
                    SELECT id
                    FROM users
                    WHERE LOWER(email) = LOWER(%s)
                """, (email,))

                if cur.fetchone():
                    return jsonify({
                        "success": False,
                        "message": "Эта почта уже используется"
                    }), 409

            password_hash = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt()
            )

            cur.execute("""
                INSERT INTO users (
                    username,
                    password_hash,
                    display_name,
                    email,
                    role
                )
                VALUES (%s, %s, %s, %s, 'user')
                RETURNING id
            """, (
                username,
                password_hash,
                display_name,
                email
            ))

            user_id = cur.fetchone()[0]

            conn.commit()

        except Exception:
            conn.rollback()
            raise

        finally:
            cur.close()
            conn.close()

        user = get_user_by_id(user_id)
        token = make_token(user_id)

        return jsonify({
            "success": True,
            "token": token,
            "user": user_json(user)
        })

    except Exception as e:
        print("REGISTER ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка регистрации"
        }), 500


# =========================================================
# LOGIN
# =========================================================

@app.route("/api/login", methods=["POST"])
def login():

    try:
        data = request.get_json(silent=True) or {}

        # Поддерживаем username/login/email
        login_value = str(
            data.get("username")
            or data.get("login")
            or data.get("email")
            or ""
        ).strip()

        password = str(
            data.get("password")
            or ""
        )

        if not login_value or not password:
            return jsonify({
                "success": False,
                "message": "Введите логин и пароль"
            }), 400

        user = get_user_by_username(login_value)

        if not user and "@" in login_value:
            user = get_user_by_email(login_value)

        if not user:
            return jsonify({
                "success": False,
                "message": "Неверный логин или пароль"
            }), 401

        if not check_password(
            password,
            user[2]
        ):
            return jsonify({
                "success": False,
                "message": "Неверный логин или пароль"
            }), 401

        token = make_token(user[0])
        full_user = get_user_by_id(user[0])

        return jsonify({
            "success": True,
            "token": token,
            "user": user_json(full_user)
        })

    except Exception as e:
        print("LOGIN ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка входа"
        }), 500


# =========================================================
# ME
# =========================================================

@app.route("/api/me", methods=["GET"])
def me():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    return jsonify({
        "success": True,
        "user": user_json(user)
    })


# =========================================================
# USERS
# =========================================================

@app.route("/api/users", methods=["GET"])
def users():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                username,
                display_name,
                email,
                role
            FROM users
            ORDER BY username
        """)

        rows = cur.fetchall()

        result = []

        for r in rows:
            result.append({
                "id": r[0],
                "username": r[1],
                "display_name": r[2] or r[1],
                "email": r[3] or "",
                "role": r[4] or "user"
            })

        return jsonify({
            "success": True,
            "users": result
        })

    except Exception as e:
        print("USERS ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка загрузки пользователей"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# SEARCH
# =========================================================

@app.route("/api/users/search", methods=["GET"])
@app.route("/api/search", methods=["GET"])
def search():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    q = request.args.get(
        "q",
        ""
    ).strip()

    if not q:
        return jsonify({
            "success": True,
            "users": []
        })

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT
                id,
                username,
                display_name,
                email,
                role
            FROM users
            WHERE
                username ILIKE %s
                OR display_name ILIKE %s
            ORDER BY username
            LIMIT 50
        """, (
            f"%{q}%",
            f"%{q}%"
        ))

        rows = cur.fetchall()

        result = []

        for r in rows:
            result.append({
                "id": r[0],
                "username": r[1],
                "display_name": r[2] or r[1],
                "email": r[3] or "",
                "role": r[4] or "user"
            })

        return jsonify({
            "success": True,
            "users": result
        })

    except Exception as e:
        print("SEARCH ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка поиска"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# POSTS GET
# =========================================================

@app.route("/api/posts", methods=["GET"])
def get_posts():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT
                p.id,
                p.user_id,
                u.username,
                u.display_name,
                p.content,
                p.mood,
                p.created_at,
                COUNT(l.post_id) AS likes
            FROM posts p
            LEFT JOIN users u
                ON u.id = p.user_id
            LEFT JOIN likes l
                ON l.post_id = p.id
            GROUP BY
                p.id,
                p.user_id,
                u.username,
                u.display_name,
                p.content,
                p.mood,
                p.created_at
            ORDER BY p.created_at DESC
            LIMIT 100
        """)

        rows = cur.fetchall()

        posts = []

        for r in rows:
            posts.append({
                "id": r[0],
                "user_id": r[1],
                "username": r[2] or "Пользователь",
                "display_name": r[3] or r[2] or "Пользователь",
                "content": r[4] or "",
                "mood": r[5] or "·",
                "created_at": (
                    r[6].isoformat()
                    if r[6]
                    else None
                ),
                "likes": int(r[7] or 0)
            })

        return jsonify({
            "success": True,
            "posts": posts
        })

    except Exception as e:
        print("GET POSTS ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка загрузки постов"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# CREATE POST
# =========================================================

@app.route("/api/posts", methods=["POST"])
def create_post():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    data = request.get_json(silent=True) or {}

    content = str(
        data.get("content")
        or data.get("text")
        or ""
    ).strip()

    mood = str(
        data.get("mood")
        or "·"
    ).strip()

    if not content:
        return jsonify({
            "success": False,
            "message": "Введите текст"
        }), 400

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO posts (
                user_id,
                content,
                mood
            )
            VALUES (%s, %s, %s)
            RETURNING
                id,
                user_id,
                content,
                mood,
                created_at
        """, (
            user[0],
            content,
            mood
        ))

        row = cur.fetchone()

        conn.commit()

        return jsonify({
            "success": True,
            "post": {
                "id": row[0],
                "user_id": row[1],
                "username": user[1],
                "display_name": user[2] or user[1],
                "content": row[2],
                "mood": row[3],
                "created_at": (
                    row[4].isoformat()
                    if row[4]
                    else None
                ),
                "likes": 0
            }
        })

    except Exception as e:
        conn.rollback()

        print("CREATE POST ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка создания поста"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# DELETE POST
# =========================================================

@app.route("/api/posts/<int:post_id>", methods=["DELETE"])
def delete_post(post_id):

    user = get_user_by_token()

    if not user:
        return unauthorized()

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT user_id
            FROM posts
            WHERE id = %s
        """, (post_id,))

        post = cur.fetchone()

        if not post:
            return jsonify({
                "success": False,
                "message": "Пост не найден"
            }), 404

        if post[0] != user[0] and user[4] != "admin":
            return jsonify({
                "success": False,
                "message": "Нет прав"
            }), 403

        cur.execute("""
            DELETE FROM likes
            WHERE post_id = %s
        """, (post_id,))

        cur.execute("""
            DELETE FROM posts
            WHERE id = %s
        """, (post_id,))

        conn.commit()

        return jsonify({
            "success": True
        })

    except Exception as e:
        conn.rollback()

        print("DELETE POST ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка удаления"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# LIKE
# =========================================================

@app.route("/api/posts/<int:post_id>/like", methods=["POST"])
def like_post(post_id):

    user = get_user_by_token()

    if not user:
        return unauthorized()

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT 1
            FROM posts
            WHERE id = %s
        """, (post_id,))

        if not cur.fetchone():
            return jsonify({
                "success": False,
                "message": "Пост не найден"
            }), 404

        cur.execute("""
            SELECT 1
            FROM likes
            WHERE
                post_id = %s
                AND user_id = %s
            LIMIT 1
        """, (
            post_id,
            user[0]
        ))

        existing = cur.fetchone()

        if existing:
            cur.execute("""
                DELETE FROM likes
                WHERE
                    post_id = %s
                    AND user_id = %s
            """, (
                post_id,
                user[0]
            ))

            liked = False

        else:
            cur.execute("""
                INSERT INTO likes (
                    post_id,
                    user_id
                )
                VALUES (%s, %s)
            """, (
                post_id,
                user[0]
            ))

            liked = True

        cur.execute("""
            SELECT COUNT(*)
            FROM likes
            WHERE post_id = %s
        """, (post_id,))

        count = cur.fetchone()[0]

        conn.commit()

        return jsonify({
            "success": True,
            "liked": liked,
            "likes": int(count)
        })

    except Exception as e:
        conn.rollback()

        print("LIKE ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка лайка"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# CHATS GET
# =========================================================

@app.route("/api/chats", methods=["GET"])
def get_chats():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    conn = get_db()
    cur = conn.cursor()

    try:
        # Берём собеседников непосредственно из messages.
        # Это надёжнее старой таблицы chats и автоматически
        # показывает новый диалог после первой отправки.

        cur.execute("""
            SELECT
                other_id,
                MAX(created_at) AS last_time
            FROM (
                SELECT
                    receiver_id AS other_id,
                    created_at
                FROM messages
                WHERE sender_id = %s

                UNION ALL

                SELECT
                    sender_id AS other_id,
                    created_at
                FROM messages
                WHERE receiver_id = %s
            ) q
            GROUP BY other_id
            ORDER BY MAX(created_at) DESC
        """, (
            user[0],
            user[0]
        ))

        rows = cur.fetchall()

        chats = []

        for row in rows:
            other_id = row[0]

            cur.execute("""
                SELECT
                    id,
                    username,
                    display_name
                FROM users
                WHERE id = %s
            """, (other_id,))

            other = cur.fetchone()

            if not other:
                continue

            cur.execute("""
                SELECT
                    content,
                    created_at
                FROM messages
                WHERE
                    (
                        sender_id = %s
                        AND receiver_id = %s
                    )
                    OR
                    (
                        sender_id = %s
                        AND receiver_id = %s
                    )
                ORDER BY created_at DESC
                LIMIT 1
            """, (
                user[0],
                other_id,
                other_id,
                user[0]
            ))

            last = cur.fetchone()

            chats.append({
                "id": other_id,
                "user_id": other_id,
                "username": other[1],
                "display_name": other[2] or other[1],
                "unread": 0,
                "last_message": (
                    last[0]
                    if last
                    else ""
                ),
                "last_time": (
                    last[1].isoformat()
                    if last and last[1]
                    else None
                )
            })

        return jsonify({
            "success": True,
            "chats": chats
        })

    except Exception as e:
        print("GET CHATS ERROR:", repr(e))
        traceback.print_exc()

        return jsonify({
            "success": False,
            "message": "Ошибка загрузки чатов"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# CREATE CHAT
# =========================================================

@app.route("/api/chats", methods=["POST"])
def create_chat():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    data = request.get_json(silent=True) or {}

    other_id = (
        data.get("user_id")
        or data.get("userId")
        or data.get("receiver_id")
        or data.get("receiverId")
    )

    try:
        other_id = int(other_id)
    except (ValueError, TypeError):
        return jsonify({
            "success": False,
            "message": "Неверный user_id"
        }), 400

    if other_id == user[0]:
        return jsonify({
            "success": False,
            "message": "Нельзя создать чат с собой"
        }), 400

    other = get_user_by_id(other_id)

    if not other:
        return jsonify({
            "success": False,
            "message": "Пользователь не найден"
        }), 404

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT id
            FROM chats
            WHERE
                (
                    user1_id = %s
                    AND user2_id = %s
                )
                OR
                (
                    user1_id = %s
                    AND user2_id = %s
                )
            LIMIT 1
        """, (
            user[0],
            other_id,
            other_id,
            user[0]
        ))

        existing = cur.fetchone()

        if existing:
            chat_id = existing[0]

        else:
            cur.execute("""
                INSERT INTO chats (
                    user1_id,
                    user2_id
                )
                VALUES (%s, %s)
                RETURNING id
            """, (
                user[0],
                other_id
            ))

            chat_id = cur.fetchone()[0]

        conn.commit()

        return jsonify({
            "success": True,
            "chat": {
                "id": chat_id,
                "user_id": other[0],
                "username": other[1],
                "display_name": other[2] or other[1]
            }
        })

    except Exception as e:
        conn.rollback()

        print("CREATE CHAT ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка создания чата"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# GET MESSAGES
# =========================================================

@app.route("/api/messages", methods=["GET"])
def get_messages():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    other_id = (
        request.args.get("user_id")
        or request.args.get("userId")
        or request.args.get("receiver_id")
        or request.args.get("receiverId")
    )

    try:
        other_id = int(other_id)
    except (ValueError, TypeError):
        return jsonify({
            "success": False,
            "message": "Не указан user_id"
        }), 400

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT
                m.id,
                m.sender_id,
                sender.username,
                sender.display_name,

                m.receiver_id,
                receiver.username,
                receiver.display_name,

                m.content,
                m.created_at

            FROM messages m

            JOIN users sender
                ON sender.id = m.sender_id

            JOIN users receiver
                ON receiver.id = m.receiver_id

            WHERE
                (
                    m.sender_id = %s
                    AND m.receiver_id = %s
                )
                OR
                (
                    m.sender_id = %s
                    AND m.receiver_id = %s
                )

            ORDER BY m.created_at ASC
        """, (
            user[0],
            other_id,
            other_id,
            user[0]
        ))

        rows = cur.fetchall()

        messages = []

        for r in rows:
            messages.append({
                "id": r[0],

                "sender_id": r[1],
                "sender_username": r[2],
                "sender_display_name": r[3] or r[2],

                "receiver_id": r[4],
                "receiver_username": r[5],
                "receiver_display_name": r[6] or r[5],

                "content": r[7],

                "created_at": (
                    r[8].isoformat()
                    if r[8]
                    else None
                )
            })

        return jsonify({
            "success": True,
            "messages": messages
        })

    except Exception as e:
        print("GET MESSAGES ERROR:", repr(e))

        return jsonify({
            "success": False,
            "message": "Ошибка загрузки сообщений"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# SEND MESSAGE
# =========================================================

@app.route("/api/messages", methods=["POST"])
def send_message():
    """Надёжная отправка сообщения для старой и новой схемы PostgreSQL."""
    user = get_user_by_token()
    if not user:
        return unauthorized()

    data = request.get_json(silent=True) or {}

    try:
        # Получатель
        receiver_id = (
            data.get("receiver_id") or data.get("receiverId") or
            data.get("recipient_id") or data.get("recipientId") or
            data.get("user_id") or data.get("userId")
        )

        username_target = (
            data.get("to_user") or data.get("toUser") or
            data.get("username")
        )

        if not receiver_id and username_target:
            target = get_user_by_username(str(username_target).strip())
            if not target:
                return jsonify({"success": False, "message": "Получатель не найден"}), 404
            receiver_id = target[0]

        if receiver_id is None or str(receiver_id).strip() == "":
            return jsonify({"success": False, "message": "Не указан получатель"}), 400

        try:
            receiver_id = int(receiver_id)
        except (ValueError, TypeError):
            return jsonify({"success": False, "message": "Неверный ID получателя"}), 400

        content = data.get("content")
        if content is None:
            content = data.get("text")
        if content is None:
            content = data.get("message")
        content = str(content or "").strip()

        if not content:
            return jsonify({"success": False, "message": "Введите сообщение"}), 400
        if len(content) > 5000:
            return jsonify({"success": False, "message": "Сообщение слишком длинное"}), 400
        if receiver_id == user[0]:
            return jsonify({"success": False, "message": "Нельзя отправить сообщение самому себе"}), 400

        receiver = get_user_by_id(receiver_id)
        if not receiver:
            return jsonify({"success": False, "message": "Получатель не найден"}), 404

        conn = get_db()
        cur = conn.cursor()

        try:
            # Находим/создаём чат. Если старая таблица chats несовместима,
            # сообщение всё равно пытаемся сохранить без chat_id.
            chat_id = None
            try:
                cur.execute("""
                    SELECT id FROM chats
                    WHERE (user1_id = %s AND user2_id = %s)
                       OR (user1_id = %s AND user2_id = %s)
                    LIMIT 1
                """, (user[0], receiver_id, receiver_id, user[0]))
                row = cur.fetchone()

                if row:
                    chat_id = row[0]
                else:
                    cur.execute("""
                        INSERT INTO chats (user1_id, user2_id)
                        VALUES (%s, %s)
                        RETURNING id
                    """, (user[0], receiver_id))
                    row = cur.fetchone()
                    chat_id = row[0] if row else None
            except Exception as chat_error:
                print("CHAT CREATE ERROR:", repr(chat_error))
                traceback.print_exc()
                conn.rollback()

            # Получаем РЕАЛЬНУЮ структуру messages.
            cur.execute("""
                SELECT
                    column_name,
                    is_nullable,
                    column_default,
                    data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'messages'
                ORDER BY ordinal_position
            """)
            schema_rows = cur.fetchall()

            if not schema_rows:
                raise RuntimeError("Таблица messages не найдена")

            schema = {
                row[0]: {
                    "nullable": row[1] == "YES",
                    "default": row[2],
                    "type": row[3]
                }
                for row in schema_rows
            }

            # Значения для всех распространённых вариантов старой/новой схемы.
            values_by_name = {
                "sender_id": user[0],
                "receiver_id": receiver_id,
                "from_user": user[0],
                "to_user": receiver_id,
                "content": content,
                "text": content,
                "message": content,
                "chat_id": chat_id,
                "sender": user[0],
                "receiver": receiver_id,
                "user_id": user[0],
                "created_at": None,
                "timestamp": None
            }

            insert_columns = []
            insert_values = []

            # Заполняем только реально существующие колонки.
            # Колонки с DEFAULT можно не передавать.
            for column_name, meta in schema.items():
                if column_name == "id":
                    continue

                if column_name in values_by_name:
                    value = values_by_name[column_name]

                    # created_at/timestamp с DEFAULT оставляем БД.
                    if value is None and meta["default"] is not None:
                        continue

                    # chat_id не вставляем, если чата нет.
                    if column_name == "chat_id" and value is None:
                        if not meta["nullable"] and meta["default"] is None:
                            raise RuntimeError("В messages обязательный chat_id, но чат создать не удалось")
                        continue

                    # created_at/timestamp без DEFAULT лучше не трогать:
                    # PostgreSQL сам сообщит, если такая схема несовместима.
                    if column_name in ("created_at", "timestamp") and value is None:
                        if meta["nullable"] or meta["default"] is not None:
                            continue

                    insert_columns.append(column_name)
                    insert_values.append(value)

            # Проверяем обязательные поля старой таблицы.
            missing_required = []
            for column_name, meta in schema.items():
                if column_name == "id":
                    continue
                if not meta["nullable"] and meta["default"] is None:
                    if column_name not in insert_columns:
                        missing_required.append(column_name)

            if missing_required:
                raise RuntimeError(
                    "В messages есть обязательные поля без значения: " +
                    ", ".join(missing_required)
                )

            if not insert_columns:
                raise RuntimeError("Не найдено ни одного поля для INSERT в messages")

            placeholders = ", ".join(["%s"] * len(insert_values))
            columns_sql = ", ".join(f'"{c}"' for c in insert_columns)

            # id гарантированно есть в нормальной таблице messages.
            cur.execute(
                f'INSERT INTO messages ({columns_sql}) VALUES ({placeholders}) RETURNING id',
                tuple(insert_values)
            )
            row = cur.fetchone()
            if not row:
                raise RuntimeError("PostgreSQL не вернул ID сообщения")

            message_id = row[0]

            # Получаем дату уже созданной записи, если поле есть.
            created_at = None
            if "created_at" in schema:
                cur.execute('SELECT "created_at" FROM messages WHERE id = %s', (message_id,))
                created_row = cur.fetchone()
                if created_row:
                    created_at = created_row[0]

            conn.commit()

        except Exception as e:
            conn.rollback()
            print("\n===================================")
            print("SEND MESSAGE DATABASE ERROR")
            print("TYPE:", type(e).__name__)
            print("ERROR:", str(e))
            print("REPR:", repr(e))
            print("===================================")
            traceback.print_exc()
            raise
        finally:
            cur.close()
            conn.close()

        message = {
            "id": message_id,
            "chat_id": chat_id,
            "sender_id": user[0],
            "sender_username": user[1],
            "sender_display_name": user[2] or user[1],
            "receiver_id": receiver[0],
            "receiver_username": receiver[1],
            "receiver_display_name": receiver[2] or receiver[1],
            "content": content,
            "text": content,
            "created_at": created_at.isoformat() if created_at else None
        }

        try:
            socketio.emit("new_message", message, room=receiver[1])
            socketio.emit("message_sent", message, room=user[1])
        except Exception as socket_error:
            print("SOCKET MESSAGE ERROR:", repr(socket_error))

        return jsonify({"success": True, "message": message}), 200

    except Exception as e:
        print("\n===================================")
        print("SEND MESSAGE FATAL ERROR")
        print("TYPE:", type(e).__name__)
        print("ERROR:", str(e))
        print("REPR:", repr(e))
        print("===================================")
        traceback.print_exc()

        return jsonify({
            "success": False,
            "message": "Ошибка отправки сообщения",
            "error": str(e)
        }), 500

@app.route("/api/mood", methods=["GET"])
def get_my_mood():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute("""
            SELECT
                id,
                mood,
                created_at
            FROM moods
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 30
        """, (user[0],))

        rows = cur.fetchall()

        return jsonify({
            "success": True,
            "moods": [
                {
                    "id": r[0],
                    "mood": r[1],
                    "created_at": (
                        r[2].isoformat()
                        if r[2]
                        else None
                    )
                }
                for r in rows
            ]
        })

    except Exception as e:

        print(
            "GET MOOD ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "message": "Ошибка загрузки настроения"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# MOOD POST
# =========================================================

@app.route("/api/mood", methods=["POST"])
def save_mood():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    data = request.get_json(silent=True) or {}

    mood = str(
        data.get("mood")
        or ""
    ).strip()

    if not mood:
        return jsonify({
            "success": False,
            "message": "Настроение не указано"
        }), 400

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute("""
            INSERT INTO moods (
                user_id,
                mood
            )
            VALUES (%s, %s)
            RETURNING
                id,
                mood,
                created_at
        """, (
            user[0],
            mood
        ))

        row = cur.fetchone()

        conn.commit()

        return jsonify({
            "success": True,
            "mood": {
                "id": row[0],
                "mood": row[1],
                "created_at": (
                    row[2].isoformat()
                    if row[2]
                    else None
                )
            }
        })

    except Exception as e:

        conn.rollback()

        print(
            "SAVE MOOD ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "message": "Ошибка сохранения настроения"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# GRATITUDE GET
# =========================================================

@app.route("/api/gratitude", methods=["GET"])
def get_my_gratitude():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute("""
            SELECT
                id,
                content,
                created_at
            FROM gratitude
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 50
        """, (user[0],))

        rows = cur.fetchall()

        return jsonify({
            "success": True,
            "gratitude": [
                {
                    "id": r[0],
                    "content": r[1],
                    "created_at": (
                        r[2].isoformat()
                        if r[2]
                        else None
                    )
                }
                for r in rows
            ]
        })

    except Exception as e:

        print(
            "GET GRATITUDE ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "message": "Ошибка загрузки благодарностей"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# GRATITUDE POST
# =========================================================

@app.route("/api/gratitude", methods=["POST"])
def save_gratitude():

    user = get_user_by_token()

    if not user:
        return unauthorized()

    data = request.get_json(silent=True) or {}

    content = str(
        data.get("content")
        or data.get("text")
        or ""
    ).strip()

    if not content:
        return jsonify({
            "success": False,
            "message": "Введите текст"
        }), 400

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute("""
            INSERT INTO gratitude (
                user_id,
                content
            )
            VALUES (%s, %s)
            RETURNING
                id,
                content,
                created_at
        """, (
            user[0],
            content
        ))

        row = cur.fetchone()

        conn.commit()

        return jsonify({
            "success": True,
            "gratitude": {
                "id": row[0],
                "content": row[1],
                "created_at": (
                    row[2].isoformat()
                    if row[2]
                    else None
                )
            }
        })

    except Exception as e:

        conn.rollback()

        print(
            "SAVE GRATITUDE ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "message": "Ошибка сохранения"
        }), 500

    finally:
        cur.close()
        conn.close()


# =========================================================
# SOCKET.IO CONNECT
# =========================================================

@socketio.on("connect")
def socket_connect(auth=None):

    print("SOCKET CONNECTION ATTEMPT")

    if not auth:

        print("SOCKET: NO AUTH")

        return False

    token = auth.get("token")

    if not token:

        print("SOCKET: NO TOKEN")

        return False

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        user_id = payload.get("user_id")

        if not user_id:

            print("SOCKET: NO USER ID")

            return False

        user = get_user_by_id(user_id)

        if not user:

            print("SOCKET: USER NOT FOUND")

            return False

        # Каждый пользователь находится
        # в комнате со своим username
        join_room(user[1])

        print(
            f"SOCKET AUTHORIZED: {user[1]}"
        )

        emit(
            "connected",
            {
                "success": True,
                "username": user[1]
            }
        )

        return True

    except Exception as e:

        print(
            "SOCKET AUTH ERROR:",
            repr(e)
        )

        return False


# =========================================================
# SOCKET DISCONNECT
# =========================================================

@socketio.on("disconnect")
def socket_disconnect():

    print("SOCKET DISCONNECTED")


# =========================================================
# ROOT
# =========================================================

@app.route("/")
def index():

    return jsonify({
        "success": True,
        "message": "Спокойный ум API работает"
    })


# =========================================================
# HEALTH
# =========================================================

@app.route("/api/health")
def health():

    try:

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT 1")
        cur.fetchone()

        cur.close()
        conn.close()

        return jsonify({
            "success": True,
            "database": True
        })

    except Exception as e:

        print(
            "HEALTH ERROR:",
            repr(e)
        )

        return jsonify({
            "success": False,
            "database": False,
            "error": str(e)
        }), 500


# =========================================================
# START
# =========================================================

print("===================================")
print("ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ")
print("===================================")

try:

    init_db()

    print("===================================")
    print("БАЗА ДАННЫХ ГОТОВА")
    print("===================================")

except Exception as e:

    print("DATABASE START ERROR:")
    print(repr(e))


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            10000
        )
    )

    print(
        f"SERVER STARTING ON PORT {port}"
    )

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        allow_unsafe_werkzeug=True
    )

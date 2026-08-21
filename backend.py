from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from functools import wraps
import psycopg2
import psycopg2.extras
import bcrypt
import jwt
import datetime
import json
import re
import time
import os

app = Flask(__name__)

CORS(app)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet"
)

SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "spokoyny_ym_dev_secret_change_me"
)

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL не задан в Environment Render")


# ============================================================
# DATABASE
# ============================================================

class ReturningCursor(psycopg2.extensions.cursor):
    def execute(self, query, vars=None):
        super().execute(query, vars)
        return self


def get_db():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=ReturningCursor
    )


# ============================================================
# LOGIN RATE LIMIT
# ============================================================

login_attempts = {}


def is_blocked(ip):
    if ip in login_attempts:
        data = login_attempts[ip]

        if (
            data['blocked_until']
            and data['blocked_until'] > time.time()
        ):
            return True

    return False


def record_failed_attempt(ip):
    if ip not in login_attempts:
        login_attempts[ip] = {
            'attempts': 0,
            'blocked_until': None
        }

    login_attempts[ip]['attempts'] += 1

    if login_attempts[ip]['attempts'] >= 5:
        login_attempts[ip]['blocked_until'] = time.time() + 300


def reset_attempts(ip):
    if ip in login_attempts:
        login_attempts[ip] = {
            'attempts': 0,
            'blocked_until': None
        }


# ============================================================
# DATABASE INIT
# ============================================================

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash BYTEA NOT NULL,
            display_name TEXT,
            email TEXT UNIQUE,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            text TEXT,
            mood TEXT DEFAULT '·',
            media TEXT,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            from_user TEXT NOT NULL,
            to_user TEXT NOT NULL,
            text TEXT NOT NULL,
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read BOOLEAN DEFAULT FALSE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS moods (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            mood TEXT NOT NULL,
            date DATE DEFAULT CURRENT_DATE,
            UNIQUE(username, date)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS gratitude (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS likes (
            post_id INTEGER NOT NULL
                REFERENCES posts(id)
                ON DELETE CASCADE,

            user_id INTEGER NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            PRIMARY KEY (post_id, user_id)
        )
    """)

    # --------------------------------------------------------
    # DEMO USERS
    # --------------------------------------------------------

    cursor.execute("SELECT COUNT(*) FROM users")

    if cursor.fetchone()[0] == 0:

        alex_hash = bcrypt.hashpw(
            "alex123".encode("utf-8"),
            bcrypt.gensalt()
        )

        marina_hash = bcrypt.hashpw(
            "marina123".encode("utf-8"),
            bcrypt.gensalt()
        )

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                display_name,
                email
            )
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                "alex",
                alex_hash,
                "Алекс",
                "alex@example.com"
            )
        )

        alex_id = cursor.fetchone()[0]

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                display_name,
                email
            )
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                "marina",
                marina_hash,
                "Марина",
                "marina@example.com"
            )
        )

        marina_id = cursor.fetchone()[0]

        cursor.execute(
            """
            INSERT INTO posts
            (
                user_id,
                text,
                mood
            )
            VALUES (%s, %s, %s)
            """,
            (
                alex_id,
                "тишина — это тоже голос",
                "·"
            )
        )

        cursor.execute(
            """
            INSERT INTO posts
            (
                user_id,
                text,
                mood
            )
            VALUES (%s, %s, %s)
            """,
            (
                marina_id,
                "заметил, как дышит ветер",
                "◌"
            )
        )

    conn.commit()

    cursor.close()
    conn.close()

    print("✅ PostgreSQL база данных готова!")


# ============================================================
# USER HELPERS
# ============================================================

def get_user_by_token(token):

    try:

        data = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        conn = get_db()
        cursor = conn.cursor()

        user = cursor.execute(
            """
            SELECT
                id,
                username,
                display_name,
                email,
                role
            FROM users
            WHERE id = %s
            """,
            [data['user_id']]
        ).fetchone()

        cursor.close()
        conn.close()

        return user

    except Exception:
        return None


def get_user_by_username(username):

    conn = get_db()
    cursor = conn.cursor()

    user = cursor.execute(
        """
        SELECT
            id,
            username,
            password_hash,
            display_name
        FROM users
        WHERE username = %s
        """,
        [username]
    ).fetchone()

    cursor.close()
    conn.close()

    return user


def get_user_by_email(email):

    conn = get_db()
    cursor = conn.cursor()

    user = cursor.execute(
        """
        SELECT
            id,
            username,
            password_hash,
            display_name,
            email
        FROM users
        WHERE email = %s
        """,
        [email]
    ).fetchone()

    cursor.close()
    conn.close()

    return user


def get_user_by_login(login):

    if '@' in login:
        return get_user_by_email(login)

    return get_user_by_username(login)


# ============================================================
# ADMIN
# ============================================================

def admin_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        token = request.headers.get('Authorization')

        if not token:
            return jsonify({
                "success": False,
                "message": "Не авторизован"
            }), 401

        token = token.replace('Bearer ', '')

        user = get_user_by_token(token)

        if not user or user[4] != 'admin':
            return jsonify({
                "success": False,
                "message": "Нет прав"
            }), 403

        return f(*args, **kwargs)

    return decorated


# ============================================================
# HEALTH
# ============================================================

@app.route('/api/health', methods=['GET'])
def health():

    return jsonify({
        "success": True,
        "server": "online",
        "websocket": True
    })


# ============================================================
# REGISTER
# ============================================================

@app.route('/api/register', methods=['POST'])
def register():

    data = request.get_json(silent=True) or {}

    username = str(
        data.get('username', '')
    ).strip().lower()

    password = str(
        data.get('password', '')
    )

    display_name = str(
        data.get('display_name', username)
    )

    email = str(
        data.get('email', '')
    ).strip().lower()

    if not username or not password or not email:

        return jsonify({
            "success": False,
            "message": "Заполните все поля"
        }), 400

    if len(password) < 8:

        return jsonify({
            "success": False,
            "message": "Пароль минимум 8 символов"
        }), 400

    if not re.search(r'[A-Z]', password):

        return jsonify({
            "success": False,
            "message": "Пароль должен содержать заглавную букву"
        }), 400

    if not re.search(r'\d', password):

        return jsonify({
            "success": False,
            "message": "Пароль должен содержать цифру"
        }), 400

    if not re.match(
        r'^[a-zA-Z0-9_]+$',
        username
    ):

        return jsonify({
            "success": False,
            "message": "Юзернейм: только латиница, цифры и _"
        }), 400

    if '@' not in email:

        return jsonify({
            "success": False,
            "message": "Введите корректный email"
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    try:

        password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        )

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                password_hash,
                display_name,
                email
            )
            VALUES (%s, %s, %s, %s)
            """,
            [
                username,
                password_hash,
                display_name,
                email
            ]
        )

        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "message": "Регистрация успешна!"
        }), 201

    except psycopg2.IntegrityError:

        conn.rollback()
        cursor.close()
        conn.close()

        return jsonify({
            "success": False,
            "message": "Пользователь или email уже существует"
        }), 409

    except Exception as e:

        conn.rollback()
        cursor.close()
        conn.close()

        print(f"❌ Ошибка регистрации: {e}")

        return jsonify({
            "success": False,
            "message": "Ошибка сервера"
        }), 500


# ============================================================
# LOGIN
# ============================================================

@app.route('/api/login', methods=['POST'])
def login():

    ip = request.remote_addr

    data = request.get_json(silent=True) or {}

    login_value = str(
        data.get('login', '')
    ).strip().lower()

    password = str(
        data.get('password', '')
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

    user = get_user_by_login(login_value)

    if not user:

        record_failed_attempt(ip)

        return jsonify({
            "success": False,
            "message": "Пользователь не найден"
        }), 401

    # ========================================================
    # FIX:
    # PostgreSQL BYTEA возвращается как memoryview.
    # bcrypt.checkpw() требует bytes.
    # ========================================================

    hashed_password = user[2]

    if isinstance(
        hashed_password,
        memoryview
    ):
        hashed_password = hashed_password.tobytes()

    elif isinstance(
        hashed_password,
        bytearray
    ):
        hashed_password = bytes(
            hashed_password
        )

    elif isinstance(
        hashed_password,
        str
    ):
        hashed_password = hashed_password.encode(
            'utf-8'
        )

    try:

        password_correct = bcrypt.checkpw(
            password.encode('utf-8'),
            hashed_password
        )

    except Exception as e:

        print(
            f"❌ Ошибка проверки пароля: {e}"
        )

        return jsonify({
            "success": False,
            "message": "Ошибка проверки пароля"
        }), 500

    if not password_correct:

        record_failed_attempt(ip)

        return jsonify({
            "success": False,
            "message": "Неверный пароль"
        }), 401

    reset_attempts(ip)

    token = jwt.encode(
        {
            "user_id": user[0],
            "username": user[1],
            "exp": datetime.datetime.utcnow()
            + datetime.timedelta(days=7)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "id": user[0],
            "username": user[1],
            "display_name": user[3],
            "email": user[4]
        }
    }), 200


# ============================================================
# PASSWORD RECOVERY
# ============================================================

@app.route('/api/recover', methods=['POST'])
def recover_password():

    data = request.get_json(silent=True) or {}

    email = str(
        data.get('email', '')
    ).strip().lower()

    if not email:

        return jsonify({
            "success": False,
            "message": "Введите email"
        }), 400

    user = get_user_by_email(email)

    if not user:

        return jsonify({
            "success": False,
            "message": "Пользователь с таким email не найден"
        }), 404

    return jsonify({
        "success": True,
        "message": (
            "Ссылка для сброса пароля отправлена "
            "на почту (демо: код 123456)"
        ),
        "code": "123456"
    })


# ============================================================
# USERS
# ============================================================

@app.route('/api/users', methods=['GET'])
def get_users():

    conn = get_db()
    cursor = conn.cursor()

    users = cursor.execute(
        """
        SELECT
            username,
            display_name,
            email
        FROM users
        ORDER BY id
        """
    ).fetchall()

    cursor.close()
    conn.close()

    result = []

    for u in users:

        result.append({
            "username": u[0],
            "display_name": u[1],
            "email": u[2]
        })

    return jsonify(result)


# ============================================================
# POSTS
# ============================================================

@app.route('/api/posts', methods=['GET'])
def get_posts():

    conn = get_db()
    cursor = conn.cursor()

    posts = cursor.execute(
        '''
        SELECT
            users.username,
            users.display_name,
            posts.text,
            posts.mood,
            posts.media,
            posts.time,
            posts.id
        FROM posts
        JOIN users
            ON posts.user_id = users.id
        ORDER BY posts.time DESC
        '''
    ).fetchall()

    cursor.close()
    conn.close()

    result = []

    for p in posts:

        try:
            media = json.loads(p[4]) if p[4] else []
        except Exception:
            media = []

        result.append({
            "username": p[0],
            "display_name": p[1],
            "text": p[2],
            "mood": p[3] or '·',
            "media": media,
            "time": p[5],
            "id": p[6],
            "likes": 0
        })

    return jsonify(result)


@app.route('/api/posts', methods=['POST'])
def create_post():

    token = request.headers.get(
        'Authorization'
    )

    if not token:

        return jsonify({
            "success": False,
            "message": "Не авторизован"
        }), 401

    token = token.replace(
        'Bearer ',
        ''
    )

    user = get_user_by_token(token)

    if not user:

        return jsonify({
            "success": False,
            "message": "Неверный токен"
        }), 401

    data = request.get_json(silent=True) or {}

    text = str(
        data.get('text', '')
    ).strip()

    mood = data.get(
        'mood',
        '·'
    )

    if not text:

        return jsonify({
            "success": False,
            "message": "Напишите что-нибудь"
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO posts
        (
            user_id,
            text,
            mood
        )
        VALUES (%s, %s, %s)
        """,
        [
            user[0],
            text,
            mood
        ]
    )

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Пост опубликован"
    })


@app.route('/api/posts/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):

    token = request.headers.get(
        'Authorization'
    )

    if not token:

        return jsonify({
            "success": False,
            "message": "Не авторизован"
        }), 401

    token = token.replace(
        'Bearer ',
        ''
    )

    user = get_user_by_token(token)

    if not user:

        return jsonify({
            "success": False,
            "message": "Неверный токен"
        }), 401

    conn = get_db()
    cursor = conn.cursor()

    post = cursor.execute(
        """
        SELECT user_id
        FROM posts
        WHERE id = %s
        """,
        [post_id]
    ).fetchone()

    if not post or post[0] != user[0]:

        cursor.close()
        conn.close()

        return jsonify({
            "success": False,
            "message": "Нельзя удалить чужой пост"
        }), 403

    cursor.execute(
        """
        DELETE FROM posts
        WHERE id = %s
        """,
        [post_id]
    )

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Пост удалён"
    })


# ============================================================
# LIKES
# ============================================================

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
def like_post(post_id):

    token = request.headers.get(
        'Authorization'
    )

    if not token:

        return jsonify({
            "success": False,
            "message": "Не авторизован"
        }), 401

    token = token.replace(
        'Bearer ',
        ''
    )

    user = get_user_by_token(token)

    if not user:

        return jsonify({
            "success": False,
            "message": "Неверный токен"
        }), 401

    conn = get_db()
    cursor = conn.cursor()

    existing = cursor.execute(
        """
        SELECT *
        FROM likes
        WHERE post_id = %s
        AND user_id = %s
        """,
        [
            post_id,
            user[0]
        ]
    ).fetchone()

    if existing:

        cursor.execute(
            """
            DELETE FROM likes
            WHERE post_id = %s
            AND user_id = %s
            """,
            [
                post_id,
                user[0]
            ]
        )

        conn.commit()

        cursor.close()
        conn.close()

        return jsonify({
            "success": True,
            "liked": False
        })

    cursor.execute(
        """
        INSERT INTO likes
        (
            post_id,
            user_id
        )
        VALUES (%s, %s)
        """,
        [
            post_id,
            user[0]
        ]
    )

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({
        "success": True,
        "liked": True
    })


# ============================================================
# CHATS
# ============================================================

@app.route('/api/chats', methods=['GET'])
def get_chats():

    token = request.headers.get(
        'Authorization'
    )

    if not token:

        return jsonify({
            "success": False,
            "message": "Не авторизован"
        }), 401

    token = token.replace(
        'Bearer ',
        ''
    )

    user = get_user_by_token(token)

    if not user:

        return jsonify({
            "success": False,
            "message": "Неверный токен"
        }), 401

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT DISTINCT
            CASE
                WHEN from_user = %s
                THEN to_user
                ELSE from_user
            END
        FROM messages
        WHERE from_user = %s
        OR to_user = %s
        ''',
        [
            user[1],
            user[1],
            user[1]
        ]
    )

    partners = cursor.fetchall()

    result = []

    for p in partners:

        partner = p[0]

        last = cursor.execute(
            '''
            SELECT
                text,
                time
            FROM messages
            WHERE
                (
                    from_user = %s
                    AND to_user = %s
                )
                OR
                (
                    from_user = %s
                    AND to_user = %s
                )
            ORDER BY time DESC
            LIMIT 1
            ''',
            [
                user[1],
                partner,
                partner,
                user[1]
            ]
        ).fetchone()

        unread = cursor.execute(
            '''
            SELECT COUNT(*)
            FROM messages
            WHERE
                from_user = %s
                AND to_user = %s
                AND read = FALSE
            ''',
            [
                partner,
                user[1]
            ]
        ).fetchone()[0]

        result.append({
            "username": partner,
            "last_message": (
                last[0]
                if last
                else ''
            ),
            "last_time": (
                last[1]
                if last
                else None
            ),
            "unread": unread
        })

    cursor.close()
    conn.close()

    return jsonify(result)


# ============================================================
# SEND MESSAGE
# ============================================================

@app.route('/api/messages', methods=['POST'])
def send_message():

    token = request.headers.get(
        'Authorization'
    )

    if not token:

        return jsonify({
            "success": False,
            "message": "Не авторизован"
        }), 401

    token = token.replace(
        'Bearer ',
        ''
    )

    user = get_user_by_token(token)

    if not user:

        return jsonify({
            "success": False,
            "message": "Неверный токен"
        }), 401

    data = request.get_json(silent=True) or {}

    to_user = str(
        data.get('to_user', '')
    ).strip().lower()

    text = str(
        data.get('text', '')
    ).strip()

    if not to_user or not text:

        return jsonify({
            "success": False,
            "message": "Заполните все поля"
        }), 400

    if len(text) > 5000:

        return jsonify({
            "success": False,
            "message": "Сообщение слишком длинное"
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    receiver = cursor.execute(
        """
        SELECT username
        FROM users
        WHERE username = %s
        """,
        [to_user]
    ).fetchone()

    if not receiver:

        cursor.close()
        conn.close()

        return jsonify({
            "success": False,
            "message": "Пользователь не найден"
        }), 404

    cursor.execute(
        """
        INSERT INTO messages
        (
            from_user,
            to_user,
            text
        )
        VALUES (%s, %s, %s)
        RETURNING id
        """,
        (
            user[1],
            to_user,
            text
        )
    )

    message_id = cursor.fetchone()[0]

    row = cursor.execute(
        """
        SELECT
            id,
            from_user,
            to_user,
            text,
            time,
            read
        FROM messages
        WHERE id = %s
        """,
        [message_id]
    ).fetchone()

    conn.commit()

    cursor.close()
    conn.close()

    message = {
        "id": row[0],
        "from": row[1],
        "to": row[2],
        "text": row[3],
        "time": row[4],
        "read": bool(row[5])
    }

    # Real-time
    socketio.emit(
        "new_message",
        message,
        room=to_user
    )

    socketio.emit(
        "message_sent",
        message,
        room=user[1]
    )

    return jsonify({
        "success": True,
        "message": "Сообщение отправлено",
        "data": message
    })


# ============================================================
# GET MESSAGES
# ============================================================

@app.route('/api/messages/<username>', methods=['GET'])
def get_messages(username):

    token = request.headers.get(
        'Authorization'
    )

    if not token:

        return jsonify({
            "success": False,
            "message": "Не авторизован"
        }), 401

    token = token.replace(
        'Bearer ',
        ''
    )

    user = get_user_by_token(token)

    if not user:

        return jsonify({
            "success": False,
            "message": "Неверный токен"
        }), 401

    username = username.strip().lower()

    conn = get_db()
    cursor = conn.cursor()

    messages = cursor.execute(
        '''
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
                from_user = %s
                AND to_user = %s
            )
            OR
            (
                from_user = %s
                AND to_user = %s
            )
        ORDER BY id ASC
        ''',
        [
            user[1],
            username,
            username,
            user[1]
        ]
    ).fetchall()

    result = []

    for m in messages:

        result.append({
            "id": m[0],
            "from": m[1],
            "to": m[2],
            "text": m[3],
            "time": m[4],
            "read": bool(m[5])
        })

    cursor.execute(
        """
        UPDATE messages
        SET read = TRUE
        WHERE
            from_user = %s
            AND to_user = %s
        """,
        [
            username,
            user[1]
        ]
    )

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify(result)


# ============================================================
# MOOD
# ============================================================

@app.route('/api/mood', methods=['POST'])
def save_mood():

    data = request.get_json(silent=True) or {}

    username = str(
        data.get('username', '')
    ).strip().lower()

    mood = str(
        data.get('mood', '')
    )

    if not username or not mood:

        return jsonify({
            "success": False,
            "message": "Заполните все поля"
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO moods
        (
            username,
            mood,
            date
        )
        VALUES
        (
            %s,
            %s,
            CURRENT_DATE
        )
        ON CONFLICT
        (
            username,
            date
        )
        DO UPDATE
        SET mood = EXCLUDED.mood
        """,
        [
            username,
            mood
        ]
    )

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Состояние сохранено"
    })


@app.route('/api/mood/<username>', methods=['GET'])
def get_mood(username):

    conn = get_db()
    cursor = conn.cursor()

    mood = cursor.execute(
        """
        SELECT mood
        FROM moods
        WHERE
            username = %s
            AND date = CURRENT_DATE
        """,
        [username]
    ).fetchone()

    cursor.close()
    conn.close()

    return jsonify({
        "mood": mood[0]
        if mood
        else None
    })


# ============================================================
# GRATITUDE
# ============================================================

@app.route('/api/gratitude', methods=['POST'])
def save_gratitude():

    data = request.get_json(silent=True) or {}

    username = str(
        data.get('username', '')
    ).strip().lower()

    text = str(
        data.get('text', '')
    ).strip()

    if not username or not text:

        return jsonify({
            "success": False,
            "message": "Заполните все поля"
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO gratitude
        (
            username,
            text
        )
        VALUES (%s, %s)
        """,
        [
            username,
            text
        ]
    )

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Благодарность сохранена"
    })


@app.route('/api/gratitude/<username>', methods=['GET'])
def get_gratitude(username):

    conn = get_db()
    cursor = conn.cursor()

    entries = cursor.execute(
        """
        SELECT
            text,
            date
        FROM gratitude
        WHERE username = %s
        ORDER BY date DESC
        LIMIT 10
        """,
        [username]
    ).fetchall()

    cursor.close()
    conn.close()

    return jsonify([
        {
            "text": e[0],
            "date": e[1]
        }
        for e in entries
    ])


# ============================================================
# SEARCH
# ============================================================

@app.route('/api/search', methods=['GET'])
def search_users():

    query = request.args.get(
        'q',
        ''
    ).strip().lower()

    if not query:
        return jsonify([])

    conn = get_db()
    cursor = conn.cursor()

    users = cursor.execute(
        """
        SELECT
            username,
            display_name,
            email
        FROM users
        WHERE
            username LIKE %s
            OR display_name LIKE %s
        LIMIT 10
        """,
        [
            f'%{query}%',
            f'%{query}%'
        ]
    ).fetchall()

    cursor.close()
    conn.close()

    result = []

    for u in users:

        result.append({
            "username": u[0],
            "display_name": u[1],
            "email": u[2]
        })

    return jsonify(result)


# ============================================================
# CURRENT USER
# ============================================================

@app.route('/api/me', methods=['GET'])
def get_me():

    token = request.headers.get(
        'Authorization'
    )

    if not token:

        return jsonify({
            "error": "Не авторизован"
        }), 401

    token = token.replace(
        'Bearer ',
        ''
    )

    user = get_user_by_token(token)

    if not user:

        return jsonify({
            "error": "Неверный токен"
        }), 401

    return jsonify({
        "id": user[0],
        "username": user[1],
        "display_name": user[2],
        "email": user[3]
    })


# ============================================================
# ADMIN - MODERATOR
# ============================================================

@app.route(
    '/api/admin/make_moderator',
    methods=['POST']
)
@admin_required
def make_moderator():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get('username', '')
    ).strip().lower()

    if not username:

        return jsonify({
            "success": False,
            "message": "Укажите пользователя"
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET role = 'moderator'
        WHERE username = %s
        """,
        [username]
    )

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({
        "success": True,
        "message": (
            f"{username} теперь модератор"
        )
    })


# ============================================================
# ADMIN - BAN
# ============================================================

@app.route(
    '/api/admin/ban',
    methods=['POST']
)
@admin_required
def ban_user():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get('username', '')
    ).strip().lower()

    if not username:

        return jsonify({
            "success": False,
            "message": "Укажите пользователя"
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET role = 'banned'
        WHERE username = %s
        """,
        [username]
    )

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({
        "success": True,
        "message": (
            f"{username} забанен"
        )
    })


# ============================================================
# SOCKET.IO
# ============================================================

@socketio.on('connect')
def socket_connect(auth):

    if not auth or not auth.get('token'):
        return False

    user = get_user_by_token(
        auth['token']
    )

    if not user:
        return False

    join_room(
        user[1]
    )

    emit(
        'connected',
        {
            'success': True,
            'username': user[1]
        }
    )

    print(
        f"🟢 WebSocket подключён: @{user[1]}"
    )


@socketio.on('disconnect')
def socket_disconnect():

    print(
        "🔴 WebSocket отключён"
    )


# ============================================================
# INIT DATABASE
# ============================================================

init_db()


# ============================================================
# START SERVER
# ============================================================

if __name__ == '__main__':

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    print(
        f"🚀 Сервер запущен на "
        f"http://0.0.0.0:{port}"
    )

    print(
        "📡 API доступны по адресу /api/..."
    )

    print(
        "💬 WebSocket включён"
    )

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=False
    )

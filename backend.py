import os
import datetime
import bcrypt
import jwt
import psycopg2

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room


# =========================================================
# CONFIG
# =========================================================

app = Flask(__name__)

SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "spokoyny_ym_dev_secret_change_me"
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
    async_mode="eventlet"
)


# =========================================================
# DATABASE
# =========================================================

def get_db():

    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL не задан")

    return psycopg2.connect(DATABASE_URL)


def init_db():

    conn = get_db()
    cur = conn.cursor()

    # -----------------------------------------------------
    # USERS
    # -----------------------------------------------------

    cur.execute("""
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


    # -----------------------------------------------------
    # FAILED ATTEMPTS
    # -----------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS failed_attempts (
            ip TEXT PRIMARY KEY,
            attempts INTEGER DEFAULT 0,
            last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # -----------------------------------------------------
    # POSTS
    # -----------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ВАЖНО:
    # Если таблица posts уже существовала раньше,
    # CREATE TABLE IF NOT EXISTS её НЕ меняет.
    # Поэтому добавляем отсутствующие колонки отдельно.

    cur.execute("""
        ALTER TABLE posts
        ADD COLUMN IF NOT EXISTS content TEXT
    """)

    cur.execute("""
        ALTER TABLE posts
        ADD COLUMN IF NOT EXISTS created_at
        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    """)


    # -----------------------------------------------------
    # LIKES
    # -----------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS likes (
            id SERIAL PRIMARY KEY,
            post_id INTEGER
                REFERENCES posts(id)
                ON DELETE CASCADE,

            user_id INTEGER
                REFERENCES users(id)
                ON DELETE CASCADE,

            UNIQUE(post_id, user_id)
        )
    """)


    # -----------------------------------------------------
    # CHATS
    # -----------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chats (
            id SERIAL PRIMARY KEY,

            user1_id INTEGER
                REFERENCES users(id)
                ON DELETE CASCADE,

            user2_id INTEGER
                REFERENCES users(id)
                ON DELETE CASCADE,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # -----------------------------------------------------
    # MESSAGES
    # -----------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,

            sender_id INTEGER
                REFERENCES users(id)
                ON DELETE CASCADE,

            receiver_id INTEGER
                REFERENCES users(id)
                ON DELETE CASCADE,

            content TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # -----------------------------------------------------
    # MOODS
    # -----------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS moods (
            id SERIAL PRIMARY KEY,

            user_id INTEGER
                REFERENCES users(id)
                ON DELETE CASCADE,

            mood TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


    # -----------------------------------------------------
    # GRATITUDE
    # -----------------------------------------------------

    cur.execute("""
        CREATE TABLE IF NOT EXISTS gratitude (
            id SERIAL PRIMARY KEY,

            user_id INTEGER
                REFERENCES users(id)
                ON DELETE CASCADE,

            content TEXT NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


    conn.commit()

    cur.close()
    conn.close()

    print("DATABASE INITIALIZED")


# =========================================================
# HELPERS
# =========================================================

def get_json():

    return request.get_json(
        silent=True
    ) or {}


def normalize(value):

    return str(
        value or ""
    ).strip().lower()


# =========================================================
# PASSWORD
# =========================================================

def hash_password(password):

    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )


def check_password(password, stored_hash):

    # PostgreSQL BYTEA может возвращать memoryview.
    # bcrypt принимает bytes.

    if isinstance(
        stored_hash,
        memoryview
    ):
        stored_hash = stored_hash.tobytes()

    elif isinstance(
        stored_hash,
        bytearray
    ):
        stored_hash = bytes(
            stored_hash
        )

    elif isinstance(
        stored_hash,
        str
    ):
        stored_hash = stored_hash.encode(
            "utf-8"
        )

    return bcrypt.checkpw(
        password.encode("utf-8"),
        stored_hash
    )


# =========================================================
# JWT
# =========================================================

def create_token(
    user_id,
    username
):

    now = datetime.datetime.now(
        datetime.timezone.utc
    )

    return jwt.encode(
        {
            "user_id": user_id,
            "username": username,

            "exp":
                now
                + datetime.timedelta(
                    days=7
                )
        },

        SECRET_KEY,

        algorithm="HS256"
    )


def get_token_from_request():

    auth = request.headers.get(
        "Authorization",
        ""
    )

    if not auth:
        return None

    if auth.lower().startswith(
        "bearer "
    ):
        return auth[7:].strip()

    return auth.strip()


def get_user_by_token(token):

    try:

        if not token:

            print(
                "JWT: токен пустой"
            )

            return None


        token = token.replace(
            "Bearer ",
            ""
        ).strip()


        data = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )


        user_id = data.get(
            "user_id"
        )


        if not user_id:

            print(
                "JWT: нет user_id"
            )

            return None


        conn = get_db()
        cur = conn.cursor()


        cur.execute("""
            SELECT
                id,
                username,
                display_name,
                email,
                role
            FROM users
            WHERE id = %s
        """, (
            user_id,
        ))


        user = cur.fetchone()


        cur.close()
        conn.close()


        if not user:

            print(
                f"JWT: пользователь "
                f"id={user_id} не найден"
            )

            return None


        return user


    except jwt.ExpiredSignatureError:

        print(
            "JWT: токен истёк"
        )

        return None


    except jwt.InvalidTokenError as e:

        print(
            f"JWT: недействительный "
            f"токен: {e}"
        )

        return None


    except Exception as e:

        print(
            f"JWT ERROR: "
            f"{type(e).__name__}: {e}"
        )

        return None


def auth_user():

    token = get_token_from_request()

    if not token:
        return None

    return get_user_by_token(
        token
    )


def auth_error():

    return jsonify({

        "success": False,

        "message":
            "Токен недействителен"

    }), 401


# =========================================================
# USERS
# =========================================================

def get_user_by_email(email):

    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT
            id,
            username,
            password_hash,
            display_name,
            email
        FROM users
        WHERE email = %s
    """, (
        email,
    ))


    user = cur.fetchone()


    cur.close()
    conn.close()


    return user


def get_user_by_username(username):

    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT
            id,
            username,
            password_hash,
            display_name,
            email
        FROM users
        WHERE username = %s
    """, (
        username,
    ))


    user = cur.fetchone()


    cur.close()
    conn.close()


    return user


def get_user_by_login(login):

    user = get_user_by_email(
        login
    )

    if user:
        return user

    return get_user_by_username(
        login
    )


# =========================================================
# LOGIN ATTEMPTS
# =========================================================

def is_blocked(ip):

    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT
            attempts,
            last_attempt
        FROM failed_attempts
        WHERE ip = %s
    """, (
        ip,
    ))


    row = cur.fetchone()


    cur.close()
    conn.close()


    if not row:
        return False


    attempts, last_attempt = row


    if attempts < 5:
        return False


    now = datetime.datetime.now(
        datetime.timezone.utc
    )


    if last_attempt.tzinfo is None:

        last_attempt = (
            last_attempt.replace(
                tzinfo=datetime.timezone.utc
            )
        )


    if (
        now - last_attempt
        >= datetime.timedelta(
            minutes=5
        )
    ):

        reset_attempts(ip)

        return False


    return True


def record_failed_attempt(ip):

    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        INSERT INTO failed_attempts
            (
                ip,
                attempts,
                last_attempt
            )

        VALUES
            (
                %s,
                1,
                CURRENT_TIMESTAMP
            )

        ON CONFLICT (ip)

        DO UPDATE SET

            attempts =
                failed_attempts.attempts
                + 1,

            last_attempt =
                CURRENT_TIMESTAMP
    """, (
        ip,
    ))


    conn.commit()


    cur.close()
    conn.close()


def reset_attempts(ip):

    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        DELETE FROM failed_attempts
        WHERE ip = %s
    """, (
        ip,
    ))


    conn.commit()


    cur.close()
    conn.close()


# =========================================================
# MAIN
# =========================================================

@app.route("/")
def home():

    return jsonify({

        "success": True,

        "message":
            "Спокойный ум API работает"

    })


@app.route(
    "/api/health"
)
def health():

    return jsonify({

        "success": True,

        "message":
            "Server is online"

    })


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/api/register",
    methods=["POST"]
)
def register():

    try:

        data = get_json()


        username = normalize(
            data.get("username")
        )


        email = normalize(
            data.get("email")
        )


        password = str(
            data.get("password")
            or ""
        )


        display_name = str(

            data.get(
                "display_name"
            )

            or data.get(
                "displayName"
            )

            or username

        ).strip()


        if (
            not username
            or not email
            or not password
        ):

            return jsonify({

                "success": False,

                "message":
                    "Заполните все поля"

            }), 400


        if len(username) < 3:

            return jsonify({

                "success": False,

                "message":
                    "Логин должен содержать "
                    "минимум 3 символа"

            }), 400


        if len(password) < 6:

            return jsonify({

                "success": False,

                "message":
                    "Пароль должен содержать "
                    "минимум 6 символов"

            }), 400


        if get_user_by_username(
            username
        ):

            return jsonify({

                "success": False,

                "message":
                    "Такой логин "
                    "уже существует"

            }), 409


        if get_user_by_email(
            email
        ):

            return jsonify({

                "success": False,

                "message":
                    "Такая почта "
                    "уже зарегистрирована"

            }), 409


        password_hash = hash_password(
            password
        )


        conn = get_db()
        cur = conn.cursor()


        cur.execute("""
            INSERT INTO users
                (
                    username,
                    password_hash,
                    display_name,
                    email
                )

            VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s
                )

            RETURNING
                id,
                username,
                display_name,
                email,
                role
        """, (

            username,

            psycopg2.Binary(
                password_hash
            ),

            display_name,

            email

        ))


        user = cur.fetchone()


        conn.commit()


        cur.close()
        conn.close()


        token = create_token(
            user[0],
            user[1]
        )


        return jsonify({

            "success": True,

            "token": token,

            "user": {

                "id": user[0],

                "username": user[1],

                "display_name":
                    user[2],

                "email":
                    user[3],

                "role":
                    user[4]

            }

        }), 201


    except Exception as e:

        print(
            f"REGISTER ERROR: "
            f"{type(e).__name__}: {e}"
        )


        return jsonify({

            "success": False,

            "message":
                "Ошибка сервера"

        }), 500


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/api/login",
    methods=["POST"]
)
def login():

    try:

        ip = (
            request.remote_addr
            or "unknown"
        )


        data = get_json()


        login_value = normalize(

            data.get("login")

            or data.get("username")

            or data.get("email")

        )


        password = str(
            data.get("password")
            or ""
        )


        if (
            not login_value
            or not password
        ):

            return jsonify({

                "success": False,

                "message":
                    "Заполните все поля"

            }), 400


        if is_blocked(ip):

            return jsonify({

                "success": False,

                "message":
                    "Слишком много попыток. "
                    "Подождите 5 минут."

            }), 429


        user = get_user_by_login(
            login_value
        )


        if not user:

            record_failed_attempt(
                ip
            )

            return jsonify({

                "success": False,

                "message":
                    "Пользователь не найден"

            }), 401


        try:

            # =================================================
            # ГЛАВНОЕ ИСПРАВЛЕНИЕ:
            # PostgreSQL BYTEA -> memoryview.
            # check_password превращает его в bytes.
            # =================================================

            correct = check_password(
                password,
                user[2]
            )


        except Exception as e:

            print(
                f"BCRYPT ERROR: "
                f"{type(e).__name__}: {e}"
            )


            return jsonify({

                "success": False,

                "message":
                    "Ошибка проверки пароля"

            }), 500


        if not correct:

            record_failed_attempt(
                ip
            )

            return jsonify({

                "success": False,

                "message":
                    "Неверный пароль"

            }), 401


        reset_attempts(ip)


        token = create_token(
            user[0],
            user[1]
        )


        print(
            f"LOGIN: @{user[1]} вошёл"
        )


        return jsonify({

            "success": True,

            "token": token,

            "user": {

                "id":
                    user[0],

                "username":
                    user[1],

                "display_name":
                    user[3],

                "email":
                    user[4]

            }

        })


    except Exception as e:

        print(
            f"LOGIN ERROR: "
            f"{type(e).__name__}: {e}"
        )


        return jsonify({

            "success": False,

            "message":
                "Ошибка сервера"

        }), 500


# =========================================================
# ME
# =========================================================

@app.route(
    "/api/me",
    methods=["GET"]
)
def me():

    user = auth_user()


    if not user:
        return auth_error()


    return jsonify({

        "success": True,

        "user": {

            "id":
                user[0],

            "username":
                user[1],

            "display_name":
                user[2],

            "email":
                user[3],

            "role":
                user[4]

        }

    })


# =========================================================
# USERS
# =========================================================

@app.route(
    "/api/users",
    methods=["GET"]
)
def users():

    user = auth_user()


    if not user:
        return auth_error()


    search = normalize(
        request.args.get(
            "search"
        )
    )


    conn = get_db()
    cur = conn.cursor()


    if search:

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

            f"%{search}%",

            f"%{search}%"

        ))


    else:

        cur.execute("""
            SELECT
                id,
                username,
                display_name,
                email,
                role
            FROM users
            ORDER BY username
            LIMIT 50
        """)


    rows = cur.fetchall()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "users": [

            {

                "id":
                    row[0],

                "username":
                    row[1],

                "display_name":
                    row[2],

                "email":
                    row[3],

                "role":
                    row[4]

            }

            for row in rows

        ]

    })


@app.route(
    "/api/search",
    methods=["GET"]
)
def search():

    user = auth_user()


    if not user:
        return auth_error()


    query = normalize(
        request.args.get("q")
    )


    conn = get_db()
    cur = conn.cursor()


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
            OR email ILIKE %s
        ORDER BY username
        LIMIT 50
    """, (

        f"%{query}%",

        f"%{query}%",

        f"%{query}%"

    ))


    rows = cur.fetchall()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "users": [

            {

                "id":
                    row[0],

                "username":
                    row[1],

                "display_name":
                    row[2],

                "email":
                    row[3],

                "role":
                    row[4]

            }

            for row in rows

        ]

    })


# =========================================================
# POSTS
# =========================================================

@app.route(
    "/api/posts",
    methods=["GET"]
)
def get_posts():

    user = auth_user()


    if not user:
        return auth_error()


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT
            p.id,
            p.user_id,
            u.username,
            u.display_name,
            p.content,
            p.created_at,
            COUNT(l.id)

        FROM posts p

        JOIN users u
            ON u.id = p.user_id

        LEFT JOIN likes l
            ON l.post_id = p.id

        GROUP BY
            p.id,
            p.user_id,
            u.username,
            u.display_name,
            p.content,
            p.created_at

        ORDER BY
            p.created_at DESC

        LIMIT 100
    """)


    rows = cur.fetchall()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "posts": [

            {

                "id":
                    row[0],

                "user_id":
                    row[1],

                "username":
                    row[2],

                "display_name":
                    row[3],

                "content":
                    row[4],

                "created_at":
                    row[5].isoformat()
                    if row[5]
                    else None,

                "likes":
                    row[6]

            }

            for row in rows

        ]

    })


@app.route(
    "/api/posts",
    methods=["POST"]
)
def create_post():

    user = auth_user()


    if not user:
        return auth_error()


    data = get_json()


    content = str(
        data.get("content")
        or ""
    ).strip()


    if not content:

        return jsonify({

            "success": False,

            "message":
                "Введите текст"

        }), 400


    if len(content) > 5000:

        return jsonify({

            "success": False,

            "message":
                "Пост слишком длинный"

        }), 400


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        INSERT INTO posts
            (
                user_id,
                content
            )

        VALUES
            (
                %s,
                %s
            )

        RETURNING
            id,
            created_at
    """, (

        user[0],

        content

    ))


    post_id, created_at = (
        cur.fetchone()
    )


    conn.commit()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "post": {

            "id":
                post_id,

            "user_id":
                user[0],

            "username":
                user[1],

            "display_name":
                user[2],

            "content":
                content,

            "created_at":
                created_at.isoformat()

        }

    }), 201


@app.route(
    "/api/posts/<int:post_id>/like",
    methods=["POST"]
)
def like_post(post_id):

    user = auth_user()


    if not user:
        return auth_error()


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT id
        FROM likes
        WHERE
            post_id = %s
            AND user_id = %s
    """, (

        post_id,

        user[0]

    ))


    existing = cur.fetchone()


    if existing:

        cur.execute("""
            DELETE FROM likes
            WHERE id = %s
        """, (
            existing[0],
        ))

        liked = False


    else:

        cur.execute("""
            INSERT INTO likes
                (
                    post_id,
                    user_id
                )

            VALUES
                (
                    %s,
                    %s
                )

            ON CONFLICT DO NOTHING
        """, (

            post_id,

            user[0]

        ))

        liked = True


    cur.execute("""
        SELECT COUNT(*)
        FROM likes
        WHERE post_id = %s
    """, (
        post_id,
    ))


    count = cur.fetchone()[0]


    conn.commit()


    cur.close()
    conn.close()


    return jsonify({

        "success":
            True,

        "liked":
            liked,

        "likes":
            count

    })


# =========================================================
# CHATS
# =========================================================

@app.route(
    "/api/chats",
    methods=["GET"]
)
def get_chats():

    user = auth_user()


    if not user:
        return auth_error()


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT
            c.id,

            CASE
                WHEN c.user1_id = %s
                THEN c.user2_id
                ELSE c.user1_id
            END,

            u.username,
            u.display_name

        FROM chats c

        JOIN users u
            ON u.id =
                CASE
                    WHEN c.user1_id = %s
                    THEN c.user2_id
                    ELSE c.user1_id
                END

        WHERE
            c.user1_id = %s
            OR c.user2_id = %s

        ORDER BY
            c.created_at DESC
    """, (

        user[0],
        user[0],
        user[0],
        user[0]

    ))


    rows = cur.fetchall()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "chats": [

            {

                "id":
                    row[0],

                "user_id":
                    row[1],

                "username":
                    row[2],

                "display_name":
                    row[3]

            }

            for row in rows

        ]

    })


@app.route(
    "/api/chats",
    methods=["POST"]
)
def create_chat():

    user = auth_user()


    if not user:
        return auth_error()


    data = get_json()


    try:

        other_user_id = int(
            data.get("user_id")
        )

    except (
        TypeError,
        ValueError
    ):

        return jsonify({

            "success": False,

            "message":
                "Неверный user_id"

        }), 400


    if other_user_id == user[0]:

        return jsonify({

            "success": False,

            "message":
                "Нельзя создать "
                "чат с самим собой"

        }), 400


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT
            id,
            username,
            display_name
        FROM users
        WHERE id = %s
    """, (
        other_user_id,
    ))


    other = cur.fetchone()


    if not other:

        cur.close()
        conn.close()


        return jsonify({

            "success": False,

            "message":
                "Пользователь "
                "не найден"

        }), 404


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

        other_user_id,

        other_user_id,

        user[0]

    ))


    chat = cur.fetchone()


    if chat:

        chat_id = chat[0]


    else:

        cur.execute("""
            INSERT INTO chats
                (
                    user1_id,
                    user2_id
                )

            VALUES
                (
                    %s,
                    %s
                )

            RETURNING id
        """, (

            user[0],

            other_user_id

        ))


        chat_id = (
            cur.fetchone()[0]
        )


    conn.commit()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "chat": {

            "id":
                chat_id,

            "user_id":
                other[0],

            "username":
                other[1],

            "display_name":
                other[2]

        }

    })


# =========================================================
# MESSAGES
# =========================================================

@app.route(
    "/api/messages",
    methods=["GET"]
)
def get_messages():

    user = auth_user()


    if not user:
        return auth_error()


    try:

        other_user_id = int(
            request.args.get(
                "user_id"
            )
        )

    except (
        TypeError,
        ValueError
    ):

        return jsonify({

            "success": False,

            "message":
                "Неверный user_id"

        }), 400


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT

            m.id,

            m.sender_id,

            su.username,

            su.display_name,

            m.receiver_id,

            ru.username,

            ru.display_name,

            m.content,

            m.created_at

        FROM messages m

        JOIN users su
            ON su.id = m.sender_id

        JOIN users ru
            ON ru.id = m.receiver_id

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

        ORDER BY
            m.created_at ASC

        LIMIT 500
    """, (

        user[0],

        other_user_id,

        other_user_id,

        user[0]

    ))


    rows = cur.fetchall()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "messages": [

            {

                "id":
                    row[0],

                "sender_id":
                    row[1],

                "sender_username":
                    row[2],

                "sender_display_name":
                    row[3],

                "receiver_id":
                    row[4],

                "receiver_username":
                    row[5],

                "receiver_display_name":
                    row[6],

                "content":
                    row[7],

                "created_at":
                    row[8].isoformat()
                    if row[8]
                    else None

            }

            for row in rows

        ]

    })


@app.route(
    "/api/messages",
    methods=["POST"]
)
def send_message():

    user = auth_user()


    if not user:
        return auth_error()


    data = get_json()


    try:

        receiver_id = int(
            data.get("receiver_id")
        )

    except (
        TypeError,
        ValueError
    ):

        return jsonify({

            "success": False,

            "message":
                "Неверный receiver_id"

        }), 400


    content = str(
        data.get("content")
        or ""
    ).strip()


    if not content:

        return jsonify({

            "success": False,

            "message":
                "Сообщение пустое"

        }), 400


    if len(content) > 5000:

        return jsonify({

            "success": False,

            "message":
                "Сообщение слишком длинное"

        }), 400


    if receiver_id == user[0]:

        return jsonify({

            "success": False,

            "message":
                "Нельзя написать "
                "самому себе"

        }), 400


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT
            id,
            username,
            display_name
        FROM users
        WHERE id = %s
    """, (
        receiver_id,
    ))


    receiver = cur.fetchone()


    if not receiver:

        cur.close()
        conn.close()


        return jsonify({

            "success": False,

            "message":
                "Получатель "
                "не найден"

        }), 404


    # -----------------------------------------------------
    # Находим или создаём чат
    # -----------------------------------------------------

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

        receiver_id,

        receiver_id,

        user[0]

    ))


    chat = cur.fetchone()


    if chat:

        chat_id = chat[0]


    else:

        cur.execute("""
            INSERT INTO chats
                (
                    user1_id,
                    user2_id
                )

            VALUES
                (
                    %s,
                    %s
                )

            RETURNING id
        """, (

            user[0],

            receiver_id

        ))


        chat_id = (
            cur.fetchone()[0]
        )


    # -----------------------------------------------------
    # Сохраняем сообщение
    # -----------------------------------------------------

    cur.execute("""
        INSERT INTO messages
            (
                sender_id,
                receiver_id,
                content
            )

        VALUES
            (
                %s,
                %s,
                %s
            )

        RETURNING
            id,
            created_at
    """, (

        user[0],

        receiver_id,

        content

    ))


    message_id, created_at = (
        cur.fetchone()
    )


    conn.commit()


    cur.close()
    conn.close()


    message = {

        "id":
            message_id,

        "chat_id":
            chat_id,

        "sender_id":
            user[0],

        "sender_username":
            user[1],

        "sender_display_name":
            user[2],

        "receiver_id":
            receiver_id,

        "receiver_username":
            receiver[1],

        "receiver_display_name":
            receiver[2],

        "content":
            content,

        "created_at":
            created_at.isoformat()

    }


    # Отправляем получателю
    socketio.emit(
        "new_message",
        message,
        room=receiver[1]
    )


    # Подтверждение отправителю
    socketio.emit(
        "message_sent",
        message,
        room=user[1]
    )


    return jsonify({

        "success": True,

        "message":
            message

    }), 201


# =========================================================
# MOOD
# =========================================================

@app.route(
    "/api/mood",
    methods=["POST"]
)
def save_mood():

    user = auth_user()


    if not user:
        return auth_error()


    data = get_json()


    mood = str(
        data.get("mood")
        or ""
    ).strip()


    if not mood:

        return jsonify({

            "success": False,

            "message":
                "Укажите настроение"

        }), 400


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        INSERT INTO moods
            (
                user_id,
                mood
            )

        VALUES
            (
                %s,
                %s
            )

        RETURNING
            id,
            created_at
    """, (

        user[0],

        mood

    ))


    row = cur.fetchone()


    conn.commit()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "mood": {

            "id":
                row[0],

            "mood":
                mood,

            "created_at":
                row[1].isoformat()

        }

    })


# =========================================================
# GET MOOD
# =========================================================

@app.route(
    "/api/mood/<username>",
    methods=["GET"]
)
def get_mood(username):

    user = auth_user()


    if not user:
        return auth_error()


    username = normalize(
        username
    )


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT
            m.id,
            m.mood,
            m.created_at

        FROM moods m

        JOIN users u
            ON u.id = m.user_id

        WHERE
            u.username = %s

        ORDER BY
            m.created_at DESC

        LIMIT 100
    """, (
        username,
    ))


    rows = cur.fetchall()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "moods": [

            {

                "id":
                    row[0],

                "mood":
                    row[1],

                "created_at":
                    row[2].isoformat()
                    if row[2]
                    else None

            }

            for row in rows

        ]

    })


# =========================================================
# GRATITUDE
# =========================================================

@app.route(
    "/api/gratitude",
    methods=["POST"]
)
def save_gratitude():

    user = auth_user()


    if not user:
        return auth_error()


    data = get_json()


    content = str(
        data.get("content")
        or ""
    ).strip()


    if not content:

        return jsonify({

            "success": False,

            "message":
                "Введите текст"

        }), 400


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        INSERT INTO gratitude
            (
                user_id,
                content
            )

        VALUES
            (
                %s,
                %s
            )

        RETURNING
            id,
            created_at
    """, (

        user[0],

        content

    ))


    row = cur.fetchone()


    conn.commit()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "gratitude": {

            "id":
                row[0],

            "content":
                content,

            "created_at":
                row[1].isoformat()

        }

    })


# =========================================================
# GET GRATITUDE
# =========================================================

@app.route(
    "/api/gratitude/<username>",
    methods=["GET"]
)
def get_gratitude(username):

    user = auth_user()


    if not user:
        return auth_error()


    username = normalize(
        username
    )


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        SELECT
            g.id,
            g.content,
            g.created_at

        FROM gratitude g

        JOIN users u
            ON u.id = g.user_id

        WHERE
            u.username = %s

        ORDER BY
            g.created_at DESC

        LIMIT 100
    """, (
        username,
    ))


    rows = cur.fetchall()


    cur.close()
    conn.close()


    return jsonify({

        "success": True,

        "gratitude": [

            {

                "id":
                    row[0],

                "content":
                    row[1],

                "created_at":
                    row[2].isoformat()
                    if row[2]
                    else None

            }

            for row in rows

        ]

    })


# =========================================================
# ADMIN
# =========================================================

@app.route(
    "/api/admin/moderator",
    methods=["POST"]
)
def make_moderator():

    user = auth_user()


    if not user:
        return auth_error()


    if user[4] != "admin":

        return jsonify({

            "success": False,

            "message":
                "Недостаточно прав"

        }), 403


    data = get_json()


    try:

        target_id = int(
            data.get("user_id")
        )

    except (
        TypeError,
        ValueError
    ):

        return jsonify({

            "success": False,

            "message":
                "Неверный user_id"

        }), 400


    conn = get_db()
    cur = conn.cursor()


    cur.execute("""
        UPDATE users

        SET role = 'moderator'

        WHERE id = %s

        RETURNING
            id,
            username,
            role
    """, (
        target_id,
    ))


    result = cur.fetchone()


    conn.commit()


    cur.close()
    conn.close()


    if not result:

        return jsonify({

            "success": False,

            "message":
                "Пользователь "
                "не найден"

        }), 404


    return jsonify({

        "success": True,

        "user": {

            "id":
                result[0],

            "username":
                result[1],

            "role":
                result[2]

        }

    })


# =========================================================
# SOCKET.IO
# =========================================================

connected_users = {}


@socketio.on("connect")
def socket_connect(auth):

    try:

        token = None


        if isinstance(
            auth,
            dict
        ):

            token = auth.get(
                "token"
            )


        user = get_user_by_token(
            token
        )


        if not user:

            print(
                "SOCKET: "
                "неверный токен"
            )

            return False


        username = user[1]


        join_room(
            username
        )


        connected_users[
            username
        ] = request.sid


        print(
            f"SOCKET: "
            f"@{username} подключился"
        )


        emit(
            "connected",
            {
                "success":
                    True,

                "username":
                    username
            }
        )


        return True


    except Exception as e:

        print(
            f"SOCKET ERROR: "
            f"{type(e).__name__}: {e}"
        )

        return False


@socketio.on("disconnect")
def socket_disconnect():

    try:

        for (
            username,
            sid
        ) in list(
            connected_users.items()
        ):

            if sid == request.sid:

                del connected_users[
                    username
                ]


                print(
                    f"SOCKET: "
                    f"@{username} "
                    f"отключился"
                )


                break


    except Exception as e:

        print(
            f"SOCKET DISCONNECT ERROR: "
            f"{type(e).__name__}: {e}"
        )


# =========================================================
# START
# =========================================================

try:

    init_db()

except Exception as e:

    print(
        f"DATABASE ERROR: "
        f"{type(e).__name__}: {e}"
    )


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            10000
        )
    )


    socketio.run(

        app,

        host="0.0.0.0",

        port=port

    )

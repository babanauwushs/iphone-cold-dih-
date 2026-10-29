from contextlib import closing
from datetime import date, timedelta
from functools import wraps
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from news_integration import get_latest_news, init_news_database, news_bp

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get(
        "DATABASE_PATH",
        str(Path(app.instance_path) / "users.sqlite3"),
    ),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    TEMPLATES_AUTO_RELOAD=True,
)

if not os.environ.get("FLASK_SECRET_KEY"):
    app.logger.warning(
        "FLASK_SECRET_KEY is unset; sessions will not survive restarts. "
        "Set it to a persistent random secret before deployment."
    )

app.register_blueprint(news_bp)
app.add_url_rule(
    "/admin/news",
    endpoint="admin_news",
    view_func=app.view_functions["news.manage"],
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def initialize_database():
    database_path = Path(app.config["DATABASE"])
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email TEXT,
                phone TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(users)").fetchall()
        }
        if "email" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "phone" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN phone TEXT")
        if "role" not in columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'"
            )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique "
            "ON users(email COLLATE NOCASE) WHERE email IS NOT NULL"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique "
            "ON users(phone) WHERE phone IS NOT NULL"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS programs (
                slug TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                icon TEXT NOT NULL,
                description TEXT NOT NULL,
                skills TEXT NOT NULL,
                image TEXT NOT NULL DEFAULT ''
            )
            """
        )
        program_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(programs)").fetchall()
        }
        if "image" not in program_columns:
            connection.execute(
                "ALTER TABLE programs ADD COLUMN image TEXT NOT NULL DEFAULT ''"
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


initialize_database()
init_news_database(app)


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


@app.before_request
def load_current_user():
    user_id = session.get("user_id")
    g.current_user = (
        get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user_id is not None
        else None
    )


@app.context_processor
def inject_auth_context():
    return {
        "current_user": g.get("current_user"),
        "programs": get_programs(),
        "csrf_token": session.setdefault("csrf_token", secrets.token_urlsafe(32)),
        "current_year": date.today().year,
    }


def validate_csrf():
    submitted_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")
    if not session_token or not hmac.compare_digest(
        submitted_token.encode("utf-8"),
        session_token.encode("utf-8"),
    ):
        abort(400, description="Хүсэлтийн баталгаажуулалт амжилтгүй боллоо.")


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.current_user is None:
            return redirect(url_for("login", next=request.path))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.current_user is None:
            return redirect(url_for("admin_login", next=request.path))
        if g.current_user["role"] != "admin":
            abort(403)
        return view(**kwargs)

    return wrapped_view


def safe_next_url(target):
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("students")


def safe_admin_next_url(target):
    if (
        target
        and target.startswith("/")
        and not target.startswith("//")
        and "\\" not in target
        and (target == "/admin" or target.startswith("/admin/") or target.startswith("/news/"))
    ):
        return target
    return url_for("admin")


def normalize_phone(value):
    compact = re.sub(r"[\s().-]", "", value)
    if compact.startswith("+976"):
        compact = compact[4:]
    elif compact.startswith("976") and len(compact) == 11:
        compact = compact[3:]
    return compact if re.fullmatch(r"[0-9]{8}", compact) else None


def render_home(**context):
    context.setdefault("programs", get_programs())
    context.setdefault("latest_news", get_latest_news())
    context.setdefault("current_year", date.today().year)
    context.setdefault("next_url", url_for("students"))
    context.setdefault("form_data", {})
    return render_template("index.html", **context)


# Нүүр хуудас
@app.route("/")
def index():
    return render_home(next_url=safe_next_url(request.args.get("next", "")))


@app.route("/contact", methods=["POST"])
def contact():
    validate_csrf()
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip()
    message = request.form.get("message", "").strip()
    form_data = {
        "contact_name": name,
        "contact_email": email,
        "contact_phone": phone,
        "contact_message": message,
    }

    if not name or len(name) > 100:
        flash("Нэр 1–100 тэмдэгт байх ёстой.", "error")
    elif (
        len(email) > 254
        or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
    ):
        flash("Зөв имэйл хаяг оруулна уу.", "error")
    elif normalize_phone(phone) is None:
        flash("Утасны дугаар 8 оронтой Монгол дугаар байна уу.", "error")
    elif not message or len(message) > 5000:
        flash("Зурвас 1–5000 тэмдэгт байх ёстой.", "error")
    else:
        get_db().execute(
            """
            INSERT INTO contact_messages (name, email, phone, message)
            VALUES (?, ?, ?, ?)
            """,
            (name, email, normalize_phone(phone), message),
        )
        get_db().commit()
        flash("Таны зурвас амжилттай илгээгдлээ. Баярлалаа.", "success")
        return redirect(url_for("index", _anchor="contact"))

    return render_home(form_data=form_data, contact_open=True)


# Бидний тухай
@app.route("/about")
def about():
    return redirect(url_for("index", _anchor="about"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.current_user is not None:
        return redirect(url_for("students"))

    if request.method == "GET":
        return redirect(url_for("index", _anchor="register"))

    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone_input = request.form.get("phone", "").strip()
        phone = normalize_phone(phone_input)
        password = request.form.get("password", "")
        password_confirmation = request.form.get("password_confirmation", "")

        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            flash(
                "Нэвтрэх нэр 3–32 тэмдэгт байх бөгөөд латин үсэг, тоо, цэг, "
                "зураас ашиглана уу.",
                "error",
            )
        elif (
            len(email) > 254
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
        ):
            flash("Зөв Gmail/имэйл хаяг оруулна уу.", "error")
        elif phone is None:
            flash("Утасны дугаар 8 оронтой Монгол дугаар байна уу.", "error")
        elif len(password) < 10:
            flash("Нууц үг хамгийн багадаа 10 тэмдэгт байна.", "error")
        elif len(password) > 128:
            flash("Нууц үг 128 тэмдэгтээс хэтрэхгүй байна.", "error")
        elif password != password_confirmation:
            flash("Нууц үгийн баталгаажуулалт таарахгүй байна.", "error")
        else:
            identifiers = (username, email, phone)
            existing_user = get_db().execute(
                """
                SELECT 1 FROM users
                WHERE username = ? COLLATE NOCASE
                   OR username = ? COLLATE NOCASE
                   OR username = ? COLLATE NOCASE
                   OR email = ? COLLATE NOCASE
                   OR email = ? COLLATE NOCASE
                   OR email = ? COLLATE NOCASE
                   OR phone = ? OR phone = ? OR phone = ?
                LIMIT 1
                """,
                identifiers + identifiers + identifiers,
            ).fetchone()
            if existing_user is not None:
                flash("Нэвтрэх нэр, имэйл эсвэл утас бүртгэлтэй байна.", "error")
            else:
                try:
                    get_db().execute(
                        "INSERT INTO users (username, email, phone, password_hash) "
                        "VALUES (?, ?, ?, ?)",
                        (username, email, phone, generate_password_hash(password)),
                    )
                    get_db().commit()
                except sqlite3.IntegrityError:
                    get_db().rollback()
                    flash("Нэвтрэх нэр, имэйл эсвэл утас бүртгэлтэй байна.", "error")
                else:
                    flash("Бүртгэл амжилттай. Одоо нэвтэрнэ үү.", "success")
                    return redirect(url_for("login"))

    return render_home(form_data=request.form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.current_user is not None:
        return redirect(url_for("students"))

    if request.method == "GET":
        next_url = safe_next_url(request.args.get("next", ""))
        return redirect(url_for("index", _anchor="login", next=next_url))

    if request.method == "POST":
        validate_csrf()
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            """
            SELECT id, username, password_hash FROM users
            WHERE username = ? COLLATE NOCASE
               OR email = ? COLLATE NOCASE
               OR phone = ?
            """,
            (identifier, identifier.lower(), normalize_phone(identifier)),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Нэвтрэх нэр эсвэл нууц үг буруу байна.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            return redirect(safe_next_url(request.form.get("next", "")))

    return render_home(
        next_url=safe_next_url(request.form.get("next", "")),
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    next_url = safe_admin_next_url(
        request.values.get("next", ""),
    )
    if request.method == "POST":
        validate_csrf()
    if g.current_user is not None and g.current_user["role"] == "admin":
        return redirect(next_url)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            """
            SELECT id, username, password_hash FROM users
            WHERE username = ? COLLATE NOCASE AND role = 'admin'
            """,
            (username,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Админы нэр эсвэл нууц үг буруу байна.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            return redirect(next_url)

    return render_template("admin_login.html", next_url=next_url)


@app.route("/logout", methods=["POST"])
def logout():
    validate_csrf()
    session.clear()
    flash("Та системээс гарлаа.", "success")
    return redirect(url_for("index"))


@app.route("/students")
@login_required
def students():
    return redirect(url_for("index", _anchor="students"))


# Хөтөлбөрийн үндсэн хуудас
@app.route("/hutulbur")
def hutulbur():
    return redirect(url_for("index", _anchor="programs"))


# Хөтөлбөр тус бүрийн мэдээлэл
programs = {
    "ikh-zasag": {
        "name": "Их Засаг Политехник коллеж",
        "icon": "🏫",
        "image": "ikh-zasag-school.png",
        "description": "Их Засаг Политехник коллежийн сургалтын орчин болон мэргэжлийн хөтөлбөрүүдтэй танилцаарай.",
        "skills": [
            "Мэргэжлийн сургалт",
            "Сургалтын хөтөлбөрүүд",
            "Суралцах орчин",
        ],
    },
    "basketball": {
        "name": "Сагсан бөмбөг",
        "icon": "🏀",
        "image": "basketball.png",
        "description": "Сагсан бөмбөгийн үндсэн техник, багийн тоглолтын ур чадвараа хөгжүүлээрэй.",
        "skills": [
            "Бөмбөг эзэмшилт ба дриблинг",
            "Дамжуулалт",
            "Шидэлт",
            "Хамгаалалт",
            "Багийн ажиллагаа",
        ],
    },
    "web-programming": {
        "name": "Вэб програмчлал",
        "icon": "💻",
        "description": "Вэб сайт болон веб систем боловсруулах чиглэлээр мэргэжлийн мэдлэг, ур чадвар эзэмшинэ.",
        "skills": [
            "HTML, CSS",
            "JavaScript",
            "Python",
            "Flask",
            "Өгөгдлийн сан",
            "Вэб сайт хөгжүүлэлт",
        ],
    },
    "graphic-design": {
        "name": "Хэвлэлийн график дизайн",
        "icon": "🎨",
        "description": "Хэвлэлийн болон график дизайны бүтээгдэхүүн боловсруулах, эх бэлтгэх, дизайн хийх ур чадвар эзэмшинэ.",
        "skills": [
            "Adobe Photoshop",
            "Adobe Illustrator",
            "CorelDRAW",
            "InDesign",
            "Лого дизайн",
            "Хэвлэлийн эх бэлтгэл",
        ],
    },
    "hairdressing": {
        "name": "Үсчин",
        "icon": "💇",
        "description": "Үс засалт, хэлбэржүүлэлт, будаг болон гоо сайхны үйлчилгээний мэргэжлийн ур чадвар эзэмшинэ.",
        "skills": [
            "Үс засалт",
            "Үс будах",
            "Үс хэлбэржүүлэх",
            "Үсний арчилгаа",
            "Орчин үеийн үсний технологи",
        ],
    },
    "tourism": {
        "name": "Аялал жуулчлал",
        "icon": "✈️",
        "description": "Аялал жуулчлалын үйлчилгээ, аяллын хөтөлбөр боловсруулах, жуулчдад үйлчилгээ үзүүлэх мэдлэг эзэмшинэ.",
        "skills": [
            "Аяллын хөтөлбөр боловсруулах",
            "Жуулчны үйлчилгээ",
            "Хөтөч тайлбарлагч",
            "Зочлох үйлчилгээ",
            "Аялал жуулчлалын менежмент",
        ],
    },
    "office": {
        "name": "Оффис бичиг хэрэг",
        "icon": "📑",
        "description": "Албан хэрэг хөтлөлт, бичиг баримт боловсруулах, оффисын программ ашиглах ур чадвар эзэмшинэ.",
        "skills": [
            "MS Word",
            "MS Excel",
            "MS PowerPoint",
            "Албан бичиг боловсруулах",
            "Архив, бичиг хэрэг",
            "Оффисын зохион байгуулалт",
        ],
    },
    "beauty": {
        "name": "Гоо засалч",
        "icon": "💄",
        "description": "Гоо сайхны үйлчилгээ, нүүр будалт, арьс арчилгаа болон гоо заслын мэргэжлийн ур чадвар эзэмшинэ.",
        "skills": [
            "Нүүр будалт",
            "Арьс арчилгаа",
            "Гоо сайхны үйлчилгээ",
            "Маникюр",
            "Педикюр",
            "Гоо заслын технологи",
        ],
    },
    "nursing": {
        "name": "Сувилагч",
        "icon": "🩺",
        "description": "Эрүүл мэндийн байгууллагад сувилахуйн тусламж үйлчилгээ үзүүлэх мэргэжлийн мэдлэг, ур чадвар эзэмшинэ.",
        "skills": [
            "Сувилахуйн тусламж",
            "Анхны тусламж",
            "Өвчтөний асаргаа",
            "Эрүүл мэндийн боловсрол",
            "Сувилахуйн ёс зүй",
        ],
    },
    "accounting": {
        "name": "Нярав",
        "icon": "💰",
        "description": "Байгууллагын бараа материал, хөрөнгө, мөнгөн хөрөнгийн бүртгэл, тооцоог хөтлөх мэдлэг эзэмшинэ.",
        "skills": [
            "Анхан шатны бүртгэл",
            "Бараа материалын бүртгэл",
            "Мөнгөн хөрөнгийн бүртгэл",
            "Excel",
            "Санхүүгийн тайлан",
        ],
    },
    "stage-screen": {
        "name": "Тайз дэлгэц",
        "icon": "🎬",
        "description": "Тайз, дэлгэцийн бүтээл, зураг авалт, гэрэлтүүлэг, дуу болон техникийн чиглэлээр мэдлэг эзэмшинэ.",
        "skills": [
            "Камер ашиглалт",
            "Видео зураг авалт",
            "Видео эвлүүлэг",
            "Тайзны зохион байгуулалт",
            "Гэрэлтүүлэг",
            "Дууны техник",
        ],
    },
    "fashion-design": {
        "name": "Хувцас дизайн",
        "icon": "👗",
        "description": "Хувцас загвар зохион бүтээх, эсгүүр хийх, оёх болон дизайны мэргэжлийн ур чадвар эзэмшинэ.",
        "skills": [
            "Хувцас загвар зохион бүтээлт",
            "Эсгүүр",
            "Оёдол",
            "Материал судлал",
            "Fashion illustration",
            "Хувцасны дизайн",
        ],
    },
    "construction": {
        "name": "Барилга",
        "icon": "🏗️",
        "description": "Барилгын технологи, зураг төсөл, барилгын ажил гүйцэтгэх мэргэжлийн мэдлэг, ур чадвар эзэмшинэ.",
        "skills": [
            "Барилгын зураг",
            "Барилгын материал",
            "Барилгын технологи",
            "Хөдөлмөрийн аюулгүй байдал",
            "Барилгын ажлын зохион байгуулалт",
        ],
    }
}


def get_programs():
    rows = get_db().execute(
        "SELECT slug, name, icon, description, skills, image "
        "FROM programs ORDER BY rowid"
    ).fetchall()
    return {
        row["slug"]: {
            "name": row["name"],
            "icon": row["icon"],
            "description": row["description"],
            "skills": json.loads(row["skills"]),
            "image": row["image"],
        }
        for row in rows
    }


def initialize_programs():
    database = get_db()
    for slug, program in programs.items():
        database.execute(
            """
            INSERT OR IGNORE INTO programs
                (slug, name, icon, description, skills, image)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                slug,
                program["name"],
                program["icon"],
                program["description"],
                json.dumps(program["skills"], ensure_ascii=False),
                program.get("image", ""),
            ),
        )
    database.commit()


def initialize_admin():
    configured_username = os.environ.get("FLASK_ADMIN_USERNAME")
    configured_password = os.environ.get("FLASK_ADMIN_PASSWORD")
    using_default_credentials = (
        configured_username is None and configured_password is None
    )
    username = (
        "admin1"
        if using_default_credentials
        else (configured_username or "").strip()
    )
    password = "admin1" if using_default_credentials else (configured_password or "")
    if using_default_credentials:
        app.logger.warning(
            "Using the default admin credentials (admin1/admin1). "
            "Set FLASK_ADMIN_USERNAME and FLASK_ADMIN_PASSWORD before deployment."
        )
    if not username or not password:
        raise RuntimeError(
            "Set both FLASK_ADMIN_USERNAME and FLASK_ADMIN_PASSWORD to configure the admin."
        )
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        raise RuntimeError("FLASK_ADMIN_USERNAME must be 3-32 valid username characters.")
    if len(password) > 128 or (
        not using_default_credentials and len(password) < 12
    ):
        raise RuntimeError("FLASK_ADMIN_PASSWORD must contain 12-128 characters.")

    database = get_db()
    user = database.execute(
        "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
        (username,),
    ).fetchone()
    if user is None:
        database.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (username, generate_password_hash(password)),
        )
    else:
        database.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user["id"],))
    database.commit()


with app.app_context():
    initialize_programs()
    initialize_admin()


@app.route("/hutulbur/<program_slug>")
def program_detail(program_slug):
    if program_slug not in get_programs():
        return "Хөтөлбөр олдсонгүй", 404

    return redirect(url_for("index", _anchor=f"program-{program_slug}"))


@app.route("/admin")
@admin_required
def admin():
    database = get_db()
    users = database.execute(
        "SELECT id, username, email, phone, role, created_at FROM users ORDER BY id"
    ).fetchall()
    statistics = {
        "users": database.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "admins": database.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'"
        ).fetchone()[0],
        "programs": database.execute("SELECT COUNT(*) FROM programs").fetchone()[0],
        "messages": database.execute(
            "SELECT COUNT(*) FROM contact_messages"
        ).fetchone()[0],
    }
    return render_template(
        "admin.html",
        users=users,
        statistics=statistics,
        programs=get_programs(),
    )


@app.route("/admin/messages")
@admin_required
def admin_messages():
    messages = get_db().execute(
        """
        SELECT id, name, email, phone, message, created_at
        FROM contact_messages
        ORDER BY created_at DESC, id DESC
        """
    ).fetchall()
    return render_template("admin_messages.html", messages=messages)


@app.route("/admin/messages/<int:message_id>/delete", methods=["POST"])
@admin_required
def delete_contact_message(message_id):
    validate_csrf()
    cursor = get_db().execute(
        "DELETE FROM contact_messages WHERE id = ?", (message_id,)
    )
    if cursor.rowcount == 0:
        abort(404)
    get_db().commit()
    flash("Холбоо барих зурвас устгагдлаа.", "success")
    return redirect(url_for("admin_messages"))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def update_user_role(user_id):
    validate_csrf()
    role = request.form.get("role", "")
    if role not in {"student", "admin"}:
        abort(400, description="Хэрэглэгчийн эрхийн утга буруу байна.")

    database = get_db()
    target = database.execute(
        "SELECT id, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if target is None:
        abort(404)
    if target["id"] == g.current_user["id"] and role != "admin":
        flash("Та өөрийн админ эрхийг бууруулах боломжгүй.", "error")
    elif target["role"] == "admin" and role != "admin":
        cursor = database.execute(
            """
            UPDATE users SET role = ?
            WHERE id = ? AND (SELECT COUNT(*) FROM users WHERE role = 'admin') > 1
            """,
            (role, user_id),
        )
        if cursor.rowcount == 0:
            flash("Сүүлчийн админы эрхийг бууруулж болохгүй.", "error")
        else:
            database.commit()
            flash("Хэрэглэгчийн эрх шинэчлэгдлээ.", "success")
    else:
        database.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        database.commit()
        flash("Хэрэглэгчийн эрх шинэчлэгдлээ.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    validate_csrf()
    database = get_db()
    target = database.execute(
        "SELECT id, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if target is None:
        abort(404)
    if target["id"] == g.current_user["id"]:
        flash("Та өөрийн бүртгэлийг админ самбараас устгах боломжгүй.", "error")
    elif target["role"] == "admin":
        cursor = database.execute(
            """
            DELETE FROM users
            WHERE id = ? AND (SELECT COUNT(*) FROM users WHERE role = 'admin') > 1
            """,
            (user_id,),
        )
        if cursor.rowcount == 0:
            flash("Сүүлчийн админы бүртгэлийг устгаж болохгүй.", "error")
        else:
            database.commit()
            flash("Хэрэглэгчийн бүртгэл устгагдлаа.", "success")
    else:
        database.execute("DELETE FROM users WHERE id = ?", (user_id,))
        database.commit()
        flash("Хэрэглэгчийн бүртгэл устгагдлаа.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/programs/<slug>", methods=["POST"])
@admin_required
def update_program(slug):
    validate_csrf()
    if slug not in get_programs():
        abort(404)

    name = request.form.get("name", "").strip()
    icon = request.form.get("icon", "").strip()
    description = request.form.get("description", "").strip()
    skills = [
        skill.strip()
        for skill in request.form.get("skills", "").splitlines()
        if skill.strip()
    ]
    if (
        not name
        or len(name) > 100
        or not icon
        or len(icon) > 16
        or not description
        or len(description) > 1000
        or not skills
        or len(skills) > 20
        or any(len(skill) > 100 for skill in skills)
    ):
        flash("Хөтөлбөрийн мэдээллийг шалгана уу.", "error")
        return redirect(url_for("admin"))

    get_db().execute(
        "UPDATE programs SET name = ?, icon = ?, description = ?, skills = ? "
        "WHERE slug = ?",
        (name, icon, description, json.dumps(skills, ensure_ascii=False), slug),
    )
    get_db().commit()
    flash("Хөтөлбөрийн мэдээлэл хадгалагдлаа.", "success")
    return redirect(url_for("admin"))


# ЗАСВАР: _name_ болон _main_-ийг хоёр талдаа давхар доод зураастай болгож засав.
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
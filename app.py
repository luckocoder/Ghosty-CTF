import ast
import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from flags import FLAG1, FLAG2, FLAG3, FLAG4, FLAG5


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "ctf.sqlite3"
UPLOAD_FOLDER = BASE_DIR / "static" / "uploads"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "educational-ctf-secret")
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                bio TEXT NOT NULL
            );
            """
        )
        connection.executemany(
            """
            INSERT OR IGNORE INTO users (id, username, password, bio)
            VALUES (?, ?, ?, ?)
            """,
            [
                (1, "admin", "admin123", f"Administratè sit la. {FLAG3}"),
                (2, "alice", "alice123", "Bonjou, mwen se Alice. Mwen renmen rezoud devinèt."),
                (3, "bob", "bob123", "Bonjou, mwen se Bob. Byenveni nan CTF la."),
            ],
        )


initialize_database()
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)


@app.route("/")
def index():
    challenges = [
        ("Defi 1", "Obsève sit la byen epi chèche enfòmasyon ki disponib.", url_for("robots")),
        ("Defi 2", "Eseye antre nan kont lan.", url_for("login")),
        ("Defi 3", "Eksplore paj pwofil yo.", url_for("profile", user_id=2)),
        ("Defi 4", "Teste zouti dyagnostik rezo a.", url_for("ping")),
        ("Defi 5", "Voye yon fichye epi obsève kijan sit la trete l.", url_for("upload")),
    ]
    return render_template("index.html", challenges=challenges)


@app.route("/robots.txt")
def robots():
    # VULNERABILITY: Public recon files disclose a hidden route and challenge flag.
    return f"User-agent: *\nDisallow: /dev-notes.html\n\n# {FLAG1}\n", 200, {
        "Content-Type": "text/plain; charset=utf-8"
    }


@app.route("/dev-notes.html")
def dev_notes():
    return render_template("dev_notes.html", flag=FLAG1)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABILITY: User input is interpolated directly into the SQL statement.
        query = (
            "SELECT id, username FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        with get_db() as connection:
            user = connection.execute(query).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["sql_injection_succeeded"] = username != user["username"]
            return redirect(url_for("dashboard"))
        flash("Koneksyon an echwe. Verifye enfòmasyon ou yo epi eseye ankò.", "danger")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        username=session["username"],
        flag=FLAG2 if session.get("sql_injection_succeeded") else None,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/profile/<int:user_id>")
def profile(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    with get_db() as connection:
        user = connection.execute(
            "SELECT id, username, bio FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    if user is None:
        return render_template("profile.html", profile=None), 404
    # VULNERABILITY: The requested profile ID is not checked against the logged-in user.
    return render_template("profile.html", profile=user)


def simulate_shell(command):
    """Interpret a small safe subset of shell syntax for the command-injection lesson."""
    output = []
    for part in command.split(";"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("ping "):
            host = part[5:].strip()
            output.append(f"Ping similé pou {host}: yo voye 4 pake, yo resevwa 4.")
        elif part == "cat flag4.txt":
            output.append(FLAG4)
        else:
            output.append(f"[similatè] Kòmand sa a pa disponib: {part}")
    return "\n".join(output) or "[similatè] Ou pa bay okenn kòmand."


@app.route("/ping", methods=["GET", "POST"])
def ping():
    result = None
    if request.method == "POST":
        time.sleep(0.5)
        hostname = request.form.get("hostname", "")
        # VULNERABILITY: Input is passed as shell-like command text without escaping.
        # A constrained simulator handles the input; no operating-system shell is launched.
        result = simulate_shell(f"ping {hostname}")
    return render_template("ping.html", result=result)


def simulate_python_script(source):
    """Run only print statements and the flag-file read used by this exercise."""
    tree = ast.parse(source)
    output = []
    for statement in tree.body:
        if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
            return "[similatè] Se sèlman enstriksyon print senp ki disponib."
        call = statement.value
        if (
            not isinstance(call.func, ast.Name)
            or call.func.id != "print"
            or len(call.args) != 1
            or call.keywords
        ):
            return "[similatè] Se sèlman enstriksyon print senp ki disponib."

        value = call.args[0]
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            output.append(value.value)
            continue

        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "read"
            and not value.args
            and not value.keywords
            and isinstance(value.func.value, ast.Call)
            and isinstance(value.func.value.func, ast.Name)
            and value.func.value.func.id == "open"
            and len(value.func.value.args) == 1
            and not value.func.value.keywords
            and isinstance(value.func.value.args[0], ast.Constant)
            and value.func.value.args[0].value == "flag5.txt"
        ):
            output.append(FLAG5)
            continue

        return "[similatè] Ekspresyon Python sa a pa disponib."
    return "\n".join(output) or "[similatè] Script la fini san li pa bay rezilta."


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        uploaded_file = request.files.get("file")
        if uploaded_file is None or not uploaded_file.filename:
            flash("Chwazi yon fichye pou voye.", "warning")
            return redirect(url_for("upload"))
        filename = secure_filename(uploaded_file.filename)
        if not filename:
            flash("Non fichye sa a pa ka sèvi.", "danger")
            return redirect(url_for("upload"))
        uploaded_file.save(UPLOAD_FOLDER / filename)
        flash(f"Fichye {filename} la voye.", "success")
        return redirect(url_for("upload"))
    files = sorted(path.name for path in UPLOAD_FOLDER.iterdir() if path.is_file())
    return render_template("upload.html", files=files, result=None)


@app.route("/run-upload")
def run_upload():
    requested_file = request.args.get("file", "")
    filename = secure_filename(requested_file)
    file_path = UPLOAD_FOLDER / filename
    if not filename or not file_path.is_file():
        flash("Nou pa jwenn fichye ou te voye a.", "danger")
        return redirect(url_for("upload"))

    # VULNERABILITY: Uploaded files are offered to a code-execution endpoint without
    # validating their extension or contents. Execution is simulated, not eval/exec.
    try:
        source = file_path.read_text(encoding="utf-8")
        result = simulate_python_script(source)
    except (SyntaxError, UnicodeDecodeError):
        result = "[similatè] Nou pa t kapab li fichye sa a."
    files = sorted(path.name for path in UPLOAD_FOLDER.iterdir() if path.is_file())
    return render_template("upload.html", files=files, result=result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))

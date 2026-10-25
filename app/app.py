"""MiniShop : application FastAPI VOLONTAIREMENT VULNÉRABLE (support du TP Cours 7).

Ne jamais déployer ce code tel quel. Votre mission : le rendre conforme.
Documentation interactive : http://localhost:5000/docs
"""
import hashlib
import html
import os
import random
import sqlite3
import subprocess
from urllib.parse import urlparse
import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import HTTPException
import requests
import uvicorn
import yaml
from fastapi import Body, FastAPI, Request, Depends
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from ipaddress import IPv4Address
from starlette.middleware.sessions import SessionMiddleware
import ast
from pydantic import BaseModel
from pathlib import Path
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ph = PasswordHasher()
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("minishop")
SECRET_KEY = os.environ["SECRET_KEY"]
is_production = os.getenv("IS_PRODUCTION", "").lower() in ("true", "1")
app = FastAPI(title="MiniShop",
              debug=False,
              docs_url=None if is_production else "/docs",
              redoc_url=None if is_production else "/redoc",
              openapi_url=None if is_production else "/openapi.json",
              )
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True, same_site="lax")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
ROLE_PERMS = {
    "user": {"invoice:read"},
    "admin": {"invoice:read", "user:read", "user:delete"},
}


def current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="login required")
    row = db().execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="user not found")
    return {
        "id": row["id"],
        "username": row["username"],
        "role": "admin" if row["is_admin"] == 1 else "user",
    }


def require(perm: str):
    def checker(user=Depends(current_user)):
        role = user.get("role", "user")
        if perm not in ROLE_PERMS.get(role, set()):
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return checker


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def md5(value):
    return hashlib.md5(value.encode()).hexdigest()


def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users
        (
            id       INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE products
        (
            id    INTEGER PRIMARY KEY,
            name  TEXT,
            price REAL
        );
        CREATE TABLE invoices
        (
            id       INTEGER PRIMARY KEY,
            owner_id INTEGER,
            label    TEXT,
            amount   REAL
        );
        """
    )
    conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                 ("admin", ph.hash("admin123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", ph.hash("alice123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", ph.hash("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()


@app.exception_handler(Exception)
async def handle_error(request: Request, exc: Exception):
    log.exception(f"exception has occur : {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, data: dict = Body(...)):
    username, password = data["username"], data["password"]
    log.info(f"login attempt user={username}")
    sql = f"SELECT id, username, password FROM users WHERE username = ?"
    row = db().execute(sql, (username,)).fetchone()
    if not row:
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    else:
        try:
            ph.verify(row["password"], password)
        except VerificationError:
            return JSONResponse({"error": "bad credentials"}, status_code=401)
    request.session["user_id"] = row["id"]
    request.session["token"] = str(random.randint(0, 10 ** 6))
    return {"status": "logged in", "user": row["username"]}


@app.get("/search")
def search(q: str = ""):
    sql = f"SELECT id, name, price FROM products WHERE name LIKE ?"
    return [dict(r) for r in db().execute(sql, (f"%{q}%",)).fetchall()]


@app.get("/ping")
def ping(host: IPv4Address = IPv4Address("127.0.0.1")):
    com = ["ping", "-c", "1", str(host)]
    try:
        out = subprocess.run(com, capture_output=True, text=True, timeout=5)
        return PlainTextResponse(out.stdout + out.stderr)
    except subprocess.TimeoutExpired:
        return PlainTextResponse("Timeout expired", status_code=504)


@app.get("/hello")
def hello(name: str = ""):
    return HTMLResponse(html.escape(f"<h1>Bonjour {name}</h1>"))


@app.get("/files/{name:path}")
def get_file(name: str):
    base_path = Path(UPLOAD_DIR).resolve()
    target_path = (base_path / name).resolve()
    is_relative_to = target_path.is_relative_to(base_path)
    if not is_relative_to:
        raise HTTPException(status_code=403, detail="Not a relative path")
    if not target_path.is_file():
        raise HTTPException(status_code=404, detail="Not found")

    return FileResponse(os.path.join(UPLOAD_DIR, name))


@app.post("/calc")
def calc(data: dict = Body(...)):
    try:
        calc_result = ast.literal_eval(data.get("expr", ""))
        return {"result": str(calc_result)}
    except (ValueError, SyntaxError):
        raise HTTPException(status_code=400, detail='Invalid expression')


@app.post("/import-yaml")
async def import_yaml(request: Request):
    try:
        cfg = yaml.safe_load(await request.body())
        return {"keys": list(cfg.keys()) if isinstance(cfg, dict) else str(type(cfg))}
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class Profile(BaseModel):
    name: str
    bio: str


@app.post("/import-profile")
async def import_profile(profile: Profile):
    return {"profile": profile.dict()}


@app.get("/fetch")
def fetch(url: str):
    u = urlparse(url)
    if u.scheme != "https":
        raise HTTPException(status_code=400)
    r = requests.get(url, verify=True, timeout=5, allow_redirects=False)
    return PlainTextResponse(r.text[:500])


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, user=Depends(require("invoice:read"))):
    row = db().execute(
        "SELECT * FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, user["id"])
    ).fetchone()
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    return dict(row)


@app.get("/admin/users")
def admin_users(user=Depends(require("user:read"))):
    rows = db().execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.delete("/users/{user_id}")
def delete_user(user_id: int, user=Depends(require("user:delete"))):
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"deleted": user_id}


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()

    uvicorn.run("app:app", host="127.0.0.1", port=5000, reload=False)

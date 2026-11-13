"""
App VULNERAVEL — linha de base do experimento (o "antes").

ATENCAO: este codigo contem falhas de seguranca PROPOSITAIS. Serve apenas
como alvo controlado de laboratorio para demonstrar o impacto dos controles
aplicados na versao segura. NAO use nada disto em producao.

Falhas propositais (mapeadas aos controles que faltam):
  - IA-5     : senha guardada como MD5 (praticamente texto plano).
  - IA-5(1)  : sem politica de senha (aceita "123456", "password", etc.).
  - IA-2(1)  : sem MFA.
  - AC-7     : sem limite de tentativas / lockout (brute force livre).
  - AU-2/6   : sem log de eventos de autenticacao.
  - SC-23    : sessao fraca (cookie sem HttpOnly/Secure/SameSite, sem timeout,
               sem regeneracao de ID no login).
"""
import hashlib
import os
import sqlite3

from flask import (Flask, g, redirect, render_template, request, session,
                   url_for)

DB_PATH = os.environ.get("DB_PATH", "/data/vuln.db")

app = Flask(__name__)
# Falha SC-23: chave de sessao fixa e previsivel, cookies sem flags de seguranca.
app.secret_key = "chave-fraca-123"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """CREATE TABLE IF NOT EXISTS usuarios (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               usuario TEXT UNIQUE NOT NULL,
               senha_md5 TEXT NOT NULL
           )"""
    )
    # Usuario de teste usado pelos scripts de ataque do laboratorio.
    cur = db.execute("SELECT 1 FROM usuarios WHERE usuario = ?", ("alvo",))
    if cur.fetchone() is None:
        db.execute(
            "INSERT INTO usuarios (usuario, senha_md5) VALUES (?, ?)",
            ("alvo", hashlib.md5("senha123".encode()).hexdigest()),
        )
    db.commit()
    db.close()


@app.route("/")
def index():
    if session.get("usuario"):
        return render_template("dashboard.html", usuario=session["usuario"])
    return redirect(url_for("login"))


@app.route("/registrar", methods=["GET", "POST"])
def registrar():
    erro = None
    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        senha = request.form.get("senha", "")
        # Falha IA-5(1): nenhuma validacao de politica de senha.
        try:
            db = get_db()
            db.execute(
                "INSERT INTO usuarios (usuario, senha_md5) VALUES (?, ?)",
                (usuario, hashlib.md5(senha.encode()).hexdigest()),
            )
            db.commit()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            erro = "Usuario ja existe."
    return render_template("registrar.html", erro=erro)


@app.route("/login", methods=["GET", "POST"])
def login():
    erro = None
    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        senha = request.form.get("senha", "")
        db = get_db()
        row = db.execute(
            "SELECT * FROM usuarios WHERE usuario = ?", (usuario,)
        ).fetchone()
        # Falha IA-5: comparacao de hash MD5 (reversivel por rainbow table).
        # Falha AC-7: sem contador de tentativas; brute force ilimitado.
        # Falha AU-2/6: sucesso e falha nao sao registrados em lugar nenhum.
        if row and row["senha_md5"] == hashlib.md5(senha.encode()).hexdigest():
            # Falha SC-23: sem session.clear()/regeneracao do ID de sessao.
            session["usuario"] = usuario
            return redirect(url_for("index"))
        erro = "Usuario ou senha invalidos."
    return render_template("login.html", erro=erro)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# Falha SC-23: sem HttpOnly, sem Secure, sem SameSite, sem timeout de inatividade.
# (os defaults do Flask para cookie sao mantidos de proposito frouxos aqui)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)

"""
App SEGURA — seis controles de autenticacao (C1..C6) conforme o Apendice A
do relatorio. Sessao no lado do servidor (SC-23), MFA TOTP com anti-replay
(IA-2(8)), bloqueio com recuo exponencial (AC-7) e log estruturado (AU-2/6).
"""
import os
import secrets
import sqlite3
import time
from datetime import timedelta

from flask import (Flask, g, redirect, render_template, request, session,
                   url_for)

import controles as C

DB_PATH = os.environ.get("DB_PATH", "/data/segura.db")
INATIVIDADE_SEG = int(os.environ.get("TIMEOUT_INATIVIDADE", "900"))     # 15 min
ABSOLUTA_SEG = int(os.environ.get("TIMEOUT_ABSOLUTO", "28800"))         # 8 h
PRE_AUTH_SEG = int(os.environ.get("PRE_AUTH_SEG", "300"))               # 5 min


# ---------------------------------------------------------------------------
# Banco de dados
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(g.db_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db(db_path: str):
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    db = sqlite3.connect(db_path)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            totp_segredo TEXT,
            mfa_ativado INTEGER NOT NULL DEFAULT 0,
            totp_ultimo_passo INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS tentativas (
            usuario TEXT PRIMARY KEY,
            falhas INTEGER NOT NULL DEFAULT 0,
            nivel INTEGER NOT NULL DEFAULT 0,
            bloqueado_ate REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessoes (
            sid TEXT PRIMARY KEY,
            uid INTEGER,
            usuario TEXT,
            criada_em REAL NOT NULL,
            ultimo_acesso REAL NOT NULL,
            nivel TEXT NOT NULL DEFAULT 'pre_auth',
            autenticado INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    db.commit()
    db.close()


def _ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "-")


def _ua() -> str:
    return request.headers.get("User-Agent", "")


# ---------------------------------------------------------------------------
# Sessao no lado do servidor (SC-23)
# ---------------------------------------------------------------------------
def _remover_sessao(db, sid):
    if sid:
        db.execute("DELETE FROM sessoes WHERE sid = ?", (sid,))
        db.commit()


def nova_sessao(db, uid, usuario, autenticado, nivel):
    """SC-23(3): gera novo sid (256 bits); remove o anterior (anti-fixacao)."""
    _remover_sessao(db, session.get("sid"))
    sid = secrets.token_urlsafe(32)
    agora = time.time()
    db.execute("INSERT INTO sessoes (sid, uid, usuario, criada_em, "
               "ultimo_acesso, nivel, autenticado) VALUES (?,?,?,?,?,?,?)",
               (sid, uid, usuario, agora, agora, nivel, 1 if autenticado else 0))
    db.commit()
    session.clear()
    session["sid"] = sid
    session.permanent = True
    return sid


def sessao_atual(db):
    sid = session.get("sid")
    if not sid:
        return None
    return db.execute("SELECT * FROM sessoes WHERE sid = ?", (sid,)).fetchone()


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def criar_app(config: dict = None) -> Flask:
    app = Flask(__name__)
    config = config or {}
    db_path = config.get("DB_PATH", DB_PATH)

    app.config.update(
        SECRET_KEY=config.get("SECRET_KEY",
                              os.environ.get("SECRET_KEY") or secrets.token_hex(32)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config.get(
            "SESSION_COOKIE_SECURE",
            os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"),
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=INATIVIDADE_SEG),
        SESSION_REFRESH_EACH_REQUEST=True,
    )
    app.config["DB_PATH"] = db_path
    init_db(db_path)

    @app.before_request
    def _carregar_contexto():
        g.db_path = app.config["DB_PATH"]
        db = get_db()
        s = sessao_atual(db)
        g.sessao = s
        if s is not None:
            agora = time.time()
            inativo = agora - s["ultimo_acesso"] > INATIVIDADE_SEG
            expirado = agora - s["criada_em"] > ABSOLUTA_SEG
            if inativo or expirado:
                _remover_sessao(db, s["sid"])
                C.registrar_evento("SESSAO_EXPIRADA", s["usuario"], _ip(), _ua(),
                                   "inatividade" if inativo else "absoluta")
                session.clear()
                g.sessao = None
            else:
                db.execute("UPDATE sessoes SET ultimo_acesso = ? WHERE sid = ?",
                           (agora, s["sid"]))
                db.commit()

    @app.teardown_appcontext
    def _fechar_db(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def autenticado():
        return g.get("sessao") is not None and g.sessao["autenticado"] == 1

    def erro(template, status=200, **ctx):
        return render_template(template, **ctx), status

    # -----------------------------------------------------------------------
    @app.route("/")
    def index():
        return redirect(url_for("painel") if autenticado() else url_for("login"))

    @app.route("/registro", methods=["GET", "POST"])
    def registro():
        erro_msg = None
        if request.method == "POST":
            usuario = request.form.get("usuario", "").strip()
            senha = request.form.get("senha", "")
            ok, msg = C.validar_politica_senha(senha, usuario)
            if not usuario:
                erro_msg = "Informe um nome de usuario."
            elif not ok:
                C.registrar_evento("SENHA_REJEITADA_POLITICA", usuario, _ip(), _ua())
                erro_msg = msg
            else:
                try:
                    db = get_db()
                    segredo = C.gerar_segredo_totp()
                    db.execute(
                        "INSERT INTO usuarios (usuario, senha_hash, totp_segredo, "
                        "mfa_ativado) VALUES (?, ?, ?, 0)",
                        (usuario, C.hash_senha(senha), C.cifrar_segredo(segredo)))
                    db.commit()
                    C.registrar_evento("CADASTRO", usuario, _ip(), _ua())
                    session["cadastro_usuario"] = usuario
                    return redirect(url_for("mfa_cadastro"))
                except sqlite3.IntegrityError:
                    erro_msg = "Usuario ja existe."
        return erro("registro.html", 200 if request.method == "GET" else
                    (200 if erro_msg is None else 400), erro=erro_msg)

    @app.route("/mfa/cadastro", methods=["GET", "POST"])
    def mfa_cadastro():
        usuario = session.get("cadastro_usuario")
        if not usuario:
            return redirect(url_for("login"))
        db = get_db()
        row = db.execute("SELECT totp_segredo FROM usuarios WHERE usuario = ?",
                         (usuario,)).fetchone()
        segredo = C.decifrar_segredo(row["totp_segredo"]) if row else ""
        if request.method == "POST":
            if C.verificar_totp(segredo, request.form.get("codigo", "")):
                db.execute("UPDATE usuarios SET mfa_ativado = 1 WHERE usuario = ?",
                           (usuario,))
                db.commit()
                C.registrar_evento("MFA_ATIVADO", usuario, _ip(), _ua())
                session.pop("cadastro_usuario", None)
                return redirect(url_for("login"))
            qr = C.gerar_qr_base64(usuario, segredo)
            return erro("mfa_setup.html", 400, qr=qr, segredo=segredo,
                        erro="Codigo invalido. Tente novamente.")
        qr = C.gerar_qr_base64(usuario, segredo)
        return render_template("mfa_setup.html", qr=qr, segredo=segredo, erro=None)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            usuario = request.form.get("usuario", "").strip()
            senha = request.form.get("senha", "")
            db = get_db()

            # AC-7: bloqueio tem prioridade; a senha NAO e avaliada (HTTP 429).
            bloqueado, restante = C.esta_bloqueado(db, usuario)
            if bloqueado:
                C.registrar_evento("LOGIN_BLOQUEADO", usuario, _ip(), _ua(),
                                   f"ate={restante}s")
                return erro("login.html", 429,
                            erro=f"Conta bloqueada. Tente em {restante} s.")

            row = db.execute("SELECT * FROM usuarios WHERE usuario = ?",
                             (usuario,)).fetchone()
            hash_arm = row["senha_hash"] if row else None
            # IA-5: verificacao em tempo constante mesmo se o usuario nao existe.
            if row and C.verificar_usuario(hash_arm, senha):
                # IA-5 re-hash transparente se os parametros mudaram.
                if C.precisa_rehash(hash_arm):
                    db.execute("UPDATE usuarios SET senha_hash = ? WHERE id = ?",
                               (C.hash_senha(senha), row["id"]))
                    db.commit()
                C.registrar_evento("LOGIN_SENHA_OK", usuario, _ip(), _ua())
                if row["mfa_ativado"]:
                    nova_sessao(db, row["id"], usuario, autenticado=False,
                                nivel="pre_auth")
                    return redirect(url_for("mfa"))
                C.resetar_tentativas(db, usuario)
                nova_sessao(db, row["id"], usuario, autenticado=True, nivel="auth")
                C.registrar_evento("LOGIN_SUCESSO", usuario, _ip(), _ua(), "sem mfa")
                return redirect(url_for("painel"))

            # Falha: conta para o bloqueio (REQ-AC7-06 vale p/ inexistente).
            _verificar_dummy_se_inexistente(row, senha)
            falhas, bloqueio = C.registrar_falha(db, usuario)
            C.registrar_evento("LOGIN_FALHA", usuario, _ip(), _ua(),
                               f"falhas={falhas}")
            if bloqueio:
                C.registrar_evento("LOCKOUT_ACIONADO", usuario, _ip(), _ua(),
                                   f"bloqueio={bloqueio}s")
            return erro("login.html", 401, erro="Usuario ou senha invalidos.")
        return render_template("login.html", erro=None)

    @app.route("/mfa", methods=["GET", "POST"])
    def mfa():
        s = g.get("sessao")
        if s is None or s["nivel"] != "pre_auth":
            return redirect(url_for("login"))
        db = get_db()
        # REQ-IA2-05: estado pre-autenticado expira em 5 min.
        if time.time() - s["criada_em"] > PRE_AUTH_SEG:
            _remover_sessao(db, s["sid"])
            session.clear()
            return redirect(url_for("login"))
        usuario = s["usuario"]
        if request.method == "POST":
            row = db.execute("SELECT * FROM usuarios WHERE usuario = ?",
                             (usuario,)).fetchone()
            segredo = C.decifrar_segredo(row["totp_segredo"])
            codigo = request.form.get("codigo", "")
            passo = C.passo_totp()
            valido = C.verificar_totp(segredo, codigo)
            # IA-2(8): rejeita codigo cujo passo <= ultimo aceito (anti-replay).
            if valido and passo > row["totp_ultimo_passo"]:
                db.execute("UPDATE usuarios SET totp_ultimo_passo = ? WHERE id = ?",
                           (passo, row["id"]))
                db.commit()
                C.resetar_tentativas(db, usuario)
                nova_sessao(db, row["id"], usuario, autenticado=True, nivel="auth")
                C.registrar_evento("LOGIN_SUCESSO", usuario, _ip(), _ua(), "com mfa")
                return redirect(url_for("painel"))
            # Falha de MFA conta para o mesmo bloqueio (REQ-IA2-07).
            falhas, bloqueio = C.registrar_falha(db, usuario)
            C.registrar_evento("MFA_FALHA", usuario, _ip(), _ua(), f"falhas={falhas}")
            if bloqueio:
                C.registrar_evento("LOCKOUT_ACIONADO", usuario, _ip(), _ua(),
                                   f"bloqueio={bloqueio}s")
            return erro("mfa.html", 401, erro="Codigo MFA invalido.")
        return render_template("mfa.html", erro=None)

    @app.route("/painel")
    def painel():
        if not autenticado():
            return redirect(url_for("login"))
        return render_template("dashboard.html", usuario=g.sessao["usuario"])

    @app.route("/logout")
    def logout():
        db = get_db()
        s = g.get("sessao")
        usuario = s["usuario"] if s else "-"
        _remover_sessao(db, session.get("sid"))   # SC-23(1): invalida no servidor
        session.clear()
        C.registrar_evento("LOGOUT", usuario, _ip(), _ua())
        return redirect(url_for("login"))

    return app


def _verificar_dummy_se_inexistente(row, senha):
    """Garante uma verificacao Argon2 mesmo quando o usuario nao existe."""
    if row is None:
        C.verificar_usuario(None, senha)


app = criar_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

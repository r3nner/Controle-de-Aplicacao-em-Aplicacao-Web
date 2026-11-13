"""
App SEGURA — mesma funcionalidade da versao vulneravel, mas com os seis
controles de autenticacao aplicados (IA-5, IA-5(1), IA-2(1), AC-7,
AU-2/AU-6, SC-23). Veja controles.py para o detalhe de cada um.
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

# SC-23: timeout de inatividade (segundos). 15 min por padrao.
TIMEOUT_INATIVIDADE = int(os.environ.get("TIMEOUT_INATIVIDADE", "900"))


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
    db.execute(
        """CREATE TABLE IF NOT EXISTS usuarios (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               usuario TEXT UNIQUE NOT NULL,
               senha_hash TEXT NOT NULL,
               totp_segredo TEXT,
               mfa_ativado INTEGER NOT NULL DEFAULT 0
           )"""
    )
    db.execute(
        """CREATE TABLE IF NOT EXISTS tentativas (
               usuario TEXT PRIMARY KEY,
               falhas INTEGER NOT NULL DEFAULT 0,
               nivel INTEGER NOT NULL DEFAULT 0,
               bloqueado_ate REAL NOT NULL DEFAULT 0
           )"""
    )
    db.commit()
    db.close()


def _ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "-")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def criar_app(config: dict = None) -> Flask:
    app = Flask(__name__)
    config = config or {}
    db_path = config.get("DB_PATH", DB_PATH)

    app.config.update(
        # SC-23: chave de assinatura forte e aleatoria (nao previsivel).
        SECRET_KEY=config.get("SECRET_KEY", secrets.token_hex(32)),
        # SC-23: endurecimento do cookie de sessao.
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config.get(
            "SESSION_COOKIE_SECURE",
            os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
        ),
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=TIMEOUT_INATIVIDADE),
    )
    app.config["DB_PATH"] = db_path
    init_db(db_path)

    @app.before_request
    def _carregar_contexto():
        g.db_path = app.config["DB_PATH"]
        # SC-23: timeout de inatividade com renovacao a cada requisicao.
        if session.get("usuario"):
            agora = time.time()
            ultima = session.get("ultima_atividade", agora)
            if agora - ultima > TIMEOUT_INATIVIDADE:
                usuario = session.get("usuario")
                session.clear()
                C.registrar_evento("SESSAO_EXPIRADA", usuario, _ip(),
                                   "timeout de inatividade")
                return redirect(url_for("login"))
            session["ultima_atividade"] = agora
            session.permanent = True

    @app.teardown_appcontext
    def _fechar_db(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def _regenerar_sessao(usuario: str):
        """SC-23: anti-fixacao — descarta a sessao antiga e cria um ID novo."""
        session.clear()
        session["sid"] = secrets.token_hex(16)   # identificador rotacionado
        session["usuario"] = usuario
        session["ultima_atividade"] = time.time()
        session.permanent = True

    # -----------------------------------------------------------------------
    @app.route("/")
    def index():
        if session.get("usuario"):
            return render_template("dashboard.html", usuario=session["usuario"])
        return redirect(url_for("login"))

    @app.route("/registrar", methods=["GET", "POST"])
    def registrar():
        erro = None
        if request.method == "POST":
            usuario = request.form.get("usuario", "").strip()
            senha = request.form.get("senha", "")
            if not usuario:
                erro = "Informe um nome de usuario."
            else:
                # IA-5(1): valida a politica de senha antes de aceitar.
                ok, msg = C.validar_politica_senha(senha)
                if not ok:
                    erro = msg
                else:
                    try:
                        db = get_db()
                        # IA-5: armazena hash Argon2id, nunca a senha.
                        db.execute(
                            "INSERT INTO usuarios (usuario, senha_hash) "
                            "VALUES (?, ?)",
                            (usuario, C.hash_senha(senha)),
                        )
                        db.commit()
                        C.registrar_evento("REGISTRO", usuario, _ip())
                        # Encaminha para ativar o MFA (IA-2(1)).
                        session["pre_mfa_setup"] = usuario
                        return redirect(url_for("configurar_mfa"))
                    except sqlite3.IntegrityError:
                        erro = "Usuario ja existe."
        return render_template("registrar.html", erro=erro)

    @app.route("/mfa/configurar", methods=["GET", "POST"])
    def configurar_mfa():
        usuario = session.get("pre_mfa_setup")
        if not usuario:
            return redirect(url_for("login"))
        db = get_db()

        if request.method == "GET":
            # Gera e guarda provisoriamente um segredo TOTP para este usuario.
            segredo = C.gerar_segredo_totp()
            session["totp_segredo_tmp"] = segredo
            qr = C.gerar_qr_base64(usuario, segredo)
            return render_template("mfa_setup.html", qr=qr, segredo=segredo,
                                   erro=None)

        # POST: confirma que o usuario conseguiu gerar um codigo valido.
        segredo = session.get("totp_segredo_tmp")
        codigo = request.form.get("codigo", "")
        if C.verificar_totp(segredo, codigo):
            db.execute(
                "UPDATE usuarios SET totp_segredo = ?, mfa_ativado = 1 "
                "WHERE usuario = ?",
                (segredo, usuario),
            )
            db.commit()
            C.registrar_evento("MFA_ATIVADO", usuario, _ip())
            session.pop("totp_segredo_tmp", None)
            session.pop("pre_mfa_setup", None)
            return redirect(url_for("login"))
        qr = C.gerar_qr_base64(usuario, segredo)
        return render_template("mfa_setup.html", qr=qr, segredo=segredo,
                               erro="Codigo invalido. Tente novamente.")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        erro = None
        if request.method == "POST":
            usuario = request.form.get("usuario", "").strip()
            senha = request.form.get("senha", "")
            db = get_db()

            # AC-7: se o usuario estiver bloqueado, recusa sem checar a senha.
            bloqueado, restante = C.esta_bloqueado(db, usuario)
            if bloqueado:
                C.registrar_evento("LOCKOUT_BLOQUEADO", usuario, _ip(),
                                   f"faltam {restante}s")
                erro = (f"Conta temporariamente bloqueada. "
                        f"Tente novamente em {restante} segundos.")
                return render_template("login.html", erro=erro)

            row = db.execute(
                "SELECT * FROM usuarios WHERE usuario = ?", (usuario,)
            ).fetchone()

            # IA-5: verificacao do hash Argon2id.
            if row and C.verificar_senha(row["senha_hash"], senha):
                C.resetar_tentativas(db, usuario)
                if row["mfa_ativado"]:
                    # IA-2(1): senha correta nao basta — exige 2o fator.
                    session["pre_mfa"] = usuario
                    return redirect(url_for("verificar_mfa"))
                _regenerar_sessao(usuario)
                C.registrar_evento("LOGIN_SUCESSO", usuario, _ip(),
                                   "sem mfa")
                return redirect(url_for("index"))

            # Falha de autenticacao: contabiliza (AC-7) e registra (AU-2).
            falhas, bloqueio = C.registrar_falha(db, usuario)
            C.registrar_evento("LOGIN_FALHA", usuario, _ip(),
                               f"falhas={falhas}")
            if bloqueio:
                C.registrar_evento("LOCKOUT_ACIONADO", usuario, _ip(),
                                   f"bloqueio={bloqueio}s")
                erro = (f"Muitas tentativas. Conta bloqueada por "
                        f"{bloqueio} segundos.")
            else:
                erro = "Usuario ou senha invalidos."
        return render_template("login.html", erro=erro)

    @app.route("/mfa", methods=["GET", "POST"])
    def verificar_mfa():
        usuario = session.get("pre_mfa")
        if not usuario:
            return redirect(url_for("login"))
        if request.method == "POST":
            db = get_db()
            row = db.execute(
                "SELECT totp_segredo FROM usuarios WHERE usuario = ?",
                (usuario,),
            ).fetchone()
            codigo = request.form.get("codigo", "")
            # IA-2(1): valida o segundo fator (TOTP).
            if row and C.verificar_totp(row["totp_segredo"], codigo):
                session.pop("pre_mfa", None)
                _regenerar_sessao(usuario)
                C.registrar_evento("LOGIN_SUCESSO", usuario, _ip(),
                                   "com mfa")
                return redirect(url_for("index"))
            C.registrar_evento("MFA_FALHA", usuario, _ip())
            return render_template("mfa.html", erro="Codigo MFA invalido.")
        return render_template("mfa.html", erro=None)

    @app.route("/logout")
    def logout():
        usuario = session.get("usuario", "-")
        session.clear()
        C.registrar_evento("LOGOUT", usuario, _ip())
        return redirect(url_for("login"))

    return app


app = criar_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

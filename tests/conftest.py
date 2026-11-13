"""
Fixtures compartilhadas do pytest.

Coloca app_segura/ no sys.path, cria um banco SQLite temporario por teste e
redireciona o log de seguranca para um arquivo temporario, de modo que cada
teste rode isolado e sem sujar artefatos reais.
"""
import os
import sqlite3
import sys

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "app_segura"))

# Evita que o `app = criar_app()` de nivel de modulo toque /data no host.
import tempfile  # noqa: E402
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(),
                                              "_import_segura.db"))
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")

import controles as C          # noqa: E402
import app as app_modulo       # noqa: E402


@pytest.fixture
def log_tmp(tmp_path, monkeypatch):
    caminho = str(tmp_path / "seguranca.log")
    monkeypatch.setattr(C, "ARQUIVO_LOG", caminho)
    return caminho


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "teste.db")


@pytest.fixture
def app(db_path, log_tmp):
    aplicacao = app_modulo.criar_app({
        "DB_PATH": db_path,
        "SECRET_KEY": "chave-fixa-de-teste",
        "SESSION_COOKIE_SECURE": True,   # força postura de producao para o teste
    })
    aplicacao.config["TESTING"] = True
    return aplicacao


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def conn(db_path, app):
    """Conexao direta ao banco (app ja criou as tabelas)."""
    c = sqlite3.connect(db_path)
    c.row_factory = sqlite3.Row
    yield c
    c.close()


def criar_usuario(db_path, usuario, senha, mfa=False, segredo=None):
    """Insere um usuario direto no banco para montar cenarios de teste."""
    c = sqlite3.connect(db_path)
    c.execute(
        "INSERT INTO usuarios (usuario, senha_hash, totp_segredo, mfa_ativado) "
        "VALUES (?, ?, ?, ?)",
        (usuario, C.hash_senha(senha), segredo, 1 if mfa else 0),
    )
    c.commit()
    c.close()

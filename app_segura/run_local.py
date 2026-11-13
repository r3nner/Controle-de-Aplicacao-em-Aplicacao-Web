"""
Execucao LOCAL sem Docker (versao segura), na porta 5001.

    python run_local.py

Cria o banco em app_segura/data/segura.db, semeia o usuario 'alvo'
(senha forte + MFA) e sobe o servidor. Cookie Secure desabilitado para
o laboratorio em HTTP (em producao: true + HTTPS).
"""
import os

AQUI = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("DB_PATH", os.path.join(AQUI, "data", "segura.db"))
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")

import seed  # noqa: E402
import app   # noqa: E402

if __name__ == "__main__":
    seed.seed()
    print("App SEGURA em http://127.0.0.1:5001  (alvo com senha forte + MFA)")
    app.app.run(host="127.0.0.1", port=5001)

"""
Execucao LOCAL sem Docker (versao vulneravel), na porta 5000.

    python run_local.py

Cria o banco em app_vulneravel/data/vuln.db e semeia o usuario 'alvo'.
"""
import os

AQUI = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("DB_PATH", os.path.join(AQUI, "data", "vuln.db"))

import app  # noqa: E402

if __name__ == "__main__":
    app.init_db()
    print("App VULNERAVEL em http://127.0.0.1:5000  (alvo / senha123)")
    app.app.run(host="127.0.0.1", port=5000)

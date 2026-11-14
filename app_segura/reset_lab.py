"""
Reset de laboratorio (REQ-GER-03): recria o banco, zera contadores e o log,
e recadastra a conta 'alvo'. Use antes de cada ensaio para estado limpo.

Uso:
    python reset_lab.py
"""
import os

import controles as C
from seed import seed

DB_PATH = os.environ.get("DB_PATH", "/data/segura.db")


def reset(db_path: str = None):
    caminho = db_path or DB_PATH
    if os.path.exists(caminho):
        os.remove(caminho)
    # zera o log de seguranca
    try:
        open(C.ARQUIVO_LOG, "w", encoding="utf-8").close()
    except OSError:
        pass
    seed(caminho)
    print(f"Laboratorio reiniciado: banco='{caminho}', log zerado, 'alvo' recriado.")


if __name__ == "__main__":
    reset()

"""
Semeia o usuario de teste 'alvo' na app SEGURA (idempotente).

O 'alvo' recebe uma senha FORTE (fora da lista de bloqueio) e MFA ativado,
com segredo TOTP fixo (cifrado em repouso se CHAVE_SEGREDOS estiver definida).
O atacante NAO conhece essa senha nem o segredo.
"""
import os
import sqlite3

import controles as C
from app import init_db

DB_PATH = os.environ.get("DB_PATH", "/data/segura.db")

SEGREDO_ALVO = "JBSWY3DPEHPK3PXP"
SENHA_FORTE_ALVO = "correta cavalo bateria grampo 91"


def seed(db_path: str = None):
    caminho = db_path or DB_PATH
    init_db(caminho)
    db = sqlite3.connect(caminho)
    cur = db.execute("SELECT 1 FROM usuarios WHERE usuario = ?", ("alvo",))
    if cur.fetchone() is None:
        db.execute(
            "INSERT INTO usuarios (usuario, senha_hash, totp_segredo, "
            "mfa_ativado, totp_ultimo_passo) VALUES (?, ?, ?, 1, 0)",
            ("alvo", C.hash_senha(SENHA_FORTE_ALVO),
             C.cifrar_segredo(SEGREDO_ALVO)))
        db.commit()
        print("Usuario 'alvo' criado (senha forte + MFA ativo).")
    else:
        print("Usuario 'alvo' ja existe; nada a fazer.")
    db.close()


if __name__ == "__main__":
    seed()

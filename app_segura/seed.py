"""
Semeia o usuario de teste 'alvo' na app SEGURA (idempotente).

O 'alvo' recebe uma senha FORTE (fora de qualquer wordlist) e MFA ativado,
com um segredo TOTP fixo apenas para o laboratorio. O atacante NAO conhece
essa senha nem o segredo — ele parte da credencial vazada 'alvo:senha123'
(roubada da app vulneravel) para o ataque de credential stuffing.
"""
import os
import sqlite3

import controles as C

DB_PATH = os.environ.get("DB_PATH", "/data/segura.db")

# Segredo TOTP fixo do laboratorio (em producao seria gerado por usuario).
SEGREDO_ALVO = "JBSWY3DPEHPK3PXP"
SENHA_FORTE_ALVO = "Correta-Cavalo-Bateria-Grampo-91"


def seed():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    db = sqlite3.connect(DB_PATH)
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
    cur = db.execute("SELECT 1 FROM usuarios WHERE usuario = ?", ("alvo",))
    if cur.fetchone() is None:
        db.execute(
            "INSERT INTO usuarios (usuario, senha_hash, totp_segredo, mfa_ativado) "
            "VALUES (?, ?, ?, 1)",
            ("alvo", C.hash_senha(SENHA_FORTE_ALVO), SEGREDO_ALVO),
        )
        print("Usuario 'alvo' criado (senha forte + MFA ativo).")
    else:
        print("Usuario 'alvo' ja existe; nada a fazer.")
    db.commit()
    db.close()


if __name__ == "__main__":
    seed()

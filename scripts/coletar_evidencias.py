"""
Coletor HONESTO de evidencias do trabalho G11.

Para cada passo:
  1) monta o comando como LISTA e o executa via subprocess, capturando
     stdout+stderr;
  2) grava evidencias/<nome>.txt com um cabecalho que mostra o COMANDO EXATO
     que foi executado (derivado da mesma lista), data/hora, origem
     (docker|local) e a plataforma/versao do Python de onde a saida saiu;
  3) renderiza evidencias/capturaN_*.png a partir desse .txt (sem prompt fixo
     nem comando inventado).

Modos:
  --modo docker  -> docker exec -w /proj app_segura ...   (host.docker.internal)
  --modo local   -> executa no host                       (localhost)

Sequencia (REQ do relatorio): reset -> pytest -> brute vuln -> brute segura
-> espera o bloqueio expirar -> reset -> stuffing -> parede de MFA -> copia o
log do servidor -> revisao do log -> benchmark de hash.

Rode (o relatorio diz Docker):
    python scripts/coletar_evidencias.py --modo docker
"""
import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime

from PIL import Image, ImageDraw, ImageFont

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
EVID = os.path.join(RAIZ, "evidencias")
APP_SEGURA = os.path.join(RAIZ, "app_segura")
LOG_CONTAINER = "/app/seguranca.log"   # onde o gunicorn (WORKDIR /app) escreve

# ---------------------------------------------------------------------------
# Execucao de comandos
# ---------------------------------------------------------------------------
def fmt_cmd(cmd: list) -> str:
    """Representa a lista de args como uma linha de comando legivel."""
    partes = []
    for a in cmd:
        partes.append(f'"{a}"' if " " in a else a)
    return " ".join(partes)


def rodar(cmd: list, cwd: str = RAIZ, env: dict = None) -> tuple[str, int]:
    """Executa e devolve (saida_combinada, returncode)."""
    ambiente = dict(os.environ, **(env or {}))
    ambiente.setdefault("PYTHONIOENCODING", "utf-8")
    proc = subprocess.run(cmd, cwd=cwd, env=ambiente, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    return (proc.stdout or "") + (proc.stderr or ""), proc.returncode


# ---------------------------------------------------------------------------
# Renderizacao de "print de terminal" em PNG
# ---------------------------------------------------------------------------
BG = (12, 12, 12)
FG = (220, 220, 220)
COR_PROMPT = (86, 156, 214)
COR_CMD = (240, 240, 240)
COR_META = (128, 128, 128)
COR_OK = (106, 217, 106)
COR_RUIM = (240, 95, 95)
COR_AVISO = (230, 200, 90)

TOKENS_OK = ("passed", "BLOQUEAD", "0 conta(s)", "LOCKOUT", "duas etapas",
             "MFA_REQUERIDO", "R1", "R2", "FORCA_BRUTA", "STUFFING", "ALERTAS",
             "ordens de grandeza")
TOKENS_RUIM = ("SUCESSO_TOTAL", "COMPROMETIDO", "failed", "FAILED", "Error")
TOKENS_AVISO = ("LOGIN_FALHA", "MFA_FALHA", "-> FALHA", "FALHA (HTTP")


def carregar_fonte(tam):
    for caminho in (r"C:\Windows\Fonts\consola.ttf", r"C:\Windows\Fonts\cour.ttf",
                    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"):
        if os.path.exists(caminho):
            return ImageFont.truetype(caminho, tam)
    return ImageFont.load_default()


def cor_da_linha(linha: str) -> tuple:
    if any(t in linha for t in TOKENS_RUIM):
        return COR_RUIM
    if any(t in linha for t in TOKENS_OK):
        return COR_OK
    if any(t in linha for t in TOKENS_AVISO):
        return COR_AVISO
    return FG


def renderizar(conteudo: str, destino: str) -> tuple[int, int]:
    fonte = carregar_fonte(15)
    linhas = conteudo.rstrip("\n").split("\n")

    tmp = Image.new("RGB", (10, 10))
    d = ImageDraw.Draw(tmp)
    asc, desc = fonte.getmetrics()
    alt_linha = asc + desc + 4
    larg_max = max((d.textlength(l, font=fonte) for l in linhas), default=400)

    margem = 18
    larg = int(max(larg_max + margem * 2, 760))
    alt = margem + len(linhas) * alt_linha + margem

    img = Image.new("RGB", (larg, alt), BG)
    draw = ImageDraw.Draw(img)

    y = margem
    for linha in linhas:
        if linha.startswith("$ "):                 # linha de comando
            draw.text((margem, y), "$ ", font=fonte, fill=COR_PROMPT)
            px = margem + draw.textlength("$ ", font=fonte)
            draw.text((px, y), linha[2:], font=fonte, fill=COR_CMD)
        elif linha.startswith("#"):                # metadados (comentario)
            draw.text((margem, y), linha, font=fonte, fill=COR_META)
        else:
            draw.text((margem, y), linha, font=fonte, fill=cor_da_linha(linha))
        y += alt_linha

    img.save(destino)
    return larg, alt


# ---------------------------------------------------------------------------
# Gravacao de evidencia (.txt com cabecalho honesto + .png)
# ---------------------------------------------------------------------------
def gravar_evidencia(nome_txt, cmd, saida, origem, pyver, osname, png=None):
    cabecalho = (
        f"$ {fmt_cmd(cmd)}\n"
        f"# executado: {datetime.now().astimezone().isoformat(timespec='seconds')}"
        f" | origem: {origem} | Python {pyver} ({osname})\n\n"
    )
    conteudo = cabecalho + saida.rstrip("\n") + "\n"
    caminho_txt = os.path.join(EVID, nome_txt)
    with open(caminho_txt, "w", encoding="utf-8") as f:
        f.write(conteudo)
    info = f"  [ok] {nome_txt:30s}"
    if png:
        larg, alt = renderizar(conteudo, os.path.join(EVID, png))
        info += f" -> {png:30s} ({larg}x{alt})"
    print(info)
    return caminho_txt


# ---------------------------------------------------------------------------
# Especifico de cada modo
# ---------------------------------------------------------------------------
def info_origem(modo: str) -> tuple[str, str, str]:
    """Descobre (origem, python_version, os) de ONDE a saida sai de verdade."""
    if modo == "docker":
        out, rc = rodar(["docker", "exec", "app_segura", "python", "-c",
                         "import platform;print(platform.python_version(),"
                         "platform.system().lower())"])
        if rc != 0:
            sys.exit("ERRO: 'docker exec app_segura' falhou. O container esta de "
                     "pe? Suba com: docker compose -f app_segura/docker-compose.yml "
                     "up -d\nNao vou cair para o modo local em silencio.\n" + out)
        pyver, osname = (out.split() + ["?", "?"])[:2]
        return "docker (container app_segura)", pyver, osname
    import platform
    return "local (host)", platform.python_version(), sys.platform


def preparar_comandos(modo: str) -> dict:
    """Devolve, para o modo escolhido, a lista de args de cada passo."""
    if modo == "docker":
        base = ["docker", "exec", "-w", "/proj", "app_segura", "python"]
        base_log = ["docker", "exec", "-e", f"ARQUIVO_LOG={LOG_CONTAINER}",
                    "-w", "/proj", "app_segura", "python"]
        host5000 = "http://host.docker.internal:5000"
        host5001 = "http://host.docker.internal:5001"
        cat_log = ["docker", "exec", "app_segura", "cat", LOG_CONTAINER]
    else:
        base = base_log = [sys.executable]
        host5000, host5001 = "http://localhost:5000", "http://localhost:5001"
        cat_log = None  # local: lemos o arquivo direto

    return {
        "reset": base_log + ["app_segura/reset_lab.py"],
        "pytest": base + ["-m", "pytest", "-v", "tests/"],
        "brute_vuln": base + ["ataque/brute_force.py", "--url", host5000,
                              "--usuario", "alvo", "--wordlist",
                              "ataque/wordlist.txt", "--csv",
                              "evidencias/ataque_vuln_bruteforce.csv"],
        "brute_segura": base + ["ataque/brute_force.py", "--url", host5001,
                                "--usuario", "alvo", "--wordlist",
                                "ataque/wordlist.txt", "--csv",
                                "evidencias/ataque_segura_bruteforce.csv"],
        "stuffing": base + ["ataque/credential_stuffing.py", "--url", host5001,
                            "--creds", "ataque/creds_vazadas.txt"],
        "mfa_wall": base + ["ataque/brute_force.py", "--url", host5001,
                            "--usuario", "alvo", "--wordlist",
                            "ataque/senha_correta.txt"],
        "revisao": base + ["app_segura/revisao.py", "evidencias/log_servidor.jsonl"],
        "benchmark": base + ["ataque/benchmark_hash.py", "--repeticoes", "7"],
        "cat_log": cat_log,
    }


def ler_bloqueio_base(modo: str) -> int:
    if modo == "docker":
        out, _ = rodar(["docker", "exec", "app_segura", "python", "-c",
                        "import controles;print(controles.BLOQUEIO_BASE_SEG)"])
    else:
        out, _ = rodar([sys.executable, "-c",
                        "import sys;sys.path.insert(0,'app_segura');"
                        "import controles;print(controles.BLOQUEIO_BASE_SEG)"])
    try:
        return int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 30


def senha_do_alvo() -> str:
    txt = open(os.path.join(APP_SEGURA, "seed.py"), encoding="utf-8").read()
    m = re.search(r'SENHA_FORTE_ALVO\s*=\s*"([^"]+)"', txt)
    if not m:
        sys.exit("Nao encontrei SENHA_FORTE_ALVO em app_segura/seed.py")
    return m.group(1)


# ---------------------------------------------------------------------------
# Orquestracao
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--modo", choices=["docker", "local"], default="docker")
    args = p.parse_args()
    modo = args.modo

    os.makedirs(EVID, exist_ok=True)
    origem, pyver, osname = info_origem(modo)
    cmd = preparar_comandos(modo)
    print(f"Coletando evidencias | modo={modo} | origem={origem} "
          f"| Python {pyver} ({osname})\n")

    # 1) reset (estado limpo)
    saida, _ = rodar(cmd["reset"])
    print(f"  [reset] {saida.strip().splitlines()[-1] if saida.strip() else ''}")

    # 2) pytest completo
    saida, _ = rodar(cmd["pytest"])
    if modo == "docker" and "platform linux" not in saida:
        sys.exit("ERRO: pytest no container nao mostrou 'platform linux'.\n" + saida)
    gravar_evidencia("pytest_saida.txt", cmd["pytest"], saida, origem, pyver,
                     osname, png="captura1_pytest.png")

    # 3) forca bruta na VULNERAVEL (porta 5000)
    saida, _ = rodar(cmd["brute_vuln"])
    gravar_evidencia("ataque_vuln_bruteforce.txt", cmd["brute_vuln"], saida,
                     origem, pyver, osname, png="captura2_bruteforce_vuln.png")

    # 4) forca bruta na SEGURA (porta 5001) -> 5x FALHA + BLOQUEADO na 6a
    saida, _ = rodar(cmd["brute_segura"])
    gravar_evidencia("ataque_segura_bruteforce.txt", cmd["brute_segura"], saida,
                     origem, pyver, osname, png="captura3_bruteforce_segura.png")

    # 5) espera o bloqueio expirar (le BLOQUEIO_BASE_SEG) e reseta de novo
    base = ler_bloqueio_base(modo)
    print(f"  [espera] bloqueio base = {base}s (de BLOQUEIO_BASE_SEG); "
          f"aguardando {base + 2}s para expirar...")
    time.sleep(base + 2)
    saida, _ = rodar(cmd["reset"])
    print(f"  [reset] {saida.strip().splitlines()[-1] if saida.strip() else ''}")

    # 6) credential stuffing na SEGURA
    saida, _ = rodar(cmd["stuffing"])
    gravar_evidencia("ataque_segura_stuffing.txt", cmd["stuffing"], saida,
                     origem, pyver, osname, png="captura4_stuffing_segura.png")

    # 7) parede de MFA: senha CORRETA do alvo -> deve classificar MFA_REQUERIDO
    senha = senha_do_alvo()
    with open(os.path.join(RAIZ, "ataque", "senha_correta.txt"), "w",
              encoding="utf-8") as f:
        f.write(senha + "\n")
    saida, _ = rodar(cmd["mfa_wall"])
    gravar_evidencia("mfa_wall.txt", cmd["mfa_wall"], saida, origem, pyver,
                     osname, png="captura6_mfa_wall.png")

    # 8) copia o log do servidor
    if modo == "docker":
        saida, _ = rodar(cmd["cat_log"])
        cmd_log = cmd["cat_log"]
    else:
        caminho = os.path.join(APP_SEGURA, "seguranca.log")
        saida = open(caminho, encoding="utf-8").read() if os.path.exists(caminho) else ""
        cmd_log = ["type" if os.name == "nt" else "cat", caminho]
    # Copia CRUA (JSON Lines) que o revisao.py parseia; o .txt com cabecalho
    # existe so para virar a captura (a revisao nao entenderia o cabecalho).
    with open(os.path.join(EVID, "log_servidor.jsonl"), "w",
              encoding="utf-8") as f:
        f.write(saida if saida.endswith("\n") else saida + "\n")
    gravar_evidencia("log_servidor.txt", cmd_log, saida, origem, pyver, osname,
                     png="captura5_log_servidor.png")

    # 9) revisao do log copiado (AU-6: regras R1/R2)
    saida, _ = rodar(cmd["revisao"])
    gravar_evidencia("revisao_log.txt", cmd["revisao"], saida, origem, pyver,
                     osname, png="captura7_revisao.png")

    # 10) benchmark de hash (fecha H1)
    saida, _ = rodar(cmd["benchmark"])
    gravar_evidencia("benchmark_hash.txt", cmd["benchmark"], saida, origem, pyver,
                     osname, png="captura8_benchmark.png")

    print("\nConcluido. Evidencias e imagens em evidencias/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

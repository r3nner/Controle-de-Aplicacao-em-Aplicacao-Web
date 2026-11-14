"""
Para cada evidencia .txt em evidencias/:
  1) insere na frente o comando de terminal que a gerou (idempotente);
  2) renderiza o conteudo como uma "print" de terminal em PNG.

Uso:
    python relatorio/gerar_prints_evidencias.py

As imagens saem em evidencias/capturaN_*.png, prontas para colar no relatorio.
"""
import os

from PIL import Image, ImageDraw, ImageFont

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
EVID = os.path.join(RAIZ, "evidencias")

PROMPT = r"PS C:\Users\oandr\Documentos computador\t_final_segurança> "

# Evidencia -> (comando que a gerou, nome do PNG)
MAPA = {
    "pytest_saida.txt": (
        "docker exec -w /proj app_segura python -m pytest -v tests/",
        "captura1_pytest.png",
    ),
    "ataque_vuln_bruteforce.txt": (
        "docker exec -w /proj app_segura python ataque/brute_force.py "
        "--url http://host.docker.internal:5000 --usuario alvo "
        "--wordlist ataque/wordlist.txt",
        "captura2_bruteforce_vuln.png",
    ),
    "ataque_segura_bruteforce.txt": (
        "docker exec -w /proj app_segura python ataque/brute_force.py "
        "--url http://host.docker.internal:5001 --usuario alvo "
        "--wordlist ataque/wordlist.txt",
        "captura3_bruteforce_segura.png",
    ),
    "ataque_segura_stuffing.txt": (
        "docker exec -w /proj app_segura python ataque/credential_stuffing.py "
        "--url http://host.docker.internal:5001 --creds ataque/creds_vazadas.txt",
        "captura4_stuffing_segura.png",
    ),
    "log_servidor.txt": (
        "docker exec app_segura cat /app/seguranca.log",
        "captura5_log_servidor.png",
    ),
    "revisao_log.txt": (
        "docker exec -w /proj app_segura python app_segura/revisao.py evidencias/log_servidor.txt",
        "captura7_revisao.png",
    ),
    "mfa_wall.txt": (
        "docker exec -w /proj app_segura python ataque/brute_force.py "
        "--url http://host.docker.internal:5001 --usuario alvo "
        "--wordlist senha_correta.txt   # senha correta -> para no MFA",
        "captura6_mfa_wall.png",
    ),
}

# Cores (tema escuro estilo Windows Terminal)
BG = (12, 12, 12)
FG = (220, 220, 220)
COR_PROMPT = (86, 156, 214)
COR_CMD = (240, 240, 240)
COR_OK = (106, 217, 106)
COR_RUIM = (240, 95, 95)
COR_AVISO = (230, 200, 90)

TOKENS_OK = ("passed", "BLOQUEADO", "0 conta(s)", "LOCKOUT", "duas etapas",
             "R1", "R2", "FORCA_BRUTA", "STUFFING", "ALERTAS")
TOKENS_RUIM = ("SUCESSO_TOTAL", "COMPROMETIDO", "failed", "FAILED")
TOKENS_AVISO = ("LOGIN_FALHA", "MFA_FALHA", "FALHA")


def carregar_fonte(tam):
    for caminho in (r"C:\Windows\Fonts\consola.ttf",
                    r"C:\Windows\Fonts\cour.ttf"):
        if os.path.exists(caminho):
            return ImageFont.truetype(caminho, tam)
    return ImageFont.load_default()


def preparar_txt(nome, comando):
    """Insere o comando na frente do texto (idempotente) e devolve o conteudo."""
    caminho = os.path.join(EVID, nome)
    with open(caminho, encoding="utf-8", errors="replace") as f:
        bruto = f.read()
    # Remove bloco de comando ja inserido em execucao anterior.
    if bruto.startswith("PS C:\\"):
        partes = bruto.split("\n\n", 1)
        bruto = partes[1] if len(partes) == 2 else ""
    conteudo = f"{PROMPT}{comando}\n\n{bruto.rstrip()}\n"
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(conteudo)
    return conteudo


def cor_da_linha(linha, primeira):
    if primeira:
        return None  # tratada a parte (prompt + comando)
    if any(t in linha for t in TOKENS_RUIM):
        return COR_RUIM
    if any(t in linha for t in TOKENS_OK):
        return COR_OK
    if any(t in linha for t in TOKENS_AVISO):
        return COR_AVISO
    return FG


def renderizar(conteudo, destino, titulo):
    fonte = carregar_fonte(15)
    linhas = conteudo.rstrip("\n").split("\n")

    # Medir
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

    # Conteudo
    y = margem
    for idx, linha in enumerate(linhas):
        if idx == 0 and linha.startswith(PROMPT):
            draw.text((margem, y), PROMPT, font=fonte, fill=COR_PROMPT)
            px = margem + draw.textlength(PROMPT, font=fonte)
            draw.text((px, y), linha[len(PROMPT):], font=fonte, fill=COR_CMD)
        else:
            draw.text((margem, y), linha, font=fonte, fill=cor_da_linha(linha, idx == 0))
        y += alt_linha

    img.save(destino)
    return larg, alt


def main():
    print("Gerando prints das evidencias...\n")
    for nome, (comando, png) in MAPA.items():
        caminho = os.path.join(EVID, nome)
        if not os.path.exists(caminho):
            print(f"  [pulado] {nome} (nao encontrado)")
            continue
        conteudo = preparar_txt(nome, comando)
        destino = os.path.join(EVID, png)
        larg, alt = renderizar(conteudo, destino, f"Windows PowerShell — {nome}")
        print(f"  [ok] {nome:32s} -> {png:30s} ({larg}x{alt})")
    print("\nConcluido. Imagens em evidencias/.")


if __name__ == "__main__":
    main()

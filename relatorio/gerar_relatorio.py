"""
Gera o relatorio final em .docx (python-docx), em portugues, na estrutura
exigida pelo trabalho. Le as evidencias reais de ../evidencias/ e as embute.

Uso:
    python gerar_relatorio.py
Saida:
    relatorio/Relatorio_G11_Autenticacao.docx
"""
import os

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
EVID = os.path.join(RAIZ, "evidencias")
SAIDA = os.path.join(AQUI, "Relatorio_G11_Autenticacao.docx")


def ler(nome, limite=None):
    """Le um arquivo de evidencia; devolve texto ou aviso se ausente."""
    caminho = os.path.join(EVID, nome)
    if not os.path.exists(caminho):
        return f"[EVIDENCIA PENDENTE: execute o passo que gera {nome}]"
    with open(caminho, encoding="utf-8", errors="replace") as f:
        linhas = f.readlines()
    if limite:
        linhas = linhas[:limite]
    return "".join(linhas).rstrip()


# ---------------------------------------------------------------------------
# Helpers de formatacao
# ---------------------------------------------------------------------------
def add_captura(doc, texto, imagem=None, largura=6.3):
    """Insere a imagem da captura se existir; senao, deixa o marcador vermelho."""
    caminho = os.path.join(EVID, imagem) if imagem else None
    if caminho and os.path.exists(caminho):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run().add_picture(caminho, width=Inches(largura))
        legenda = doc.add_paragraph()
        legenda.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = legenda.add_run(texto)
        r.italic = True
        r.font.size = Pt(9)
    else:
        p = doc.add_paragraph()
        run = p.add_run(f"📸 [INSERIR CAPTURA DE TELA: {texto}]")
        run.bold = True
        run.font.color.rgb = RGBColor(0xC0, 0x00, 0x00)


def add_bloco_codigo(doc, texto):
    p = doc.add_paragraph()
    run = p.add_run(texto)
    run.font.name = "Consolas"
    run.font.size = Pt(8)


def add_tabela(doc, cabecalho, linhas):
    tab = doc.add_table(rows=1, cols=len(cabecalho))
    tab.style = "Light Grid Accent 1"
    hdr = tab.rows[0].cells
    for i, c in enumerate(cabecalho):
        hdr[i].paragraphs[0].add_run(c).bold = True
    for linha in linhas:
        cels = tab.add_row().cells
        for i, v in enumerate(linha):
            cels[i].text = str(v)
    return tab


# ---------------------------------------------------------------------------
# Construcao do documento
# ---------------------------------------------------------------------------
def build():
    doc = Document()

    # Capa
    t = doc.add_heading("Seleção, Implementação e Verificação de Controles de "
                        "Autenticação", level=0)
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub = doc.add_paragraph("Disciplina de Segurança — Tema G11\n"
                            "Referências: NIST SP 800-53 (principal) e "
                            "ISO/IEC 27001 Anexo A (complementar)")
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph()

    # ---- 1. Problema e objetivo ----
    doc.add_heading("1. Problema e objetivo", level=1)
    doc.add_paragraph(
        "A autenticação é a porta de entrada de qualquer sistema e, quando mal "
        "implementada, torna-se o elo mais fraco da segurança. Ataques como "
        "força bruta e credential stuffing exploram senhas fracas, ausência de "
        "limitação de tentativas e falta de um segundo fator para assumir o "
        "controle de contas. O problema investigado é: como um conjunto "
        "delimitado de controles de autenticação, selecionados com base em "
        "normas reconhecidas, altera concretamente a resistência de uma "
        "aplicação web a esses ataques."
    )
    doc.add_paragraph(
        "O objetivo é selecionar de forma fundamentada, implementar e verificar "
        "com evidências reais seis controles de autenticação (sem tratar de "
        "autorização), comparando uma versão vulnerável e uma versão segura da "
        "mesma aplicação, e demonstrar na prática — por testes automatizados e "
        "por um ataque antes/depois — o efeito de cada controle."
    )

    # ---- 2. Cenario e metodologia ----
    doc.add_heading("2. Cenário e metodologia", level=1)
    doc.add_paragraph(
        "Foram desenvolvidas duas versões de uma mesma aplicação web de "
        "autenticação própria, em Flask (Python) com banco SQLite, cada uma "
        "empacotada em contêiner Docker:"
    )
    doc.add_paragraph(
        "• app_vulneravel (http://localhost:5000): senha em MD5, sem política "
        "de senha, sem MFA, sem limite de tentativas e sessão fraca.", style="List Bullet")
    doc.add_paragraph(
        "• app_segura (http://localhost:5001): a mesma aplicação com os seis "
        "controles aplicados.", style="List Bullet")

    doc.add_heading("2.1 Ambiente e ferramentas", level=2)
    add_tabela(doc, ["Item", "Tecnologia / versão"], [
        ["Linguagem", "Python 3.12 (contêiner) / 3.14 (host de testes)"],
        ["Framework web", "Flask 3.1"],
        ["Banco de dados", "SQLite"],
        ["Hash de senha", "argon2-cffi (Argon2id)"],
        ["MFA (TOTP)", "pyotp + qrcode"],
        ["Testes", "pytest"],
        ["Orquestração", "Docker + docker-compose"],
        ["Ataque", "Scripts Python (requests) e, opcionalmente, Hydra"],
    ])

    doc.add_heading("2.2 Seleção e justificativa dos controles", level=2)
    doc.add_paragraph(
        "Os controles foram selecionados por cobrirem toda a cadeia de um "
        "evento de autenticação — armazenamento da credencial, qualidade da "
        "credencial, prova de posse de um segundo fator, resistência a "
        "tentativas automatizadas, rastreabilidade e proteção da sessão "
        "resultante — priorizando a família IA (Identification and "
        "Authentication) do NIST 800-53, complementada por AC-7, AU-2/AU-6 e "
        "SC-23. A escolha privilegia controles que mitigam diretamente os "
        "ataques demonstrados (força bruta e credential stuffing) e que são "
        "verificáveis de forma objetiva."
    )
    add_tabela(doc, ["Controle", "O que faz", "NIST 800-53", "ISO 27001"], [
        ["Argon2id", "Hash de senha com salt e custo de memória", "IA-5", "A.8.5 / A.5.17"],
        ["Política de senha", "Mínimo 8, bloqueia senhas vazadas, sem complexidade arbitrária (NIST 800-63B)", "IA-5(1)", "A.5.17"],
        ["MFA TOTP", "Segundo fator via app autenticador", "IA-2(1)", "A.8.5"],
        ["Lockout + backoff", "Bloqueio temporário após N falhas", "AC-7", "A.8.5"],
        ["Log de autenticação", "Registro estruturado + revisão", "AU-2 / AU-6", "A.8.15 / A.8.16"],
        ["Gestão de sessão", "Cookie HttpOnly/Secure/SameSite, timeout, rotação de ID", "SC-23", "A.8.5"],
    ])

    doc.add_heading("2.3 Análise de riscos (ameaça → controle → referência)", level=2)
    add_tabela(doc, ["Ameaça", "Controle mitigante", "NIST", "ISO"], [
        ["Vazamento de banco expõe senhas em claro/MD5", "Hash Argon2id", "IA-5", "A.8.5"],
        ["Uso de senhas fracas/vazadas", "Política NIST 800-63B", "IA-5(1)", "A.5.17"],
        ["Roubo de senha (phishing/reuso)", "MFA TOTP", "IA-2(1)", "A.8.5"],
        ["Força bruta / credential stuffing", "Lockout + backoff", "AC-7", "A.8.5"],
        ["Ataque sem rastro / detecção tardia", "Log + revisão de eventos", "AU-2/AU-6", "A.8.15/16"],
        ["Sequestro/fixação de sessão, roubo de cookie", "Gestão de sessão", "SC-23", "A.8.5"],
    ])

    doc.add_heading("2.4 Procedimentos", level=2)
    for passo in [
        "1. Subir as duas aplicações via docker-compose.",
        "2. Executar a suíte pytest contra a versão segura (verificação de cada controle).",
        "3. Rodar força bruta contra a app vulnerável (antes).",
        "4. Rodar força bruta e credential stuffing contra a app segura (depois).",
        "5. Coletar os logs de autenticação do servidor.",
        "6. Consolidar as evidências e analisar os resultados.",
    ]:
        doc.add_paragraph(passo, style="List Number")

    # ---- 3. Demonstracao pratica ----
    doc.add_heading("3. Demonstração prática", level=1)
    doc.add_paragraph(
        "Cada controle foi exercitado por um teste automatizado específico e o "
        "ataque foi executado contra as duas versões. Os comandos exatos estão "
        "em ataque/README.md. A seguir, a execução e seus marcadores de captura."
    )
    doc.add_heading("3.1 Verificação automatizada (pytest)", level=2)
    doc.add_paragraph(
        "A suíte cobre os seis controles com 48 casos de teste, agrupados por "
        "controle (classes TestIA5, TestIA5_1, TestIA2_1, TestAC7, TestAU2_AU6, "
        "TestSC23). Comando: python -m pytest -v tests/."
    )
    add_captura(doc, "Figura 1 — Saída do pytest: 48 testes passam (um grupo por controle).",
                "captura1_pytest.png")

    doc.add_heading("3.2 Ataque força bruta — app VULNERÁVEL", level=2)
    doc.add_paragraph("Comando:")
    add_bloco_codigo(doc, "python brute_force.py --url http://localhost:5000 "
                          "--usuario alvo --wordlist wordlist.txt")
    add_captura(doc, "Figura 2 — Força bruta na app vulnerável: senha descoberta (SUCESSO_TOTAL).",
                "captura2_bruteforce_vuln.png")

    doc.add_heading("3.3 Ataque força bruta — app SEGURA", level=2)
    doc.add_paragraph("Comando:")
    add_bloco_codigo(doc, "python brute_force.py --url http://localhost:5001 "
                          "--usuario alvo --wordlist wordlist.txt")
    add_captura(doc, "Figura 3 — Força bruta na app segura: conta BLOQUEADA (AC-7).",
                "captura3_bruteforce_segura.png")

    doc.add_heading("3.4 Credential stuffing — app SEGURA", level=2)
    doc.add_paragraph("Comando:")
    add_bloco_codigo(doc, "python credential_stuffing.py --url http://localhost:5001 "
                          "--creds creds_vazadas.txt")
    add_captura(doc, "Figura 4 — Credential stuffing na app segura: 0 contas comprometidas.",
                "captura4_stuffing_segura.png")
    add_captura(doc, "Figura 5 — Log do servidor: LOGIN_FALHA em sequência e LOCKOUT_ACIONADO.",
                "captura5_log_servidor.png")

    # ---- 4. Evidencias e resultados ----
    doc.add_heading("4. Evidências e resultados", level=1)

    doc.add_heading("4.1 Saída dos testes automatizados", level=2)
    add_bloco_codigo(doc, ler("pytest_saida.txt"))

    doc.add_heading("4.2 Força bruta na app vulnerável (antes)", level=2)
    add_bloco_codigo(doc, ler("ataque_vuln_bruteforce.txt"))

    doc.add_heading("4.3 Força bruta na app segura (depois)", level=2)
    add_bloco_codigo(doc, ler("ataque_segura_bruteforce.txt"))

    doc.add_heading("4.4 Credential stuffing na app segura (depois)", level=2)
    add_bloco_codigo(doc, ler("ataque_segura_stuffing.txt"))

    doc.add_heading("4.5 Parede de MFA: senha correta não basta (IA-2(1))", level=2)
    doc.add_paragraph(
        "Mesmo fornecendo a senha correta do usuário 'alvo', o acesso para na "
        "verificação em duas etapas — o painel só é liberado após o segundo fator:"
    )
    add_bloco_codigo(doc, ler("mfa_wall.txt"))
    add_captura(doc, "Figura 6 — Com a senha correta, o acesso para na verificação em duas etapas (MFA).",
                "captura6_mfa_wall.png")

    doc.add_heading("4.6 Log de autenticação do servidor (AU-2/AU-6)", level=2)
    doc.add_paragraph(
        "Os eventos abaixo foram gerados pelo próprio ataque (formato JSON Lines). "
        "Note a sequência de LOGIN_FALHA culminando em LOCKOUT_ACIONADO:"
    )
    add_bloco_codigo(doc, ler("log_servidor.txt", limite=40))

    doc.add_heading("4.7 Síntese comparativa antes/depois", level=2)
    add_tabela(doc, ["Ataque", "App vulnerável", "App segura"], [
        ["Força bruta", "Senha descoberta (comprometida)", "Bloqueada na 6a tentativa — 5 falhas + bloqueio (AC-7)"],
        ["Credential stuffing", "Credencial válida reutilizável", "Rejeitada (senha forte + MFA)"],
        ["Rastreabilidade", "Nenhum registro", "Eventos registrados e revisáveis"],
    ])

    # ---- 5. Analise critica ----
    doc.add_heading("5. Análise crítica", level=1)
    doc.add_paragraph(
        "Os resultados confirmam que os controles atuam em camadas (defesa em "
        "profundidade): o lockout (AC-7) interrompe o ataque automatizado antes "
        "mesmo de a senha ser testada por completo; o MFA (IA-2(1)) garante que, "
        "mesmo que a senha fosse conhecida, o acesso não se concretiza; e o "
        "Argon2id (IA-5) torna inútil o vazamento do banco, pois os hashes não "
        "são reversíveis em tempo hábil. O log (AU-2/AU-6) transforma um ataque "
        "silencioso em um evento detectável."
    )
    doc.add_heading("5.1 Limitações e possíveis erros", level=2)
    for item in [
        "A lista de senhas vazadas é local e reduzida; em produção deve-se usar "
        "a API do Have I Been Pwned (k-anonymity) ou base equivalente.",
        "No laboratório as apps rodam em HTTP, portanto o cookie Secure foi "
        "desabilitado no demo para o navegador enviar a sessão; em produção o "
        "controle SC-23 exige HTTPS obrigatório.",
        "O Flask usa sessão assinada no cliente; a 'rotação de ID' foi "
        "demonstrada via token rotacionado. Com sessão server-side (ex.: Redis) "
        "o controle é mais robusto.",
        "O lockout por usuário pode ser alvo de negação de serviço (bloquear a "
        "vítima de propósito); mitigações incluem lockout por IP e CAPTCHA.",
    ]:
        doc.add_paragraph(item, style="List Bullet")

    doc.add_heading("5.2 Riscos residuais", level=2)
    doc.add_paragraph(
        "Permanecem riscos de phishing de MFA em tempo real (adversary-in-the-"
        "middle), roubo de dispositivo com o autenticador e engenharia social de "
        "recuperação de conta. Esses vetores exigem controles adicionais (chaves "
        "FIDO2/WebAuthn, vinculação de origem, processos de recuperação seguros) "
        "fora do escopo deste trabalho."
    )

    # ---- 6. Conclusoes e recomendacoes ----
    doc.add_heading("6. Conclusões e recomendações", level=1)
    doc.add_paragraph(
        "Demonstrou-se, com evidências reais (testes automatizados e ataque "
        "antes/depois), que os seis controles selecionados elevam de forma "
        "mensurável a resistência da aplicação: o que antes era um "
        "comprometimento trivial por força bruta passou a ser um ataque "
        "bloqueado, sem rastro perdido e com um segundo fator intransponível. "
        "Os controles são diretamente rastreáveis a NIST SP 800-53 e ISO/IEC "
        "27001 Anexo A."
    )
    doc.add_paragraph("Recomendações:")
    for rec in [
        "Adotar HTTPS obrigatório e reativar o cookie Secure (SC-23).",
        "Integrar verificação de senhas vazadas a uma base atualizada (IA-5(1)).",
        "Evoluir o MFA para FIDO2/WebAuthn, resistente a phishing (IA-2(1)).",
        "Centralizar e monitorar os logs (SIEM) com alertas de lockout (AU-6).",
        "Complementar o lockout com limitação por IP e CAPTCHA (AC-7).",
    ]:
        doc.add_paragraph(rec, style="List Bullet")

    doc.save(SAIDA)
    print(f"Relatorio gerado em: {SAIDA}")


if __name__ == "__main__":
    build()

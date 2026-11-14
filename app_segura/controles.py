"""
Controles de seguranca de autenticacao da versao SEGURA.

Implementa os requisitos do Apendice A do relatorio (REQ-*), mapeando cada
controle a NIST SP 800-53 Rev. 5 e a ISO/IEC 27001:2022 Anexo A.

    C1 IA-5               -> hash Argon2id (RFC 9106)        -> A.5.17/A.8.5/A.8.24
    C2 IA-5(1)            -> politica NIST 800-63B            -> A.5.17
    C3 IA-2(1)/(2)/(8)    -> MFA TOTP + anti-replay           -> A.8.5
    C4 AC-7               -> lockout + recuo exponencial      -> A.8.5
    C5 AU-2/AU-3/AU-6/AU-8-> log estruturado + revisao        -> A.8.15/16/17
    C6 SC-23              -> sessao server-side               -> A.8.5/A.8.24/A.8.26
"""
import base64
import hashlib
import hmac
import io
import json
import os
import time
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone

import pyotp
import qrcode
from argon2 import PasswordHasher, exceptions
from argon2.profiles import RFC_9106_LOW_MEMORY

# ---------------------------------------------------------------------------
# Parametros (ajustaveis por variavel de ambiente)
# ---------------------------------------------------------------------------
MAX_TENTATIVAS = int(os.environ.get("MAX_TENTATIVAS", "5"))        # AC-7 (N)
BLOQUEIO_BASE_SEG = int(os.environ.get("BLOQUEIO_BASE_SEG", "30"))  # AC-7 (b0)
BLOQUEIO_MAX_SEG = int(os.environ.get("BLOQUEIO_MAX_SEG", "900"))   # AC-7 (bmax=15min)
SENHA_MIN = 8     # IA-5(1): minimo com MFA obrigatorio
SENHA_MAX = 128   # IA-5(1): aceita frases-senha longas
APP_NOME = os.environ.get("APP_NOME", "portal")

_DIR = os.path.dirname(os.path.abspath(__file__))
# Lista de bloqueio (>=10k). Mantem compat. com o nome antigo como fallback.
ARQUIVO_BLOQUEIO = os.environ.get(
    "ARQUIVO_BLOQUEIO", os.path.join(_DIR, "dados", "senhas_bloqueadas.txt"))
ARQUIVO_BLOQUEIO_FALLBACK = os.path.join(_DIR, "senhas_vazadas.txt")
ARQUIVO_LOG = os.environ.get("ARQUIVO_LOG", os.path.join(_DIR, "seguranca.log"))

# Segredos opcionais (lidos do ambiente, nunca do codigo) — REQ-GER-06.
PEPPER = os.environ.get("PEPPER", "")                  # IA-5 (DEVERIA)
CHAVE_SEGREDOS = os.environ.get("CHAVE_SEGREDOS", "")  # IA-2(8) (DEVERIA)


def normalizar(s: str) -> str:
    """Normalizacao Unicode NFKC antes de hash/validacao (REQ-IA51-01)."""
    return unicodedata.normalize("NFKC", s or "")


# ===========================================================================
# C1 — IA-5 : armazenamento de senhas com Argon2id
# ===========================================================================
# Perfil RFC 9106 de baixa memoria: m=65536 KiB (64 MiB), t=3, p=4.
_ph = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)


def _com_pepper(senha: str) -> str:
    """Aplica pepper HMAC-SHA256 (se configurado) sobre a senha normalizada."""
    s = normalizar(senha)
    if PEPPER:
        return hmac.new(PEPPER.encode(), s.encode(), hashlib.sha256).hexdigest()
    return s


def hash_senha(senha: str) -> str:
    """Deriva o verificador Argon2id (formato PHC, salt interno de 16 B)."""
    return _ph.hash(_com_pepper(senha))


def verificar_senha(hash_armazenado: str, senha: str) -> bool:
    """Confere a senha contra um hash Argon2id, em tempo constante."""
    try:
        return _ph.verify(hash_armazenado, _com_pepper(senha))
    except (exceptions.VerifyMismatchError, exceptions.InvalidHashError,
            exceptions.VerificationError):
        return False


# Hash ficticio para igualar o tempo de resposta de usuarios inexistentes.
HASH_FICTICIO = hash_senha("senha-ficticia-para-tempo-constante")


def verificar_usuario(hash_armazenado, senha: str) -> bool:
    """
    REQ-IA5-05: se o usuario nao existe (hash None), ainda executa uma
    verificacao contra HASH_FICTICIO, garantindo tempo semelhante e evitando
    enumeracao de usuarios por tempo de resposta.
    """
    alvo = hash_armazenado if hash_armazenado else HASH_FICTICIO
    resultado = verificar_senha(alvo, senha)
    return bool(hash_armazenado) and resultado


def precisa_rehash(hash_armazenado: str) -> bool:
    """REQ-IA5-06: indica se o hash deve ser recalculado (parametros antigos)."""
    try:
        return _ph.check_needs_rehash(hash_armazenado)
    except exceptions.InvalidHashError:
        return True


def parametros_do_hash(hash_armazenado: str) -> dict:
    """Extrai m, t, p do proprio hash PHC (para o teste de parametros)."""
    # formato: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    try:
        secao = hash_armazenado.split("$")[3]
        return dict(kv.split("=") for kv in secao.split(","))
    except (IndexError, ValueError):
        return {}


# ===========================================================================
# C2 — IA-5(1) : politica de senha (NIST SP 800-63B)
# ===========================================================================
_cache_bloqueio = None


def _carregar_bloqueio() -> set:
    global _cache_bloqueio
    if _cache_bloqueio is None:
        for caminho in (ARQUIVO_BLOQUEIO, ARQUIVO_BLOQUEIO_FALLBACK):
            try:
                with open(caminho, encoding="utf-8") as f:
                    _cache_bloqueio = {l.strip().lower() for l in f if l.strip()}
                break
            except FileNotFoundError:
                continue
        if _cache_bloqueio is None:
            _cache_bloqueio = set()
    return _cache_bloqueio


def validar_politica_senha(senha: str, usuario: str = "",
                           app_nome: str = None) -> tuple[bool, str]:
    """
    REQ-IA51-*: comprimento 8..128 (apos NFKC), sem regras de composicao,
    rejeita lista de bloqueio (>=10k) e termos contextuais. Retorna (ok, msg).
    """
    s = normalizar(senha)
    if len(s) < SENHA_MIN:
        return False, f"A senha deve ter no minimo {SENHA_MIN} caracteres."
    if len(s) > SENHA_MAX:
        return False, f"A senha deve ter no maximo {SENHA_MAX} caracteres."
    contexto = {usuario.lower().strip(), (app_nome or APP_NOME).lower(), "g11"}
    contexto.discard("")
    if s.lower() in _carregar_bloqueio() or s.lower() in contexto:
        return False, ("Esta senha e muito comum ou ja apareceu em vazamentos. "
                       "Prefira uma frase-senha longa.")
    return True, "ok"


def verificar_hibp(senha: str) -> bool:
    """
    REQ-IA51-09 (DEVERIA): consulta Pwned Passwords por k-anonimato.
    Envia apenas os 5 primeiros hex do SHA-1; compara o sufixo localmente.
    Retorna True se a senha consta em vazamentos. Requer rede.
    """
    import urllib.request
    sha1 = hashlib.sha1(normalizar(senha).encode()).hexdigest().upper()
    prefixo, sufixo = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefixo}"
    req = urllib.request.Request(url, headers={"User-Agent": "lab-g11"})
    corpo = urllib.request.urlopen(req, timeout=10).read().decode()
    return any(linha.split(":")[0] == sufixo for linha in corpo.splitlines())


# ===========================================================================
# C3 — IA-2(1)/(2)/(8) : MFA via TOTP
# ===========================================================================
def gerar_segredo_totp() -> str:
    """Segredo Base32 de 160 bits (32 caracteres) — RFC 4226."""
    return pyotp.random_base32()


def uri_provisionamento(usuario: str, segredo: str, emissor: str = "G11") -> str:
    return pyotp.totp.TOTP(segredo).provisioning_uri(name=usuario,
                                                     issuer_name=emissor)


def gerar_qr_base64(usuario: str, segredo: str) -> str:
    img = qrcode.make(uri_provisionamento(usuario, segredo))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def passo_totp(ts: float = None) -> int:
    """Numero do passo de tempo TOTP (janela de 30 s) — base do anti-replay."""
    return int((ts if ts is not None else time.time()) // 30)


def verificar_totp(segredo: str, codigo: str) -> bool:
    """Valida um codigo TOTP de 6 digitos, janela +/-1 passo (RFC 6238)."""
    if not segredo or not codigo:
        return False
    return pyotp.TOTP(segredo).verify(codigo.strip(), valid_window=1)


# --- Cifragem do segredo em repouso (Fernet) — IA-2(8)/REQ-IA2-08 -----------
def _fernet():
    if not CHAVE_SEGREDOS:
        return None
    from cryptography.fernet import Fernet
    return Fernet(CHAVE_SEGREDOS.encode() if isinstance(CHAVE_SEGREDOS, str)
                  else CHAVE_SEGREDOS)


def cifrar_segredo(segredo: str) -> str:
    f = _fernet()
    if f is None:
        return segredo
    return "enc:" + f.encrypt(segredo.encode()).decode()


def decifrar_segredo(valor: str) -> str:
    if valor and valor.startswith("enc:"):
        f = _fernet()
        if f is not None:
            return f.decrypt(valor[4:].encode()).decode()
    return valor


# ===========================================================================
# C4 — AC-7 : bloqueio apos N falhas + recuo exponencial
# ===========================================================================
def esta_bloqueado(db, usuario: str) -> tuple[bool, int]:
    row = db.execute(
        "SELECT bloqueado_ate FROM tentativas WHERE usuario = ?", (usuario,)
    ).fetchone()
    if not row or not row["bloqueado_ate"]:
        return False, 0
    restante = int(row["bloqueado_ate"] - time.time())
    return (restante > 0, max(restante, 0))


def registrar_falha(db, usuario: str) -> tuple[int, int]:
    """
    Contabiliza uma falha. Ao atingir MAX_TENTATIVAS aplica bloqueio
    min(b0 * 2^k, bmax) e zera o contador. Retorna (falhas, bloqueio_seg).
    Vale tambem para usuarios inexistentes (REQ-AC7-06).
    """
    row = db.execute(
        "SELECT falhas, nivel FROM tentativas WHERE usuario = ?", (usuario,)
    ).fetchone()
    if row is None:
        db.execute("INSERT INTO tentativas (usuario, falhas, nivel, "
                   "bloqueado_ate) VALUES (?, 1, 0, 0)", (usuario,))
        db.commit()
        return 1, 0

    falhas, nivel, bloqueio = row["falhas"] + 1, row["nivel"], 0
    if falhas >= MAX_TENTATIVAS:
        bloqueio = min(BLOQUEIO_BASE_SEG * (2 ** nivel), BLOQUEIO_MAX_SEG)
        db.execute("UPDATE tentativas SET falhas = 0, nivel = ?, "
                   "bloqueado_ate = ? WHERE usuario = ?",
                   (nivel + 1, time.time() + bloqueio, usuario))
    else:
        db.execute("UPDATE tentativas SET falhas = ? WHERE usuario = ?",
                   (falhas, usuario))
    db.commit()
    return falhas, bloqueio


def resetar_tentativas(db, usuario: str) -> None:
    db.execute(
        "INSERT INTO tentativas (usuario, falhas, nivel, bloqueado_ate) "
        "VALUES (?, 0, 0, 0) ON CONFLICT(usuario) DO UPDATE SET "
        "falhas = 0, nivel = 0, bloqueado_ate = 0", (usuario,))
    db.commit()


# ===========================================================================
# C5 — AU-2/AU-3/AU-6/AU-8 : log estruturado + revisao
# ===========================================================================
EVENTOS = {
    "CADASTRO", "SENHA_REJEITADA_POLITICA", "LOGIN_FALHA", "LOGIN_SENHA_OK",
    "MFA_FALHA", "LOGIN_SUCESSO", "LOCKOUT_ACIONADO", "LOGIN_BLOQUEADO",
    "MFA_ATIVADO", "LOGOUT", "SESSAO_EXPIRADA",
}
CAMPOS_PROIBIDOS = {"senha", "codigo", "segredo", "sid", "totp"}


def registrar_evento(tipo: str, usuario: str, ip: str = "-", user_agent: str = "",
                     detalhe: str = "", arquivo: str = None) -> dict:
    """AU-3: registra um evento como linha JSON (JSON Lines, UTF-8)."""
    registro = {
        "timestamp": datetime.now(timezone.utc).isoformat(),   # AU-8: UTC, us
        "tipo": tipo,
        "usuario": usuario,
        "ip": ip,
        "user_agent": (user_agent or "")[:200],
        "detalhe": detalhe,
    }
    caminho = arquivo or ARQUIVO_LOG
    with open(caminho, "a", encoding="utf-8") as f:                 # somente acrescimo
        f.write(json.dumps(registro, ensure_ascii=False) + "\n")
    return registro


def _parse_ts(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (ValueError, TypeError):
        return 0.0


def revisar_eventos(arquivo: str = None, tipo: str = None, usuario: str = None,
                    desde: float = None) -> list[dict]:
    """AU-6: le e filtra o log por tipo, usuario e instante (desde)."""
    caminho = arquivo or ARQUIVO_LOG
    eventos = []
    try:
        with open(caminho, encoding="utf-8") as f:
            for linha in f:
                linha = linha.strip()
                if not linha:
                    continue
                reg = json.loads(linha)
                if tipo and reg.get("tipo") != tipo:
                    continue
                if usuario and reg.get("usuario") != usuario:
                    continue
                if desde and _parse_ts(reg.get("timestamp")) < desde:
                    continue
                eventos.append(reg)
    except FileNotFoundError:
        pass
    return eventos


def _regra_r1(eventos: list[dict]) -> list[dict]:
    """R1: >=5 falhas da mesma conta em 60 s -> alerta FORCA_BRUTA."""
    por_conta = defaultdict(list)
    for e in eventos:
        if e["tipo"] in ("LOGIN_FALHA", "MFA_FALHA"):
            por_conta[e["usuario"]].append(_parse_ts(e["timestamp"]))
    alertas = []
    for usuario, ts in por_conta.items():
        ts.sort()
        for i in range(len(ts)):
            janela = [t for t in ts if ts[i] <= t < ts[i] + 60]
            if len(janela) >= 5:
                alertas.append({"regra": "R1", "tipo": "FORCA_BRUTA",
                                "usuario": usuario, "ocorrencias": len(janela)})
                break
    return alertas


def _regra_r2(eventos: list[dict]) -> list[dict]:
    """R2: falhas em >=10 contas distintas do mesmo IP em 10 min -> STUFFING."""
    por_ip = defaultdict(list)
    for e in eventos:
        if e["tipo"] in ("LOGIN_FALHA", "MFA_FALHA"):
            por_ip[e["ip"]].append((_parse_ts(e["timestamp"]), e["usuario"]))
    alertas = []
    for ip, itens in por_ip.items():
        itens.sort()
        for i in range(len(itens)):
            t0 = itens[i][0]
            contas = {u for t, u in itens if t0 <= t < t0 + 600}
            if len(contas) >= 10:
                alertas.append({"regra": "R2", "tipo": "STUFFING_SPRAYING",
                                "ip": ip, "contas": len(contas)})
                break
    return alertas


def resumo_eventos(arquivo: str = None) -> dict:
    """AU-6: contagem por tipo + lista de alertas (R1, R2)."""
    eventos = revisar_eventos(arquivo)
    return {
        "por_tipo": dict(Counter(e["tipo"] for e in eventos)),
        "alertas": _regra_r1(eventos) + _regra_r2(eventos),
    }

"""
Controles de seguranca de autenticacao da versao SEGURA.

Cada bloco mapeia um controle para NIST SP 800-53 e ISO/IEC 27001 Anexo A.
Os controles sao implementados como funcoes puras/auxiliares para serem
verificaveis de forma isolada pelos testes automatizados (pytest).

    IA-5       -> hash Argon2id            -> ISO A.8.5 / A.5.17
    IA-5(1)    -> politica NIST 800-63B     -> ISO A.5.17
    IA-2(1)    -> MFA TOTP                  -> ISO A.8.5
    AC-7       -> lockout + backoff         -> ISO A.8.5
    AU-2/AU-6  -> log de eventos + revisao  -> ISO A.8.15 / A.8.16
    SC-23      -> gestao de sessao          -> ISO A.8.5
"""
import base64
import io
import json
import os
import time
from datetime import datetime, timezone

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# ---------------------------------------------------------------------------
# Parametros dos controles (ajustaveis por variavel de ambiente).
# ---------------------------------------------------------------------------
MAX_TENTATIVAS = int(os.environ.get("MAX_TENTATIVAS", "5"))      # AC-7
BLOQUEIO_BASE_SEG = int(os.environ.get("BLOQUEIO_BASE_SEG", "30"))  # AC-7 backoff
SENHA_MIN = 8    # IA-5(1) NIST 800-63B: minimo 8 caracteres
SENHA_MAX = 64   # IA-5(1) NIST 800-63B: permitir ate >=64

_DIR = os.path.dirname(os.path.abspath(__file__))
ARQUIVO_SENHAS_VAZADAS = os.environ.get(
    "ARQUIVO_SENHAS_VAZADAS", os.path.join(_DIR, "senhas_vazadas.txt")
)
ARQUIVO_LOG = os.environ.get("ARQUIVO_LOG", os.path.join(_DIR, "seguranca.log"))

# ===========================================================================
# IA-5 : Armazenamento de senha com Argon2id  (ISO A.8.5 / A.5.17)
# ===========================================================================
# Parametros alinhados a recomendacao OWASP para Argon2id.
_ph = PasswordHasher(
    time_cost=3,         # iteracoes
    memory_cost=65536,   # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_senha(senha: str) -> str:
    """Deriva o verificador Argon2id (inclui salt e parametros no proprio hash)."""
    return _ph.hash(senha)


def verificar_senha(hash_armazenado: str, senha: str) -> bool:
    """Confere a senha contra o hash Argon2id em tempo constante."""
    try:
        return _ph.verify(hash_armazenado, senha)
    except (VerifyMismatchError, InvalidHashError):
        return False


def precisa_rehash(hash_armazenado: str) -> bool:
    """Indica se o hash deve ser recalculado (parametros desatualizados)."""
    try:
        return _ph.check_needs_rehash(hash_armazenado)
    except InvalidHashError:
        return True


# ===========================================================================
# IA-5(1) : Politica de senha conforme NIST SP 800-63B  (ISO A.5.17)
# ===========================================================================
_cache_vazadas = None


def _carregar_senhas_vazadas() -> set:
    global _cache_vazadas
    if _cache_vazadas is None:
        try:
            with open(ARQUIVO_SENHAS_VAZADAS, encoding="utf-8") as f:
                _cache_vazadas = {linha.strip() for linha in f if linha.strip()}
        except FileNotFoundError:
            _cache_vazadas = set()
    return _cache_vazadas


def validar_politica_senha(senha: str) -> tuple[bool, str]:
    """
    Aplica a politica moderna do NIST 800-63B:
      - comprimento minimo 8 e maximo >= 64;
      - rejeita senhas presentes em lista de senhas comprometidas/vazadas;
      - NAO exige regras de complexidade arbitrarias (maiuscula, simbolo, etc.),
        pois o proprio NIST desaconselha esse tipo de regra.
    Retorna (valida, mensagem).
    """
    if len(senha) < SENHA_MIN:
        return False, f"A senha deve ter no minimo {SENHA_MIN} caracteres."
    if len(senha) > SENHA_MAX:
        return False, f"A senha deve ter no maximo {SENHA_MAX} caracteres."
    if senha in _carregar_senhas_vazadas():
        return False, "Esta senha aparece em vazamentos conhecidos. Escolha outra."
    return True, "ok"


# ===========================================================================
# IA-2(1) : MFA via TOTP  (ISO A.8.5)
# ===========================================================================
def gerar_segredo_totp() -> str:
    """Gera um segredo base32 para o autenticador TOTP."""
    return pyotp.random_base32()


def uri_provisionamento(usuario: str, segredo: str,
                        emissor: str = "AppSegura-G11") -> str:
    """URI otpauth:// para cadastrar o segredo no app autenticador."""
    return pyotp.totp.TOTP(segredo).provisioning_uri(
        name=usuario, issuer_name=emissor
    )


def gerar_qr_base64(usuario: str, segredo: str) -> str:
    """Renderiza o QR code de provisionamento como PNG em data URI base64."""
    uri = uri_provisionamento(usuario, segredo)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


def verificar_totp(segredo: str, codigo: str) -> bool:
    """Valida um codigo TOTP de 6 digitos (janela +/-1 para tolerar relogio)."""
    if not segredo or not codigo:
        return False
    return pyotp.TOTP(segredo).verify(codigo.strip(), valid_window=1)


# ===========================================================================
# AC-7 : Bloqueio apos N tentativas falhas + backoff  (ISO A.8.5)
# ===========================================================================
# Estado persistido na tabela `tentativas(usuario, falhas, nivel, bloqueado_ate)`.
def esta_bloqueado(db, usuario: str) -> tuple[bool, int]:
    """Retorna (bloqueado, segundos_restantes) para o usuario."""
    row = db.execute(
        "SELECT bloqueado_ate FROM tentativas WHERE usuario = ?", (usuario,)
    ).fetchone()
    if not row or not row["bloqueado_ate"]:
        return False, 0
    restante = int(row["bloqueado_ate"] - time.time())
    if restante > 0:
        return True, restante
    return False, 0


def registrar_falha(db, usuario: str) -> tuple[int, int]:
    """
    Contabiliza uma falha de autenticacao. Ao atingir MAX_TENTATIVAS, aplica
    bloqueio temporario com backoff exponencial (dobra a cada rodada de bloqueio)
    e zera o contador de falhas para a proxima janela.
    Retorna (falhas_atuais, segundos_de_bloqueio) — bloqueio 0 se nao bloqueou.
    """
    row = db.execute(
        "SELECT falhas, nivel FROM tentativas WHERE usuario = ?", (usuario,)
    ).fetchone()
    if row is None:
        db.execute(
            "INSERT INTO tentativas (usuario, falhas, nivel, bloqueado_ate) "
            "VALUES (?, 1, 0, 0)",
            (usuario,),
        )
        db.commit()
        return 1, 0

    falhas = row["falhas"] + 1
    nivel = row["nivel"]
    bloqueio = 0
    if falhas >= MAX_TENTATIVAS:
        # Backoff exponencial: 30s, 60s, 120s, ... a cada rodada de bloqueio.
        bloqueio = BLOQUEIO_BASE_SEG * (2 ** nivel)
        db.execute(
            "UPDATE tentativas SET falhas = 0, nivel = ?, bloqueado_ate = ? "
            "WHERE usuario = ?",
            (nivel + 1, time.time() + bloqueio, usuario),
        )
    else:
        db.execute(
            "UPDATE tentativas SET falhas = ? WHERE usuario = ?",
            (falhas, usuario),
        )
    db.commit()
    return falhas, bloqueio


def resetar_tentativas(db, usuario: str) -> None:
    """Zera contador e bloqueio apos autenticacao bem-sucedida."""
    db.execute(
        "INSERT INTO tentativas (usuario, falhas, nivel, bloqueado_ate) "
        "VALUES (?, 0, 0, 0) "
        "ON CONFLICT(usuario) DO UPDATE SET falhas = 0, nivel = 0, bloqueado_ate = 0",
        (usuario,),
    )
    db.commit()


# ===========================================================================
# AU-2 / AU-6 : Log estruturado de eventos de autenticacao + revisao
#              (ISO A.8.15 / A.8.16)
# ===========================================================================
# Eventos padronizados (AU-2: quais eventos auditar).
EVENTOS = {
    "REGISTRO", "LOGIN_SUCESSO", "LOGIN_FALHA", "LOCKOUT_ACIONADO",
    "LOCKOUT_BLOQUEADO", "MFA_ATIVADO", "MFA_FALHA", "LOGOUT",
    "SESSAO_EXPIRADA",
}


def registrar_evento(tipo: str, usuario: str, ip: str = "-",
                     detalhe: str = "", arquivo: str = None) -> dict:
    """
    Grava um evento de autenticacao em formato JSON por linha (JSON Lines).
    Campos: timestamp ISO-8601 UTC, tipo, usuario, ip, detalhe.
    """
    registro = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tipo": tipo,
        "usuario": usuario,
        "ip": ip,
        "detalhe": detalhe,
    }
    caminho = arquivo or ARQUIVO_LOG
    with open(caminho, "a", encoding="utf-8") as f:
        f.write(json.dumps(registro, ensure_ascii=False) + "\n")
    return registro


def revisar_eventos(arquivo: str = None, tipo: str = None,
                    usuario: str = None) -> list[dict]:
    """
    AU-6: le e filtra o log para revisao/analise de eventos de autenticacao.
    """
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
                eventos.append(reg)
    except FileNotFoundError:
        pass
    return eventos


def resumo_eventos(arquivo: str = None) -> dict:
    """AU-6: contagem por tipo de evento, util para deteccao de abuso."""
    resumo = {}
    for ev in revisar_eventos(arquivo):
        resumo[ev["tipo"]] = resumo.get(ev["tipo"], 0) + 1
    return resumo

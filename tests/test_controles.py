"""
Testes automatizados que COMPROVAM cada controle de seguranca.

Cada classe cobre um controle NIST 800-53. Rode com:
    pytest -v tests/
Para gerar evidencia em arquivo:
    pytest -v tests/ | tee evidencias/pytest_saida.txt
"""
import sqlite3
import time

import pyotp
import pytest

import controles as C
from conftest import criar_usuario


# ===========================================================================
# IA-5 : hash de senha com Argon2id
# ===========================================================================
class TestIA5_HashArgon2:
    def test_hash_usa_argon2id(self):
        h = C.hash_senha("umaSenhaQualquer123")
        assert h.startswith("$argon2id$"), "o hash deve ser Argon2id"

    def test_salt_unico_por_hash(self):
        # Mesmo texto gera hashes diferentes -> salt aleatorio por senha.
        assert C.hash_senha("mesmaSenha123") != C.hash_senha("mesmaSenha123")

    def test_verificacao_correta_e_incorreta(self):
        h = C.hash_senha("senhaCorreta#2024")
        assert C.verificar_senha(h, "senhaCorreta#2024") is True
        assert C.verificar_senha(h, "senhaErrada") is False

    def test_senha_nunca_em_texto_plano_no_banco(self, app, db_path):
        criar_usuario(db_path, "joao", "senhaSecretaLonga123")
        row = sqlite3.connect(db_path).execute(
            "SELECT senha_hash FROM usuarios WHERE usuario='joao'"
        ).fetchone()
        guardado = row[0]
        assert "senhaSecretaLonga123" not in guardado
        assert guardado.startswith("$argon2id$")


# ===========================================================================
# IA-5(1) : politica de senha NIST 800-63B
# ===========================================================================
class TestIA5_1_PoliticaSenha:
    def test_rejeita_curta(self):
        ok, _ = C.validar_politica_senha("abc123")  # 6 < 8
        assert ok is False

    def test_rejeita_senha_vazada(self):
        ok, msg = C.validar_politica_senha("senha123")  # consta na lista
        assert ok is False
        assert "vazamento" in msg.lower()

    def test_aceita_passphrase_sem_complexidade(self):
        # Longa, so minusculas, sem simbolo: NIST NAO exige complexidade.
        ok, _ = C.validar_politica_senha("cavalo bateria grampo correto")
        assert ok is True

    def test_registro_pela_web_rejeita_senha_vazada(self, client, db_path):
        # "senha123" tem 8 chars (passa no comprimento) e consta na lista.
        r = client.post("/registrar",
                        data={"usuario": "novo", "senha": "senha123"})
        assert b"vazamento" in r.data.lower()
        # Usuario NAO deve ter sido criado.
        n = sqlite3.connect(db_path).execute(
            "SELECT COUNT(*) FROM usuarios WHERE usuario='novo'"
        ).fetchone()[0]
        assert n == 0


# ===========================================================================
# IA-2(1) : MFA via TOTP
# ===========================================================================
class TestIA2_1_MFA:
    def test_totp_valido_e_invalido(self):
        segredo = C.gerar_segredo_totp()
        codigo = pyotp.TOTP(segredo).now()
        assert C.verificar_totp(segredo, codigo) is True
        assert C.verificar_totp(segredo, "000000") is False

    def test_qr_code_gerado(self):
        qr = C.gerar_qr_base64("alice", C.gerar_segredo_totp())
        assert qr.startswith("data:image/png;base64,")

    def test_login_com_senha_mas_sem_mfa_nao_autentica(self, client, db_path):
        segredo = C.gerar_segredo_totp()
        criar_usuario(db_path, "bob", "SenhaForteDoBob#1", mfa=True,
                      segredo=segredo)
        # Senha correta leva ao desafio MFA, nao ao painel.
        r = client.post("/login",
                        data={"usuario": "bob", "senha": "SenhaForteDoBob#1"},
                        follow_redirects=True)
        assert "duas etapas" in r.get_data(as_text=True).lower()
        # Ainda nao esta autenticado de fato.
        painel = client.get("/", follow_redirects=True)
        assert "duas etapas" in painel.get_data(as_text=True).lower() or \
               "login" in painel.get_data(as_text=True).lower()

    def test_login_completo_com_mfa(self, client, db_path):
        segredo = C.gerar_segredo_totp()
        criar_usuario(db_path, "carol", "SenhaForteDaCarol#1", mfa=True,
                      segredo=segredo)
        client.post("/login",
                   data={"usuario": "carol", "senha": "SenhaForteDaCarol#1"})
        codigo = pyotp.TOTP(segredo).now()
        r = client.post("/mfa", data={"codigo": codigo}, follow_redirects=True)
        assert "bem-vindo" in r.get_data(as_text=True).lower()


# ===========================================================================
# AC-7 : bloqueio apos N tentativas + backoff
# ===========================================================================
class TestAC7_Lockout:
    def test_bloqueia_na_enesima_tentativa(self, conn):
        bloqueio_final = 0
        for _ in range(C.MAX_TENTATIVAS):
            _, bloqueio_final = C.registrar_falha(conn, "vitima")
        assert bloqueio_final > 0, "deve bloquear ao atingir MAX_TENTATIVAS"
        bloqueado, restante = C.esta_bloqueado(conn, "vitima")
        assert bloqueado is True and restante > 0

    def test_backoff_exponencial(self, conn):
        # 1a janela de bloqueio
        for _ in range(C.MAX_TENTATIVAS):
            _, b1 = C.registrar_falha(conn, "alvo")
        # expira o bloqueio manualmente para simular a proxima rodada
        conn.execute("UPDATE tentativas SET bloqueado_ate=0 WHERE usuario='alvo'")
        conn.commit()
        for _ in range(C.MAX_TENTATIVAS):
            _, b2 = C.registrar_falha(conn, "alvo")
        assert b2 > b1, "o tempo de bloqueio deve crescer (backoff)"

    def test_reset_apos_sucesso(self, conn):
        for _ in range(C.MAX_TENTATIVAS - 1):
            C.registrar_falha(conn, "dave")
        C.resetar_tentativas(conn, "dave")
        bloqueado, _ = C.esta_bloqueado(conn, "dave")
        assert bloqueado is False

    def test_sexta_tentativa_bloqueada_pela_web(self, client, db_path):
        criar_usuario(db_path, "alvoweb", "SenhaForteWeb#1")
        for _ in range(C.MAX_TENTATIVAS):
            client.post("/login",
                       data={"usuario": "alvoweb", "senha": "errada"})
        # Proxima tentativa (mesmo com senha certa) deve estar bloqueada.
        r = client.post("/login",
                       data={"usuario": "alvoweb", "senha": "SenhaForteWeb#1"})
        assert "bloquead" in r.get_data(as_text=True).lower()


# ===========================================================================
# AU-2 / AU-6 : log de eventos + revisao
# ===========================================================================
class TestAU2_AU6_Logging:
    def test_evento_tem_campos_estruturados(self, log_tmp):
        reg = C.registrar_evento("LOGIN_SUCESSO", "eve", "1.2.3.4", "teste")
        for campo in ("timestamp", "tipo", "usuario", "ip", "detalhe"):
            assert campo in reg

    def test_login_falha_e_registrado(self, client, log_tmp, db_path):
        criar_usuario(db_path, "frank", "SenhaForteFrank#1")
        client.post("/login", data={"usuario": "frank", "senha": "errada"})
        eventos = C.revisar_eventos(log_tmp, tipo="LOGIN_FALHA")
        assert any(e["usuario"] == "frank" for e in eventos)

    def test_revisao_filtra_por_tipo(self, log_tmp):
        C.registrar_evento("LOGIN_SUCESSO", "u1")
        C.registrar_evento("LOGIN_FALHA", "u2")
        C.registrar_evento("LOGIN_FALHA", "u3")
        falhas = C.revisar_eventos(log_tmp, tipo="LOGIN_FALHA")
        assert len(falhas) == 2

    def test_resumo_conta_por_tipo(self, log_tmp):
        C.registrar_evento("LOGIN_FALHA", "u1")
        C.registrar_evento("LOGIN_FALHA", "u2")
        C.registrar_evento("LOCKOUT_ACIONADO", "u2")
        resumo = C.resumo_eventos(log_tmp)
        assert resumo["LOGIN_FALHA"] == 2 and resumo["LOCKOUT_ACIONADO"] == 1


# ===========================================================================
# SC-23 : gestao de sessao
# ===========================================================================
class TestSC23_Sessao:
    def _login_sem_mfa(self, client, db_path, usuario="grace"):
        criar_usuario(db_path, usuario, "SenhaForteGrace#1")
        return client.post("/login",
                          data={"usuario": usuario, "senha": "SenhaForteGrace#1"})

    def test_cookie_tem_flags_de_seguranca(self, client, db_path):
        r = self._login_sem_mfa(client, db_path)
        set_cookie = r.headers.get("Set-Cookie", "")
        assert "HttpOnly" in set_cookie
        assert "Secure" in set_cookie
        assert "SameSite=Lax" in set_cookie

    def test_regeneracao_de_sid_no_login(self, client, db_path):
        # sid antes do login (fixado artificialmente)
        with client.session_transaction() as sess:
            sess["sid"] = "sid-antigo-fixado"
        self._login_sem_mfa(client, db_path)
        with client.session_transaction() as sess:
            assert sess.get("sid") not in (None, "sid-antigo-fixado")

    def test_timeout_de_inatividade(self, client, db_path, monkeypatch):
        self._login_sem_mfa(client, db_path)
        # Simula inatividade colocando a ultima atividade no passado distante.
        with client.session_transaction() as sess:
            sess["ultima_atividade"] = time.time() - 10_000
        r = client.get("/", follow_redirects=True)
        # Deve ter sido deslogado (volta ao login).
        assert "login" in r.get_data(as_text=True).lower()
        with client.session_transaction() as sess:
            assert sess.get("usuario") is None

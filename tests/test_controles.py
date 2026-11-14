"""
Testes automatizados que COMPROVAM cada controle, incluindo os requisitos
novos do Apendice A do relatorio (REQ-*). Rode com:
    python -m pytest -v tests/
"""
import time

import pyotp
import pytest
from argon2 import PasswordHasher

import controles as C
from conftest import criar_usuario, abrir, sid_atual


# ===========================================================================
# C1 — IA-5 : hash de senha com Argon2id
# ===========================================================================
class TestIA5_HashArgon2:
    def test_hash_usa_argon2id(self):
        assert C.hash_senha("umaSenhaQualquer123").startswith("$argon2id$")

    def test_salt_unico_por_hash(self):
        assert C.hash_senha("mesmaSenha123") != C.hash_senha("mesmaSenha123")

    def test_verificacao_correta_e_incorreta(self):
        h = C.hash_senha("senhaCorreta#2024")
        assert C.verificar_senha(h, "senhaCorreta#2024") is True
        assert C.verificar_senha(h, "senhaErrada") is False

    def test_senha_nunca_em_texto_plano_no_banco(self, app, db_path):
        criar_usuario(db_path, "joao", "senhaSecretaLonga123")
        row = abrir(db_path).execute(
            "SELECT senha_hash FROM usuarios WHERE usuario='joao'").fetchone()
        assert "senhaSecretaLonga123" not in row[0]
        assert row[0].startswith("$argon2id$")

    def test_parametros_argon2(self):
        # REQ-IA5-02: m=65536, t=3, p=4 visiveis no proprio hash PHC.
        p = C.parametros_do_hash(C.hash_senha("qualquerSenha123"))
        assert p.get("m") == "65536" and p.get("t") == "3" and p.get("p") == "4"

    def test_tempo_usuario_inexistente(self):
        # REQ-IA5-05: usuario inexistente ainda roda verificacao (hash ficticio).
        assert C.HASH_FICTICIO.startswith("$argon2id$")
        assert C.verificar_usuario(None, "qualquerCoisa") is False

    def test_rehash_detecta_parametros_fracos(self):
        # REQ-IA5-06
        fraco = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("x")
        assert C.precisa_rehash(fraco) is True
        assert C.precisa_rehash(C.hash_senha("x")) is False


# ===========================================================================
# C2 — IA-5(1) : politica de senha NIST 800-63B
# ===========================================================================
class TestIA5_1_PoliticaSenha:
    def test_rejeita_curta(self):
        assert C.validar_politica_senha("abc123")[0] is False

    def test_rejeita_senha_vazada(self):
        ok, msg = C.validar_politica_senha("senha123")
        assert ok is False and "vazamento" in msg.lower()

    def test_aceita_passphrase_sem_complexidade(self):
        assert C.validar_politica_senha("cavalo bateria grampo correto")[0] is True

    def test_aceita_unicode_e_espacos(self):
        # REQ-IA51-02
        assert C.validar_politica_senha("caminho do café com açúcar ☕")[0] is True

    def test_rejeita_longa_demais(self):
        assert C.validar_politica_senha("a" * 129)[0] is False

    def test_rejeita_contextual(self):
        # REQ-IA51-04: senha igual ao nome de usuario e rejeitada.
        assert C.validar_politica_senha("meuusuario", usuario="meuusuario")[0] is False

    def test_registro_pela_web_rejeita_senha_vazada(self, client, db_path):
        r = client.post("/registro", data={"usuario": "novo", "senha": "senha123"})
        assert b"vazamento" in r.data.lower()
        n = abrir(db_path).execute(
            "SELECT COUNT(*) FROM usuarios WHERE usuario='novo'").fetchone()[0]
        assert n == 0

    def test_evento_politica_registrado(self, client, log_tmp):
        # REQ-IA51-08
        client.post("/registro", data={"usuario": "novo2", "senha": "123456"})
        evs = C.revisar_eventos(log_tmp, tipo="SENHA_REJEITADA_POLITICA")
        assert any(e["usuario"] == "novo2" for e in evs)


# ===========================================================================
# C3 — IA-2(1)/(2)/(8) : MFA via TOTP
# ===========================================================================
class TestIA2_MFA:
    def test_totp_valido_e_invalido(self):
        seg = C.gerar_segredo_totp()
        assert C.verificar_totp(seg, pyotp.TOTP(seg).now()) is True
        assert C.verificar_totp(seg, "000000") is False

    def test_qr_code_gerado(self):
        qr = C.gerar_qr_base64("alice", C.gerar_segredo_totp())
        assert qr.startswith("data:image/png;base64,")

    def test_janela_totp(self):
        # REQ-IA2-03: codigo de 2 passos atras (fora de +/-1) e rejeitado.
        seg = C.gerar_segredo_totp()
        assert C.verificar_totp(seg, pyotp.TOTP(seg).now()) is True
        antigo = pyotp.TOTP(seg).at(time.time() - 60)
        assert C.verificar_totp(seg, antigo) is False

    def test_segredo_cifrado_em_repouso(self, monkeypatch):
        # REQ-IA2-08 (DEVERIA)
        from cryptography.fernet import Fernet
        monkeypatch.setattr(C, "CHAVE_SEGREDOS", Fernet.generate_key().decode())
        cif = C.cifrar_segredo("JBSWY3DPEHPK3PXP")
        assert cif.startswith("enc:") and "JBSWY3DPEHPK3PXP" not in cif
        assert C.decifrar_segredo(cif) == "JBSWY3DPEHPK3PXP"

    def test_login_com_senha_mas_sem_mfa_nao_autentica(self, client, db_path):
        seg = C.gerar_segredo_totp()
        criar_usuario(db_path, "bob", "SenhaForteDoBob#1", mfa=True, segredo=seg)
        r = client.post("/login", data={"usuario": "bob", "senha": "SenhaForteDoBob#1"},
                        follow_redirects=True)
        assert "duas etapas" in r.get_data(as_text=True).lower()
        painel = client.get("/painel", follow_redirects=True)
        assert "bem-vindo" not in painel.get_data(as_text=True).lower()

    def test_login_completo_com_mfa(self, client, db_path):
        seg = C.gerar_segredo_totp()
        criar_usuario(db_path, "carol", "SenhaForteDaCarol#1", mfa=True, segredo=seg)
        client.post("/login", data={"usuario": "carol", "senha": "SenhaForteDaCarol#1"})
        r = client.post("/mfa", data={"codigo": pyotp.TOTP(seg).now()},
                        follow_redirects=True)
        assert "bem-vindo" in r.get_data(as_text=True).lower()

    def test_anti_replay_totp(self, client, db_path):
        # REQ-IA2-06: reapresentar o mesmo codigo nao autentica de novo.
        seg = C.gerar_segredo_totp()
        criar_usuario(db_path, "rep", "SenhaForteRep#1", mfa=True, segredo=seg)
        codigo = pyotp.TOTP(seg).now()
        client.post("/login", data={"usuario": "rep", "senha": "SenhaForteRep#1"})
        r1 = client.post("/mfa", data={"codigo": codigo}, follow_redirects=True)
        assert "bem-vindo" in r1.get_data(as_text=True).lower()
        client.get("/logout")
        client.post("/login", data={"usuario": "rep", "senha": "SenhaForteRep#1"})
        r2 = client.post("/mfa", data={"codigo": codigo}, follow_redirects=True)
        assert "bem-vindo" not in r2.get_data(as_text=True).lower()

    def test_pre_auth_expira(self, client, db_path):
        # REQ-IA2-05: estado pre-autenticado expira (5 min).
        seg = C.gerar_segredo_totp()
        criar_usuario(db_path, "exp", "SenhaForteExp#1", mfa=True, segredo=seg)
        client.post("/login", data={"usuario": "exp", "senha": "SenhaForteExp#1"})
        db = abrir(db_path)
        db.execute("UPDATE sessoes SET criada_em = ? WHERE usuario='exp'",
                   (time.time() - 10_000,))
        db.commit()
        r = client.post("/mfa", data={"codigo": pyotp.TOTP(seg).now()},
                        follow_redirects=True)
        assert "bem-vindo" not in r.get_data(as_text=True).lower()

    def test_falha_mfa_conta_para_bloqueio(self, client, db_path):
        # REQ-IA2-07
        seg = C.gerar_segredo_totp()
        criar_usuario(db_path, "mf", "SenhaForteMf#1", mfa=True, segredo=seg)
        client.post("/login", data={"usuario": "mf", "senha": "SenhaForteMf#1"})
        for _ in range(C.MAX_TENTATIVAS):
            client.post("/mfa", data={"codigo": "000000"})
        bloqueado, _ = C.esta_bloqueado(abrir(db_path), "mf")
        assert bloqueado is True


# ===========================================================================
# C4 — AC-7 : bloqueio + recuo exponencial
# ===========================================================================
class TestAC7_Lockout:
    def test_bloqueia_na_enesima_tentativa(self, conn):
        b = 0
        for _ in range(C.MAX_TENTATIVAS):
            _, b = C.registrar_falha(conn, "vitima")
        assert b > 0
        bloqueado, restante = C.esta_bloqueado(conn, "vitima")
        assert bloqueado is True and restante > 0

    def test_backoff_exponencial(self, conn):
        for _ in range(C.MAX_TENTATIVAS):
            _, b1 = C.registrar_falha(conn, "alvo")
        conn.execute("UPDATE tentativas SET bloqueado_ate=0 WHERE usuario='alvo'")
        conn.commit()
        for _ in range(C.MAX_TENTATIVAS):
            _, b2 = C.registrar_falha(conn, "alvo")
        assert b2 > b1

    def test_teto_do_backoff(self, conn):
        # REQ-AC7-02: bloqueio nunca excede o teto.
        maior = 0
        for _ in range(8):
            for _ in range(C.MAX_TENTATIVAS):
                _, b = C.registrar_falha(conn, "u")
            maior = max(maior, b)
            conn.execute("UPDATE tentativas SET bloqueado_ate=0 WHERE usuario='u'")
            conn.commit()
        assert maior <= C.BLOQUEIO_MAX_SEG

    def test_reset_apos_sucesso(self, conn):
        for _ in range(C.MAX_TENTATIVAS - 1):
            C.registrar_falha(conn, "dave")
        C.resetar_tentativas(conn, "dave")
        assert C.esta_bloqueado(conn, "dave")[0] is False

    def test_sexta_tentativa_bloqueada_pela_web(self, client, db_path):
        criar_usuario(db_path, "alvoweb", "SenhaForteWeb#1")
        for _ in range(C.MAX_TENTATIVAS):
            client.post("/login", data={"usuario": "alvoweb", "senha": "errada"})
        r = client.post("/login", data={"usuario": "alvoweb", "senha": "SenhaForteWeb#1"})
        assert r.status_code == 429
        assert "bloquead" in r.get_data(as_text=True).lower()

    def test_senha_correta_durante_bloqueio(self, client, db_path):
        # REQ-AC7-03: durante o bloqueio, senha correta e recusada (429).
        criar_usuario(db_path, "blk", "SenhaForteBlk#1")
        for _ in range(C.MAX_TENTATIVAS):
            client.post("/login", data={"usuario": "blk", "senha": "errada"})
        r = client.post("/login", data={"usuario": "blk", "senha": "SenhaForteBlk#1"})
        assert r.status_code == 429

    def test_evento_login_bloqueado_sem_mexer_contador(self, client, db_path, log_tmp):
        # REQ-AC7-04
        criar_usuario(db_path, "blk2", "SenhaForteBlk2#1")
        for _ in range(C.MAX_TENTATIVAS):
            client.post("/login", data={"usuario": "blk2", "senha": "errada"})
        client.post("/login", data={"usuario": "blk2", "senha": "SenhaForteBlk2#1"})
        assert C.revisar_eventos(log_tmp, tipo="LOGIN_BLOQUEADO", usuario="blk2")
        falhas = abrir(db_path).execute(
            "SELECT falhas FROM tentativas WHERE usuario='blk2'").fetchone()[0]
        assert falhas == 0  # zerado no lockout e nao incrementado durante o bloqueio

    def test_bloqueio_usuario_inexistente(self, client, db_path):
        # REQ-AC7-06
        for _ in range(C.MAX_TENTATIVAS):
            client.post("/login", data={"usuario": "naoexiste", "senha": "x"})
        assert C.esta_bloqueado(abrir(db_path), "naoexiste")[0] is True


# ===========================================================================
# C5 — AU-2/AU-3/AU-6/AU-8 : log + revisao
# ===========================================================================
class TestAU_Logging:
    def test_evento_tem_campos_estruturados(self, log_tmp):
        reg = C.registrar_evento("LOGIN_SUCESSO", "eve", "1.2.3.4", "Mozilla", "t")
        for campo in ("timestamp", "tipo", "usuario", "ip", "user_agent", "detalhe"):
            assert campo in reg

    def test_catalogo_de_eventos(self):
        # REQ-AU-01
        esperados = {"CADASTRO", "SENHA_REJEITADA_POLITICA", "LOGIN_FALHA",
                     "LOGIN_SENHA_OK", "MFA_FALHA", "LOGIN_SUCESSO",
                     "LOCKOUT_ACIONADO", "LOGIN_BLOQUEADO", "MFA_ATIVADO",
                     "LOGOUT", "SESSAO_EXPIRADA"}
        assert esperados <= C.EVENTOS

    def test_login_falha_e_registrado(self, client, log_tmp, db_path):
        criar_usuario(db_path, "frank", "SenhaForteFrank#1")
        client.post("/login", data={"usuario": "frank", "senha": "errada"})
        assert any(e["usuario"] == "frank"
                   for e in C.revisar_eventos(log_tmp, tipo="LOGIN_FALHA"))

    def test_log_sem_senha(self, client, log_tmp, db_path):
        # REQ-AU-03
        criar_usuario(db_path, "gina", "SenhaForteGina#1")
        client.post("/login", data={"usuario": "gina", "senha": "SENHAULTRASECRETA42"})
        conteudo = open(log_tmp, encoding="utf-8").read()
        assert "SENHAULTRASECRETA42" not in conteudo

    def test_revisao_filtra_por_tipo(self, log_tmp):
        C.registrar_evento("LOGIN_SUCESSO", "u1")
        C.registrar_evento("LOGIN_FALHA", "u2")
        C.registrar_evento("LOGIN_FALHA", "u3")
        assert len(C.revisar_eventos(log_tmp, tipo="LOGIN_FALHA")) == 2

    def test_resumo_conta_por_tipo(self, log_tmp):
        C.registrar_evento("LOGIN_FALHA", "u1")
        C.registrar_evento("LOGIN_FALHA", "u2")
        C.registrar_evento("LOCKOUT_ACIONADO", "u2")
        por_tipo = C.resumo_eventos(log_tmp)["por_tipo"]
        assert por_tipo["LOGIN_FALHA"] == 2 and por_tipo["LOCKOUT_ACIONADO"] == 1

    def test_alerta_r1_forca_bruta(self, log_tmp):
        # REQ-AU-06
        for _ in range(5):
            C.registrar_evento("LOGIN_FALHA", "alvoR1", "1.1.1.1")
        alertas = C.resumo_eventos(log_tmp)["alertas"]
        assert any(a["regra"] == "R1" for a in alertas)

    def test_alerta_r2_stuffing(self, log_tmp):
        # REQ-AU-07
        for i in range(10):
            C.registrar_evento("LOGIN_FALHA", f"conta{i}", "9.9.9.9")
        alertas = C.resumo_eventos(log_tmp)["alertas"]
        assert any(a["regra"] == "R2" for a in alertas)


# ===========================================================================
# C6 — SC-23 : sessao no lado do servidor
# ===========================================================================
class TestSC23_Sessao:
    def _login(self, client, db_path, usuario="grace"):
        criar_usuario(db_path, usuario, "SenhaForteGrace#1")
        return client.post("/login",
                           data={"usuario": usuario, "senha": "SenhaForteGrace#1"})

    def test_cookie_tem_flags_de_seguranca(self, client, db_path):
        sc = self._login(client, db_path).headers.get("Set-Cookie", "")
        assert "HttpOnly" in sc and "Secure" in sc and "SameSite=Lax" in sc

    def test_sessao_no_servidor(self, client, db_path):
        # REQ-SC23-02
        self._login(client, db_path)
        sid = sid_atual(client)
        row = abrir(db_path).execute(
            "SELECT autenticado FROM sessoes WHERE sid=?", (sid,)).fetchone()
        assert row is not None and row[0] == 1

    def test_entropia_do_sid(self, client, db_path):
        # REQ-SC23-03: token_urlsafe(32) -> >= 43 caracteres (256 bits).
        self._login(client, db_path)
        assert len(sid_atual(client)) >= 43

    def test_regeneracao_de_sid_no_login(self, client, db_path):
        with client.session_transaction() as s:
            s["sid"] = "sid-antigo-fixado"
        self._login(client, db_path)
        assert sid_atual(client) not in (None, "sid-antigo-fixado")

    def test_fixacao_de_sessao(self, client, db_path):
        # REQ-SC23-07: um sid pre-definido nao vira autenticado.
        with client.session_transaction() as s:
            s["sid"] = "sid-do-atacante"
        self._login(client, db_path)
        n = abrir(db_path).execute(
            "SELECT COUNT(*) FROM sessoes WHERE sid='sid-do-atacante'").fetchone()[0]
        assert n == 0

    def test_timeout_de_inatividade(self, client, db_path):
        self._login(client, db_path)
        db = abrir(db_path)
        db.execute("UPDATE sessoes SET ultimo_acesso=? WHERE sid=?",
                   (time.time() - 10_000, sid_atual(client)))
        db.commit()
        r = client.get("/painel", follow_redirects=True)
        assert "bem-vindo" not in r.get_data(as_text=True).lower()

    def test_expiracao_absoluta(self, client, db_path):
        # REQ-SC23-05
        self._login(client, db_path)
        db = abrir(db_path)
        db.execute("UPDATE sessoes SET criada_em=? WHERE sid=?",
                   (time.time() - 100_000, sid_atual(client)))
        db.commit()
        r = client.get("/painel", follow_redirects=True)
        assert "bem-vindo" not in r.get_data(as_text=True).lower()

    def test_logout_invalida_sessao(self, client, db_path):
        # REQ-SC23-06
        self._login(client, db_path)
        sid = sid_atual(client)
        client.get("/logout")
        n = abrir(db_path).execute(
            "SELECT COUNT(*) FROM sessoes WHERE sid=?", (sid,)).fetchone()[0]
        assert n == 0
        r = client.get("/painel", follow_redirects=True)
        assert "bem-vindo" not in r.get_data(as_text=True).lower()

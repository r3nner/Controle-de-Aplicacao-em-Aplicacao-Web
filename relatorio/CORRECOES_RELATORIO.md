# Correções do relatório G11 — texto pronto para colar no Google Doc

> Gerado a partir das evidências reais coletadas por
> `scripts/coletar_evidencias.py --modo docker` nesta sessão. Cada número abaixo
> cita **de qual arquivo de `evidencias/`** ele saiu. Datas/horas das evidências:
> ver `git log` e o cabeçalho `# executado: …` dentro de cada `.txt`.

Ambiente das evidências: **Docker**, container `app_segura`, `platform linux`,
Python 3.12.16; atacante dentro do container alcançando `host.docker.internal`.

---

## (a) Tabela: número antigo → número novo

Cole substituindo a tabela de números do relatório (seções 3/4).

| Métrica | Valor antigo (relatório) | Valor novo (evidência) | Arquivo de evidência |
|---|---|---|---|
| Testes automatizados aprovados | 23 | **49** (`platform linux`, 4,32 s) | `pytest_saida.txt` |
| Força bruta na **vulnerável** | comprometida | **COMPROMETIDO** com `senha123` na 9ª senha; 0,08 s | `ataque_vuln_bruteforce.txt` |
| Força bruta na **segura** — bloqueio | "bloqueada na 1ª tentativa" | **5 falhas + BLOQUEADO (HTTP 429) na 6ª** tentativa; 0,29 s | `ataque_segura_bruteforce.txt` |
| Credential stuffing — pares testados | 1 par | **52 pares** (27 contas distintas) | `ataque_segura_stuffing.txt` |
| Credential stuffing — contas comprometidas | 0 de 1 | **0 de 52** | `ataque_segura_stuffing.txt` |
| Parede de MFA (senha correta) | descrição manual | **MFA_REQUERIDO** (senha correta, acesso barrado) | `mfa_wall.txt` |
| Revisão do log — alerta | — | **R2 STUFFING_SPRAYING** (IP `172.20.0.1`, 27 contas) | `revisao_log.txt` |
| Hash — razão de custo offline | — | **MD5 ≈ 121.000× mais rápido** que Argon2id (~5,1 ordens de grandeza) | `benchmark_hash.txt` |

> Observação: o relatório antigo e o antigo `instructions.md` divergiam (um dizia
> "1ª tentativa", o outro "5ª"). O valor correto, medido, é **bloqueio na 6ª
> tentativa** (5 falhas contabilizadas; a 6ª requisição já recebe HTTP 429). Os
> 49 testes incluem 1 teste novo (anti-spoofing de `X-Forwarded-For`, item da
> correção de segurança); os 48 anteriores continuam passando.

---

## (b) Nova subseção 2.5 — Hipóteses (H1–H6)

Ameaças referenciadas (defina-as em 2.4, ver bloco (c) para o modelo T1–T9).

**H1 — Custo de hash (C1 · IA-5 · ameaça T3, quebra offline).**
*O Argon2id reduz em ≥ 4 ordens de grandeza a taxa de tentativas offline em
relação ao MD5 sem salt.* Critério: razão de hashes/s ≥ 10⁴.
**Resultado: confirmada** — MD5 2.894.799 h/s × Argon2id 23,92 h/s = razão
**121.015× (~5,1 ordens)** (`benchmark_hash.txt`).

**H2 — Bloqueio online (C4 · AC-7 · ameaça T4, força bruta online).**
*O lockout após 5 falhas interrompe a força bruta antes de esgotar a wordlist,
respondendo HTTP 429.* Critério: ataque interrompido com 429 em ≤ `N+1`
tentativas.
**Resultado: confirmada** — 5 falhas e **BLOQUEADO (429) na 6ª**
(`ataque_segura_bruteforce.txt`).

**H3 — Segundo fator (C3 · IA-2 · ameaças T1/T5, roubo/reuso de senha).**
*Mesmo com a senha correta, o atacante não obtém sessão sem o TOTP.* Critério: a
senha válida leva a `MFA_REQUERIDO`, nunca ao painel.
**Resultado: confirmada** — senha correta do alvo → **MFA_REQUERIDO**
(`mfa_wall.txt`).

**H4 — Política + lista de bloqueio (C2 · IA-5(1) · ameaças T2/T5).**
*Senhas vazadas/reutilizadas não comprometem contas.* Critério: 0 contas
comprometidas no stuffing.
**Resultado: confirmada** — **0 de 52** (`ataque_segura_stuffing.txt`). *(Defesa
em profundidade: o 0 decorre da senha correta do alvo não estar na lista vazada
e, ainda que estivesse, do MFA/lockout; ver nota da Tabela 5.)*

**H5 — Detecção (C5 · AU-6 · ameaças T6/T7, spraying e ausência de trilha).**
*A revisão do log detecta o ataque distribuído a partir do IP real.* Critério:
alerta R2 disparado com o IP de origem verdadeiro.
**Resultado: confirmada** — **R2 STUFFING_SPRAYING**, IP `172.20.0.1`
(gateway Docker, não um cabeçalho forjável), 27 contas (`revisao_log.txt`).

**H6 — Sessão (C6 · SC-23/AC-12 · ameaças T8/T9, sequestro/fixação).**
*A sessão server-side com `Secure/HttpOnly/SameSite`, regeneração de SID e
expiração impede sequestro e fixação.* Critério: flags presentes, SID
regenerado, logout e timeouts invalidam a sessão no servidor.
**Resultado: parcialmente confirmada** — provada pelos testes SC-23 (flags,
fixação, inatividade, absoluta, logout) em `pytest_saida.txt`; falta a
demonstração **HTTPS fim-a-fim** com `Secure=true` em runtime (item opcional,
ver nota de rodapé da Tabela 5).

---

## (c) Tabela de controles (corrigida)

| Controle | NIST SP 800-53 Rev. 5 | ISO/IEC 27001:2022 Anexo A | Ameaças mitigadas |
|---|---|---|---|
| **C1** Hash Argon2id (RFC 9106; NFKC, pepper, hash fictício, re-hash) | IA-5; IA-5(1) | A.5.17, A.8.5, A.8.24 | T3 |
| **C2** Política de senha (NIST 800-63B; lista ≥10k + contexto) | IA-5(1) | A.5.17 | T2, T5 |
| **C3** MFA TOTP (duas etapas, anti-replay, segredo cifrado) | IA-2(1), IA-2(2), **IA-2(8)** | A.8.5 | T1, T5 |
| **C4** Lockout + recuo exponencial (HTTP 429; inclui falhas de MFA) | AC-7 | A.8.5 | T4, T6 |
| **C5** Log estruturado + revisão (11 eventos; regras R1/R2) | AU-2, AU-3, AU-6, AU-8 | A.8.15, A.8.16, A.8.17 | T6, T7 |
| **C6** Sessão server-side (SID 256 bits, regeneração, inatividade/absoluta, invalidação no logout) | SC-23, SC-23(1), SC-23(3), **AC-12** | A.8.5, A.8.24, A.8.26 | T8, T9 |

**Modelo de ameaças (T1–T9), para a subseção 2.4:**

| # | Ameaça |
|---|---|
| T1 | Roubo/phishing de credencial (senha legítima nas mãos do atacante) |
| T2 | Senha fraca, comum ou contextual (adivinhação) |
| T3 | Quebra **offline** do hash após vazamento do banco |
| T4 | Força bruta **online** contra `/login` |
| T5 | Credential stuffing (reuso de senha entre serviços) |
| T6 | Password spraying (uma senha, muitas contas) |
| T7 | Ausência de trilha de auditoria / não-detecção |
| T8 | Sequestro ou fixação de sessão |
| T9 | Sessão sem expiração / logout inefetivo |

---

## (d) Tabela 5 — Resultados (reconstruída das evidências)

| # | Ensaio | Controle(s) | Resultado medido | Evidência |
|---|---|---|---|---|
| 1 | Testes automatizados | C1–C6 | **49 aprovados** (`platform linux`) | `captura1_pytest.png` |
| 2 | Força bruta — vulnerável | (linha de base) | **COMPROMETIDO** (`senha123`, 9ª) | `captura2_bruteforce_vuln.png` |
| 3 | Força bruta — segura | C4 (AC-7) | **BLOQUEADO na 6ª** (HTTP 429) | `captura3_bruteforce_segura.png` |
| 4 | Credential stuffing — segura | C2, C3, C4 | **0 de 52** comprometidas ¹ | `captura4_stuffing_segura.png` |
| 5 | Parede de MFA (senha correta) | C3 (IA-2) | **MFA_REQUERIDO** (acesso barrado) | `captura6_mfa_wall.png` |
| 6 | Log do servidor | C5 (AU-3) | 52 `LOGIN_FALHA` + 1 `LOGIN_SENHA_OK`; IP real no registro | `captura5_log_servidor.png` |
| 7 | Revisão do log | C5 (AU-6) | **R2 STUFFING_SPRAYING** (27 contas, 1 IP) | `captura7_revisao.png` |
| 8 | Benchmark de hash | C1 (IA-5) | MD5 ≈ **121.000×** mais rápido que Argon2id | `captura8_benchmark.png` |

**Notas de rodapé:**
¹ "Parcial por construção": o stuffing não compromete nenhuma conta porque (a) a
senha do alvo não está na lista vazada e (b) ainda que uma senha acertasse, o MFA
(C3) e o lockout (C4) barrariam o acesso — defesa em profundidade, não um único
controle.
² O ensaio de força bruta (3) deixa o log com `LOCKOUT_ACIONADO`, mas o passo 5
da coleta **zera o log** antes do stuffing; por isso o log final (6/7) reflete o
stuffing (R2), e a evidência do lockout fica na captura 3. Isso é intencional e
está documentado em `scripts/coletar_evidencias.py`.
³ **H6 parcial:** as flags `Secure/HttpOnly/SameSite` são comprovadas por teste,
mas a demonstração HTTPS fim-a-fim em runtime não foi executada neste ambiente.

---

## (e) Legendas novas das figuras (honestas quanto à origem)

Use estas legendas (todas as saídas vêm do mesmo coletor, em modo Docker):

- **Figura (captura 1):** "Saída de `pytest -v` registrada por
  `scripts/coletar_evidencias.py` (modo docker, `platform linux`) e renderizada
  em imagem — 49 testes aprovados."
- **Figura (captura 2):** "Força bruta contra a aplicação **vulnerável**
  (`host.docker.internal:5000`): comprometimento total com `senha123`. Saída de
  terminal registrada pelo coletor (modo docker) e renderizada em imagem."
- **Figura (captura 3):** "Força bruta contra a aplicação **segura**
  (`:5001`): 5 falhas e bloqueio (HTTP 429) na 6ª tentativa (AC-7). Registrada
  pelo coletor (modo docker)."
- **Figura (captura 4):** "Credential stuffing com 52 pares vazados: 0 contas
  comprometidas. Registrada pelo coletor (modo docker)."
- **Figura (captura 5 / arquivo captura6_mfa_wall):** "Parede de MFA: a senha
  **correta** do alvo é aceita, mas o acesso para em `MFA_REQUERIDO` (IA-2).
  Saída real do `brute_force.py` registrada pelo coletor (modo docker)."
- **Figura (captura 6 / arquivo captura5_log_servidor):** "Trecho do log de
  autenticação do servidor (JSON Lines); o campo `ip` traz o IP real da conexão
  (`172.20.0.1`), não um cabeçalho forjável. Registrada pelo coletor."
- **Figura (captura 7):** "Revisão do log (AU-6): alerta R2 de
  stuffing/spraying a partir de 27 contas no mesmo IP. Registrada pelo coletor."
- **Figura (captura 8):** "Benchmark MD5 (sem salt) × Argon2id com os parâmetros
  reais dos controles: razão ~121.000× no custo por hash. Registrada pelo
  coletor (modo docker)."

---

## (f) Parágrafos reescritos

### Resumo (abstract)
> Este trabalho seleciona, implementa e **verifica com evidências reais** seis
> controles de autenticação, comparando uma aplicação web vulnerável a uma versão
> endurecida da mesma aplicação. A verificação combina 49 testes automatizados
> (todos aprovados) com ensaios de ataque reprodutíveis — força bruta, credential
> stuffing e uma "parede de MFA" — além de um benchmark de custo de hash. Enquanto
> a versão vulnerável é comprometida por força bruta na 9ª senha testada, a versão
> segura com os controles bloqueia a força bruta na 6ª tentativa (HTTP 429), não
> cede nenhuma das 52 credenciais do stuffing, barra a senha correta no segundo
> fator e tem o ataque distribuído detectado pela revisão do log. *(Use "controles"
> e não "procedimentos de controle".)*

### Seção 1 (introdução — conceitos)
> A **autenticação** responde "quem é você?" e **não** determina privilégios —
> isso é **autorização**, uma etapa posterior. Deve-se distinguir **identificadores**
> (e-mail, CPF, nome de usuário), que apenas nomeiam a conta e podem ser públicos,
> de **credenciais** (senha, segredo TOTP, chave), que provam a identidade e devem
> permanecer secretas. Os controles deste trabalho atuam sobre as credenciais e o
> processo de prova, não sobre a atribuição de permissões.

### Seção 2.3.1 (Argon2id)
> O Argon2id protege o verificador de senha contra o ataque **offline** (T3): se o
> banco vazar, o atacante precisa recomputar o hash para cada tentativa. Com os
> parâmetros RFC 9106 (m=64 MiB, t=3, p=4), o custo por hash medido foi ~41,8 ms
> contra ~0,35 µs do MD5 sem salt — uma razão de ~121.000× (~5,1 ordens de
> grandeza; `benchmark_hash.txt`). Isso **não** acelera nem retarda tentativas
> **online**, que são tratadas pelo lockout (C4); o Argon2id endereça
> especificamente o cenário de vazamento do banco.

### Seção 2.3.4 (lockout + recuo exponencial)
> O comportamento real do AC-7 é: cada falha incrementa um contador; ao atingir
> `MAX_TENTATIVAS` (5) o sistema aplica o bloqueio `min(30·2^k, 900) s` e **zera o
> contador de falhas** (o bloqueio é o "estado", não o contador). O **nível `k`**
> do recuo exponencial só volta a zero após um **login bem-sucedido**
> (`resetar_tentativas`), de modo que ataques repetidos sofrem bloqueios cada vez
> maiores. Falhas de **MFA** contam para o mesmo mecanismo (REQ-IA2-07). Durante o
> bloqueio, mesmo a senha correta é recusada com HTTP 429.

### Seção 2.3.6 (sessão)
> A sessão é **server-side**: o cookie carrega apenas um identificador aleatório de
> 256 bits (`token_urlsafe(32)`), e o estado vive no banco. O SID é **regenerado**
> no login (anti-fixação), e o **logout invalida a sessão no servidor** (remoção da
> linha em `sessoes`), não apenas no cliente — agora coberto pelo teste
> `test_logout_invalida_sessao`. Há expiração por **inatividade** (15 min) e
> **absoluta** (8 h), ambas verificadas por teste.

### Conclusão
> As evidências confirmam **H1–H5** e confirmam **parcialmente H6**: o Argon2id
> eleva o custo offline em ~5 ordens de grandeza (H1); o lockout interrompe a
> força bruta na 6ª tentativa (H2); o MFA barra a senha correta (H3); o stuffing
> não compromete nenhuma das 52 credenciais (H4); e a revisão do log detecta o
> ataque distribuído pelo IP real (H5). H6 fica parcial porque as flags de cookie
> são provadas por teste, mas a demonstração HTTPS fim-a-fim não foi executada
> neste ambiente. *(Remover qualquer menção a "descriptografar o Argon2id": o
> Argon2id é uma função de **hash** unidirecional — não há descriptografia; o que
> se mede é o custo de recomputá-lo por tentativa.)*

### Análise crítica (limitações)
> - **Negação de serviço por conta:** o lockout por conta (AC-7) permite que um
>   atacante que conheça o nome de usuário bloqueie deliberadamente um usuário
>   legítimo (DoS direcionado). Mitigações futuras: desafios (CAPTCHA/prova de
>   trabalho) e bloqueio por IP além de por conta.
> - **Password spraying:** o lockout por conta **não** detém o spraying (uma senha
>   por conta, muitas contas); quem o detecta é a **regra R2** do log (C5), que
>   deve alimentar resposta a incidentes.
> - **Custo sob carga:** cada login custa ~64 MiB de memória (Argon2id); sob alta
>   concorrência isso é um vetor de exaustão de recursos a dimensionar.
> - **Ambiente:** ensaios em laboratório local (containers, HTTP), 1 núcleo; os
>   números absolutos variam com o hardware.
> - **Tamanho da amostra:** wordlist de 12 senhas e 52 pares de stuffing —
>   suficientes para demonstrar os mecanismos, não para estimar taxas de sucesso
>   em escala real.

---

## (g) Citações sugeridas (ABNT autor-data)

Cada referência da lista hoje **não citada** no texto — onde inseri-la:

| Referência | Onde citar (seção) | Forma no texto (ABNT) |
|---|---|---|
| **Biryukov; Dinu; Khovratovich (2016)** — Argon2 | 2.3.1 / H1 | "...função de hash de senha vencedora da PHC (BIRYUKOV; DINU; KHOVRATOVICH, 2016)." |
| **Bonneau et al. (2012)** — quest to replace passwords | 1 / 2.3.3 | "...o equilíbrio entre usabilidade e segurança de esquemas de autenticação (BONNEAU et al., 2012)." |
| **Das et al. (2014)** — reuso de senhas | 2.3.2 / T5 | "...o reuso de senhas entre serviços habilita o credential stuffing (DAS et al., 2014)." |
| **Kelley et al. (2012)** — adivinhação de senhas | 2.3.2 | "...a força de uma senha deve ser medida por resistência a adivinhação (KELLEY et al., 2012)." |
| **Kolšek (2007)** — session fixation | 2.3.6 / T8 | "...a regeneração do identificador no login previne a fixação de sessão (KOLŠEK, 2007)." |
| **M'Raïhi et al.** — HOTP/TOTP (RFC 4226/6238) | 2.3.3 | "...o TOTP deriva um código temporal de um segredo compartilhado (M'RAÏHI et al., 2011)." |
| **Thomas et al. (2017)** — roubo de credenciais | 1 / 2.3.3 | "...vazamentos e phishing alimentam o mercado de credenciais roubadas (THOMAS et al., 2017)." |
| **NIST** — SP 800-63B / SP 800-53 Rev. 5 | 2 / todos os controles | "...conforme as diretrizes de identidade digital (NIST, 2017) e o catálogo de controles (NIST, 2020)." |
| **OWASP** — ASVS / Authentication Cheat Sheet | 2.3.3 / 2.3.6 | "...alinhado às recomendações de verificação de autenticação (OWASP, 2021)." |

> Ajuste os **anos** às entradas exatas da sua lista de referências; mantive o
> sobrenome do 1º autor e "et al." quando há 3+ autores (padrão ABNT autor-data).

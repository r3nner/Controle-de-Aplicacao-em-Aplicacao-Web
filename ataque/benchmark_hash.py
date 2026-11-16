"""
Benchmark de custo de hash: MD5 sem salt (como na app VULNERAVEL) vs Argon2id
com os parametros REAIS de app_segura/controles.py (perfil RFC 9106 low memory:
m=64 MiB, t=3, p=4). Fecha a hipotese H1 do relatorio.

Mede a taxa de hashes/s de cada algoritmo (N repeticoes, usa a MEDIANA para
reduzir ruido), a razao entre as duas taxas e estima o tempo para um atacante
offline testar uma lista de 10.000 senhas em cada caso.

Uso:
    python benchmark_hash.py [--repeticoes N] [--lista 10000]

A saida vai para stdout; o coletor de evidencias (scripts/coletar_evidencias.py)
captura essa saida e grava evidencias/benchmark_hash.txt com cabecalho honesto.
"""
import argparse
import hashlib
import math
import os
import statistics
import sys
import time

# Usa exatamente o PasswordHasher configurado nos controles (nao redefine params).
AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(AQUI), "app_segura"))
import controles as C  # noqa: E402

SENHA = "correta cavalo bateria grampo 91"   # mesma classe de senha do 'alvo'
LISTA_PADRAO = 10_000


def taxa_md5(amostras: int = 400_000) -> float:
    """Hashes MD5 sem salt por segundo (hex digest, como a app vulneravel)."""
    dado = SENHA.encode()
    t0 = time.perf_counter()
    for _ in range(amostras):
        hashlib.md5(dado).hexdigest()
    dt = time.perf_counter() - t0
    return amostras / dt


def tempo_argon2() -> float:
    """Segundos para derivar UM hash Argon2id com os parametros dos controles."""
    t0 = time.perf_counter()
    C._ph.hash(SENHA)
    return time.perf_counter() - t0


def mediana_taxa_md5(repeticoes: int) -> float:
    return statistics.median(taxa_md5() for _ in range(repeticoes))


def mediana_tempo_argon2(repeticoes: int) -> float:
    # descarta a 1a medicao (aquecimento de alocacao de memoria)
    tempos = [tempo_argon2() for _ in range(repeticoes + 1)]
    return statistics.median(tempos[1:])


def mil(n) -> str:
    """Formata inteiro com ponto como separador de milhar (pt-BR)."""
    return f"{n:,.0f}".replace(",", ".")


def fmt_tempo(seg: float) -> str:
    if seg < 1e-3:
        return f"{seg * 1e6:.1f} us"
    if seg < 1:
        return f"{seg * 1e3:.1f} ms"
    if seg < 60:
        return f"{seg:.2f} s"
    if seg < 3600:
        return f"{seg / 60:.1f} min"
    if seg < 86400:
        return f"{seg / 3600:.1f} h"
    return f"{seg / 86400:.1f} dias"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repeticoes", type=int, default=5)
    p.add_argument("--lista", type=int, default=LISTA_PADRAO)
    args = p.parse_args()

    ph = C._ph
    m_kib, t_cost, p_lanes = ph.memory_cost, ph.time_cost, ph.parallelism

    print("=" * 64)
    print("BENCHMARK DE HASH — MD5 (sem salt) vs Argon2id (RFC 9106 low mem)")
    print("=" * 64)
    print(f"Maquina/Python : {sys.platform}, Python {sys.version.split()[0]}")
    print(f"Argon2id params: m={m_kib} KiB ({m_kib // 1024} MiB), t={t_cost}, "
          f"p={p_lanes}")
    print(f"Repeticoes     : {args.repeticoes} (reporta a mediana)")
    print(f"Lista alvo     : {mil(args.lista)} senhas")
    print("-" * 64)

    taxa_md5_med = mediana_taxa_md5(args.repeticoes)
    tempo_ar_med = mediana_tempo_argon2(args.repeticoes)
    taxa_ar_med = 1.0 / tempo_ar_med

    razao = taxa_md5_med / taxa_ar_med
    ordens = math.log10(razao)

    print(f"MD5 sem salt   : {mil(taxa_md5_med)} hashes/s")
    print(f"Argon2id       : {taxa_ar_med:.2f} hashes/s "
          f"({fmt_tempo(tempo_ar_med)} por hash)")
    print("-" * 64)
    print(f"Razao MD5/Argon2id : {mil(razao)}x  "
          f"(~{ordens:.1f} ordens de grandeza)")
    print("-" * 64)
    print(f"Tempo p/ testar {mil(args.lista)} senhas (offline, 1 nucleo):")
    print(f"  MD5 sem salt : {fmt_tempo(args.lista / taxa_md5_med)}")
    print(f"  Argon2id     : {fmt_tempo(args.lista * tempo_ar_med)}")
    print("=" * 64)
    print("Leitura: cada login custa 1 hash, mas o ATAQUE OFFLINE (T3) precisa")
    print("recomputar o hash por tentativa; o Argon2id multiplica esse custo em")
    print(f"~{ordens:.1f} ordens de grandeza, inviabilizando listas grandes.")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())

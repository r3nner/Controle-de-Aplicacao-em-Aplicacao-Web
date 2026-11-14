"""
Revisao de eventos de autenticacao (AU-6 / REQ-AU-08).

Imprime o resumo por tipo de evento e os alertas disparados (regras R1/R2).

Uso:
    python revisao.py [caminho_do_log]
    python -m revisao [caminho_do_log]
"""
import json
import sys

import controles as C


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    arquivo = argv[0] if argv else C.ARQUIVO_LOG
    resumo = C.resumo_eventos(arquivo)

    print("=" * 56)
    print(f"REVISAO DO LOG DE AUTENTICACAO — {arquivo}")
    print("=" * 56)
    print("Contagem por tipo de evento:")
    for tipo, n in sorted(resumo["por_tipo"].items(), key=lambda x: -x[1]):
        print(f"  {tipo:28s} {n}")
    print("-" * 56)
    if resumo["alertas"]:
        print(f"ALERTAS DISPARADOS ({len(resumo['alertas'])}):")
        for a in resumo["alertas"]:
            print("  " + json.dumps(a, ensure_ascii=False))
    else:
        print("Nenhum alerta disparado.")
    print("=" * 56)
    return 0


if __name__ == "__main__":
    sys.exit(main())

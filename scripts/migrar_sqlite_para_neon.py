"""
Migra os dados do banco local SQLite (banco_horas.db) para o PostgreSQL/Neon.

Uso:
  1. Configure DATABASE_URL com a connection string do Neon.
  2. Execute:
     python scripts/migrar_sqlite_para_neon.py

Por padrão o script não apaga dados existentes no Neon. Para limpar antes:
     python scripts/migrar_sqlite_para_neon.py --clear
"""
import os
import sys
import sqlite3

import psycopg2
import psycopg2.extras

ROOT = os.path.dirname(os.path.dirname(__file__))
SQLITE_PATH = os.path.join(ROOT, "banco_horas.db")

TABLES = [
    "servidores",
    "lancamentos",
    "compensacoes",
    "pagamentos",
    "consumos",
    "usuarios",
    "config",
    "pre_autorizacoes",
]

SEQUENCES = {
    "lancamentos": "lancamentos_id_seq",
    "compensacoes": "compensacoes_id_seq",
    "pagamentos": "pagamentos_id_seq",
    "consumos": "consumos_id_seq",
    "usuarios": "usuarios_id_seq",
    "pre_autorizacoes": "pre_autorizacoes_id_seq",
}

def neon_url():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise SystemExit("Defina DATABASE_URL antes de executar a migração.")
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    if "sslmode=" not in url:
        url += ("&" if "?" in url else "?") + "sslmode=require"
    return url

def main():
    if not os.path.exists(SQLITE_PATH):
        raise SystemExit(f"Banco local não encontrado: {SQLITE_PATH}")

    clear = "--clear" in sys.argv
    src = sqlite3.connect(SQLITE_PATH)
    src.row_factory = sqlite3.Row
    dst = psycopg2.connect(neon_url())
    dst.autocommit = False

    with dst.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        if clear:
            cur.execute(
                "TRUNCATE consumos, pagamentos, compensacoes, lancamentos, pre_autorizacoes, usuarios, config, servidores "
                "RESTART IDENTITY CASCADE"
            )

        for table in TABLES:
            rows = src.execute(f"SELECT * FROM {table}").fetchall()
            if not rows:
                print(f"{table}: 0")
                continue

            cols = rows[0].keys()
            col_sql = ",".join(cols)
            placeholders = ",".join(["%s"] * len(cols))

            if table == "servidores":
                conflict = "matricula"
            elif table == "config":
                conflict = "chave"
            elif table in ("usuarios", "pre_autorizacoes"):
                conflict = "id"
            else:
                conflict = "id"

            updates = ",".join([f"{c}=EXCLUDED.{c}" for c in cols if c != conflict])
            sql = f"INSERT INTO {table} ({col_sql}) VALUES ({placeholders}) ON CONFLICT ({conflict}) DO UPDATE SET {updates}"

            for row in rows:
                cur.execute(sql, [row[c] for c in cols])
            print(f"{table}: {len(rows)}")

        for table, seq in SEQUENCES.items():
            cur.execute(f"SELECT COALESCE(MAX(id),0) FROM {table}")
            max_id = cur.fetchone()["coalesce"]
            cur.execute("SELECT setval(%s, %s, %s)", (seq, max_id if max_id else 1, bool(max_id)))

    dst.commit()
    src.close()
    dst.close()
    print("Migração concluída.")

if __name__ == "__main__":
    main()

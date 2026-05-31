"""
database.py — suporte a SQLite (local) e PostgreSQL/Neon (produção).
Seleciona automaticamente via variável de ambiente DATABASE_URL.
"""
import os
import sqlite3
import json
import calendar
from datetime import date
from flask import g

# ─── Configuração de conexão ──────────────────────────────────────────────────

DB_PATH      = os.path.join(os.path.dirname(__file__), "banco_horas.db")
_DB_URL      = os.environ.get("DATABASE_URL", "").strip()
# Render/Neon usam postgres://, psycopg2 precisa de postgresql://
if _DB_URL.startswith("postgres://"):
    _DB_URL = _DB_URL.replace("postgres://", "postgresql://", 1)
if _DB_URL.startswith("postgresql") and "sslmode=" not in _DB_URL:
    _DB_URL += ("&" if "?" in _DB_URL else "?") + "sslmode=require"
IS_POSTGRES = _DB_URL.startswith("postgresql")

if IS_POSTGRES:
    import psycopg2
    import psycopg2.extras

# ─── Helpers de data (evitam funções SQL específicas de cada banco) ────────────

def _months_ago(n: int) -> str:
    """Retorna string ISO da data de N meses atrás."""
    today = date.today()
    m = today.month - n
    y = today.year
    while m <= 0:
        m += 12
        y -= 1
    max_day = calendar.monthrange(y, m)[1]
    return date(y, m, min(today.day, max_day)).isoformat()

def six_months_ago()  -> str: return _months_ago(6)
def five_months_ago() -> str: return _months_ago(5)

# ─── Row wrapper (suporta acesso por nome E por índice inteiro) ───────────────

class Row(dict):
    """dict que também suporta row[0] (como sqlite3.Row)."""
    def __init__(self, mapping):
        super().__init__(mapping)
        self._keys_list = list(mapping.keys())

    def __getitem__(self, key):
        if isinstance(key, int):
            return super().__getitem__(self._keys_list[key])
        return super().__getitem__(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except (KeyError, IndexError):
            return default

# ─── Cursor wrapper ───────────────────────────────────────────────────────────

class _Cur:
    def __init__(self, cur, is_pg):
        self._c  = cur
        self._pg = is_pg

    def fetchone(self):
        row = self._c.fetchone()
        if row is None:
            return None
        return Row(dict(row)) if self._pg else row

    def fetchall(self):
        rows = self._c.fetchall()
        if self._pg:
            return [Row(dict(r)) for r in rows]
        return rows

    @property
    def lastrowid(self):
        return self._c.lastrowid  # SQLite only

# ─── Conexão wrapper ──────────────────────────────────────────────────────────

class DbConn:
    """Interface unificada SQLite / PostgreSQL."""

    def __init__(self, raw, is_pg=False):
        self._raw = raw
        self._pg  = is_pg

    # ── Consulta ──────────────────────────────────────────────────────────────
    def execute(self, sql, params=()):
        if self._pg:
            sql = sql.replace("?", "%s")
            cur = self._raw.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cur = self._raw.cursor()
        cur.execute(sql, list(params) if params else [])
        return _Cur(cur, self._pg)

    # ── INSERT retornando PK ──────────────────────────────────────────────────
    def insert(self, sql, params=()):
        """Executa INSERT e retorna o ID gerado."""
        if self._pg:
            sql = sql.replace("?", "%s").rstrip().rstrip(";")
            if "RETURNING id" not in sql.upper():
                sql += " RETURNING id"
            cur = self._raw.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(sql, list(params) if params else [])
            row = cur.fetchone()
            return row["id"] if row else None
        else:
            cur = self._raw.cursor()
            cur.execute(sql, params)
            return cur.lastrowid

    # ── UPSERT (INSERT OR REPLACE / ON CONFLICT) ──────────────────────────────
    def upsert(self, sql_sqlite, sql_pg, params=()):
        """Executa INSERT OR REPLACE (SQLite) ou ON CONFLICT (PG)."""
        if self._pg:
            sql = sql_pg.replace("?", "%s")
            cur = self._raw.cursor()
            cur.execute(sql, list(params) if params else [])
        else:
            cur = self._raw.cursor()
            cur.execute(sql_sqlite, params)

    # ── Script DDL ────────────────────────────────────────────────────────────
    def executescript(self, sql):
        if self._pg:
            cur = self._raw.cursor()
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if stmt and not stmt.startswith("--"):
                    try:
                        cur.execute(stmt)
                    except Exception:
                        self._raw.rollback()
        else:
            self._raw.executescript(sql)

    # ── Coluna existe? ────────────────────────────────────────────────────────
    def col_exists(self, table, col):
        if self._pg:
            r = self.execute(
                "SELECT 1 FROM information_schema.columns WHERE table_name=? AND column_name=?",
                (table, col)).fetchone()
            return bool(r)
        else:
            rows = self._raw.execute(f"PRAGMA table_info({table})").fetchall()
            return any(r[1] == col for r in rows)

    def add_col_if_missing(self, table, col, definition):
        if self._pg:
            self.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {definition}")
        elif not self.col_exists(table, col):
            self.execute(f"ALTER TABLE {table} ADD COLUMN {col} {definition}")

    def commit(self):
        self._raw.commit()

    def close(self):
        self._raw.close()

# ─── Fábrica de conexão ───────────────────────────────────────────────────────

def _new_conn() -> DbConn:
    if IS_POSTGRES:
        raw = psycopg2.connect(_DB_URL)
        raw.autocommit = False
        return DbConn(raw, is_pg=True)
    else:
        raw = sqlite3.connect(DB_PATH)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA foreign_keys = ON")
        return DbConn(raw, is_pg=False)

def get_db() -> DbConn:
    if "db" not in g:
        g.db = _new_conn()
    return g.db

# ─── Schemas ─────────────────────────────────────────────────────────────────

_SCHEMA_SQLITE = """
    CREATE TABLE IF NOT EXISTS servidores (
        matricula TEXT PRIMARY KEY, nome TEXT NOT NULL, cargo TEXT, setor TEXT
    );
    CREATE TABLE IF NOT EXISTS lancamentos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        matricula TEXT NOT NULL REFERENCES servidores(matricula),
        data TEXT NOT NULL, horas_base TEXT NOT NULL,
        minutos_base INTEGER NOT NULL DEFAULT 0, percentual INTEGER NOT NULL,
        minutos_creditados INTEGER NOT NULL, descricao TEXT,
        criado_em TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS compensacoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        matricula TEXT NOT NULL REFERENCES servidores(matricula),
        data TEXT NOT NULL, tipo TEXT NOT NULL,
        minutos_compensados INTEGER NOT NULL, descricao TEXT,
        criado_em TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS consumos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        lancamento_id INTEGER NOT NULL REFERENCES lancamentos(id),
        tipo TEXT NOT NULL, referencia_id INTEGER NOT NULL, minutos INTEGER NOT NULL,
        criado_em TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS pagamentos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        matricula TEXT NOT NULL REFERENCES servidores(matricula),
        data_pagamento TEXT NOT NULL, descricao TEXT,
        criado_em TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpf TEXT UNIQUE NOT NULL, nome TEXT NOT NULL, email TEXT,
        senha_hash TEXT NOT NULL, nivel TEXT NOT NULL DEFAULT 'servidor',
        secretaria TEXT, setor TEXT, matricula TEXT, vinculos TEXT DEFAULT '[]',
        ativo INTEGER NOT NULL DEFAULT 1, senha_temporaria INTEGER NOT NULL DEFAULT 1,
        reset_token TEXT, reset_expiry TEXT, ultimo_acesso TEXT,
        criado_em TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS config (chave TEXT PRIMARY KEY, valor TEXT);
    CREATE TABLE IF NOT EXISTS pre_autorizacoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpf TEXT UNIQUE NOT NULL, nivel TEXT NOT NULL DEFAULT 'servidor',
        secretaria TEXT, setor TEXT, matricula TEXT, obs TEXT,
        vinculos TEXT DEFAULT '[]',
        criado_em TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS auditoria (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        criado_em TEXT NOT NULL,
        usuario_id INTEGER, usuario_nome TEXT, usuario_cpf TEXT,
        acao TEXT NOT NULL, entidade TEXT NOT NULL, entidade_id TEXT,
        matricula TEXT, servidor_nome TEXT, detalhe TEXT
    );
    CREATE TABLE IF NOT EXISTS visualizacoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER, usuario_nome TEXT, usuario_cpf TEXT,
        endpoint TEXT, caminho TEXT, titulo TEXT,
        criado_em TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS exclusoes_servidores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        auditoria_id INTEGER, matricula TEXT NOT NULL, servidor_nome TEXT,
        payload TEXT NOT NULL, criado_em TEXT NOT NULL,
        restaurado INTEGER NOT NULL DEFAULT 0, restaurado_em TEXT
    );
"""

_SCHEMA_POSTGRES = """
    CREATE TABLE IF NOT EXISTS servidores (
        matricula TEXT PRIMARY KEY, nome TEXT NOT NULL, cargo TEXT, setor TEXT
    );
    CREATE TABLE IF NOT EXISTS lancamentos (
        id SERIAL PRIMARY KEY,
        matricula TEXT NOT NULL REFERENCES servidores(matricula),
        data TEXT NOT NULL, horas_base TEXT NOT NULL,
        minutos_base INTEGER NOT NULL DEFAULT 0, percentual INTEGER NOT NULL,
        minutos_creditados INTEGER NOT NULL, descricao TEXT,
        criado_em TEXT DEFAULT TO_CHAR(NOW(),'YYYY-MM-DD HH24:MI:SS')
    );
    CREATE TABLE IF NOT EXISTS compensacoes (
        id SERIAL PRIMARY KEY,
        matricula TEXT NOT NULL REFERENCES servidores(matricula),
        data TEXT NOT NULL, tipo TEXT NOT NULL,
        minutos_compensados INTEGER NOT NULL, descricao TEXT,
        criado_em TEXT DEFAULT TO_CHAR(NOW(),'YYYY-MM-DD HH24:MI:SS')
    );
    CREATE TABLE IF NOT EXISTS consumos (
        id SERIAL PRIMARY KEY,
        lancamento_id INTEGER NOT NULL REFERENCES lancamentos(id),
        tipo TEXT NOT NULL, referencia_id INTEGER NOT NULL, minutos INTEGER NOT NULL,
        criado_em TEXT DEFAULT TO_CHAR(NOW(),'YYYY-MM-DD HH24:MI:SS')
    );
    CREATE TABLE IF NOT EXISTS pagamentos (
        id SERIAL PRIMARY KEY,
        matricula TEXT NOT NULL REFERENCES servidores(matricula),
        data_pagamento TEXT NOT NULL, descricao TEXT,
        criado_em TEXT DEFAULT TO_CHAR(NOW(),'YYYY-MM-DD HH24:MI:SS')
    );
    CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        cpf TEXT UNIQUE NOT NULL, nome TEXT NOT NULL, email TEXT,
        senha_hash TEXT NOT NULL, nivel TEXT NOT NULL DEFAULT 'servidor',
        secretaria TEXT, setor TEXT, matricula TEXT, vinculos TEXT DEFAULT '[]',
        ativo INTEGER NOT NULL DEFAULT 1, senha_temporaria INTEGER NOT NULL DEFAULT 1,
        reset_token TEXT, reset_expiry TEXT, ultimo_acesso TEXT,
        criado_em TEXT DEFAULT TO_CHAR(NOW(),'YYYY-MM-DD HH24:MI:SS')
    );
    CREATE TABLE IF NOT EXISTS config (chave TEXT PRIMARY KEY, valor TEXT);
    CREATE TABLE IF NOT EXISTS pre_autorizacoes (
        id SERIAL PRIMARY KEY,
        cpf TEXT UNIQUE NOT NULL, nivel TEXT NOT NULL DEFAULT 'servidor',
        secretaria TEXT, setor TEXT, matricula TEXT, obs TEXT,
        vinculos TEXT DEFAULT '[]',
        criado_em TEXT DEFAULT TO_CHAR(NOW(),'YYYY-MM-DD HH24:MI:SS')
    );
    CREATE TABLE IF NOT EXISTS auditoria (
        id SERIAL PRIMARY KEY,
        criado_em TEXT NOT NULL,
        usuario_id INTEGER, usuario_nome TEXT, usuario_cpf TEXT,
        acao TEXT NOT NULL, entidade TEXT NOT NULL, entidade_id TEXT,
        matricula TEXT, servidor_nome TEXT, detalhe TEXT
    );
    CREATE TABLE IF NOT EXISTS visualizacoes (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER, usuario_nome TEXT, usuario_cpf TEXT,
        endpoint TEXT, caminho TEXT, titulo TEXT,
        criado_em TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS exclusoes_servidores (
        id SERIAL PRIMARY KEY,
        auditoria_id INTEGER, matricula TEXT NOT NULL, servidor_nome TEXT,
        payload TEXT NOT NULL, criado_em TEXT NOT NULL,
        restaurado INTEGER NOT NULL DEFAULT 0, restaurado_em TEXT
    );
"""

# ─── init_db ─────────────────────────────────────────────────────────────────

def init_db():
    db = _new_conn()
    schema = _SCHEMA_POSTGRES if IS_POSTGRES else _SCHEMA_SQLITE
    db.executescript(schema)
    db.commit()

    # Migrações de colunas
    _migracoes = [
        ("lancamentos",       "minutos_base",      "INTEGER NOT NULL DEFAULT 0"),
        ("servidores",        "secretaria",         "TEXT"),
        ("servidores",        "cpf",                "TEXT"),
        ("servidores",        "funcao_gratificada", "INTEGER NOT NULL DEFAULT 0"),
        ("servidores",        "email",              "TEXT"),
        ("servidores",        "arquivado",          "INTEGER NOT NULL DEFAULT 0"),
        ("usuarios",          "vinculos",           "TEXT DEFAULT '[]'"),
        ("pre_autorizacoes",  "vinculos",           "TEXT DEFAULT '[]'"),
    ]
    for table, col, defn in _migracoes:
        try:
            db.add_col_if_missing(table, col, defn)
            db.commit()
        except Exception:
            pass

    # Migra vinculos de colunas únicas para JSON
    _migrar_vinculos(db)
    _migrar_consumos(db)
    _criar_master_padrao(db)
    db.close()


def _migrar_vinculos(db):
    """Converte secretaria/setor unicos para JSON em vinculos."""
    def row_get(row, key):
        try:
            return row[key]
        except Exception:
            return ""

    for u in db.execute("SELECT id,nivel,secretaria,setor FROM usuarios WHERE vinculos IS NULL OR vinculos='[]'").fetchall():
        vinculo = row_get(u, 'secretaria') if row_get(u, 'nivel') == 'secretario' else (row_get(u, 'setor') if row_get(u, 'nivel') == 'chefia' else '')
        if vinculo:
            db.execute("UPDATE usuarios SET vinculos=? WHERE id=?", (json.dumps([vinculo]), u['id']))
    for p in db.execute("SELECT id,nivel,secretaria,setor FROM pre_autorizacoes WHERE vinculos IS NULL OR vinculos='[]'").fetchall():
        vinculo = row_get(p, 'secretaria') if row_get(p, 'nivel') == 'secretario' else (row_get(p, 'setor') if row_get(p, 'nivel') == 'chefia' else '')
        if vinculo:
            db.execute("UPDATE pre_autorizacoes SET vinculos=? WHERE id=?", (json.dumps([vinculo]), p['id']))
    db.commit()

def _migrar_consumos(db):
    """Converte compensações existentes em registros FIFO (roda uma vez)."""
    ja = db.execute("SELECT COUNT(*) FROM consumos WHERE tipo='compensacao'").fetchone()[0]
    if ja:
        return
    # Atualiza minutos_base zerados
    for l in db.execute("SELECT id,horas_base FROM lancamentos WHERE minutos_base=0").fetchall():
        try:
            h, m = map(int, l["horas_base"].split(":"))
            db.execute("UPDATE lancamentos SET minutos_base=? WHERE id=?", (h*60+m, l["id"]))
        except Exception:
            pass
    # Aplica FIFO para cada servidor
    for srv in db.execute("SELECT matricula FROM servidores").fetchall():
        mat   = srv["matricula"]
        comps = db.execute(
            "SELECT id, minutos_compensados FROM compensacoes WHERE matricula=? ORDER BY data ASC, id ASC",
            (mat,)).fetchall()
        for comp in comps:
            _consumir_fifo_raw(db, mat, comp["minutos_compensados"], "compensacao", comp["id"])
    db.commit()


def _criar_master_padrao(db):
    """Cria usuário master padrão se nenhum existir."""
    if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] > 0:
        return
    from werkzeug.security import generate_password_hash
    db.execute(
        "INSERT INTO usuarios (cpf,nome,email,senha_hash,nivel,ativo,senha_temporaria) VALUES (?,?,?,?,?,1,1)",
        ("000.000.000-00", "Administrador Master", "", generate_password_hash("Ibipora@2024"), "master"))
    db.commit()


def _consumir_fifo_raw(db, matricula, minutos_a_consumir, tipo, referencia_id):
    """Aloca minutos sobre os lançamentos mais antigos com saldo disponível."""
    lancamentos = db.execute("""
        SELECT l.id, l.minutos_creditados,
               COALESCE((SELECT SUM(c.minutos) FROM consumos c WHERE c.lancamento_id=l.id),0) AS consumido
        FROM lancamentos l WHERE l.matricula=? ORDER BY l.data ASC, l.id ASC
    """, (matricula,)).fetchall()

    restante = minutos_a_consumir
    for l in lancamentos:
        disponivel = l["minutos_creditados"] - l["consumido"]
        if disponivel <= 0:
            continue
        consumir = min(disponivel, restante)
        db.execute(
            "INSERT INTO consumos (lancamento_id,tipo,referencia_id,minutos) VALUES (?,?,?,?)",
            (l["id"], tipo, referencia_id, consumir))
        restante -= consumir
        if restante <= 0:
            break

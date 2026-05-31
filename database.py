"""
database.py — suporte a SQLite (local) e PostgreSQL/Neon (produção).
Seleciona automaticamente via variável de ambiente DATABASE_URL.
"""
import os
import sqlite3
import json
import calendar
import csv
import io
from datetime import date, timedelta
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

    @property
    def rowcount(self):
        return self._c.rowcount

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
    CREATE TABLE IF NOT EXISTS importacoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tipo TEXT NOT NULL, arquivo TEXT, usuario_id INTEGER, usuario_nome TEXT, usuario_cpf TEXT,
        total_linhas INTEGER NOT NULL DEFAULT 0, criados INTEGER NOT NULL DEFAULT 0, atualizados INTEGER NOT NULL DEFAULT 0,
        erros INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL, criado_em TEXT NOT NULL,
        estornado INTEGER NOT NULL DEFAULT 0, estornado_em TEXT
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
    CREATE TABLE IF NOT EXISTS importacoes (
        id SERIAL PRIMARY KEY,
        tipo TEXT NOT NULL, arquivo TEXT, usuario_id INTEGER, usuario_nome TEXT, usuario_cpf TEXT,
        total_linhas INTEGER NOT NULL DEFAULT 0, criados INTEGER NOT NULL DEFAULT 0, atualizados INTEGER NOT NULL DEFAULT 0,
        erros INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL, criado_em TEXT NOT NULL,
        estornado INTEGER NOT NULL DEFAULT 0, estornado_em TEXT
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
    _popular_demo_render(db)
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

_DEMO_SERVIDORES_CSV = """matricula,nome,cpf,email,cargo,secretaria,setor,funcao_gratificada
10001,Ana Clara Martins,000.000.000-01,ana.martins@ibipora.pr.gov.br,Agente Administrativo,Secretaria de Gestão de Pessoas,Departamento de Gestão de Pessoas,FG-1
10002,Bruno Henrique Almeida,000.000.000-02,bruno.almeida@ibipora.pr.gov.br,Assistente Administrativo,Secretaria de Administração,Protocolo Geral,
10003,Carolina Souza Ribeiro,000.000.000-03,carolina.ribeiro@ibipora.pr.gov.br,Professora,Secretaria de Educação,Escola Municipal Aurora,
10004,Daniel Ferreira Costa,000.000.000-04,daniel.costa@ibipora.pr.gov.br,Motorista,Secretaria de Saúde,Transporte Sanitário,
10005,Eduarda Lima Nascimento,000.000.000-05,eduarda.nascimento@ibipora.pr.gov.br,Enfermeira,Secretaria de Saúde,Unidade Básica de Saúde Central,FG-2
10006,Felipe Augusto Moreira,000.000.000-06,felipe.moreira@ibipora.pr.gov.br,Contador,Secretaria de Fazenda,Departamento de Contabilidade,
10007,Gabriela Mendes Rocha,000.000.000-07,gabriela.rocha@ibipora.pr.gov.br,Técnica em Enfermagem,Secretaria de Saúde,Pronto Atendimento Municipal,
10008,Henrique Lopes Cardoso,000.000.000-08,henrique.cardoso@ibipora.pr.gov.br,Fiscal de Tributos,Secretaria de Fazenda,Fiscalização Tributária,FG-1
10009,Isabela Cristina Gomes,000.000.000-09,isabela.gomes@ibipora.pr.gov.br,Educadora Infantil,Secretaria de Educação,CMEI Pequeno Aprendiz,
10010,João Pedro Batista,000.000.000-10,joao.batista@ibipora.pr.gov.br,Agente de Serviços Gerais,Secretaria de Obras,Manutenção Urbana,
10011,Karen Aparecida Dias,000.000.000-11,karen.dias@ibipora.pr.gov.br,Psicóloga,Secretaria de Assistência Social,CRAS Norte,
10012,Lucas Matheus Pereira,000.000.000-12,lucas.pereira@ibipora.pr.gov.br,Engenheiro Civil,Secretaria de Obras,Departamento de Engenharia,FG-3
10013,Mariana Teixeira Ramos,000.000.000-13,mariana.ramos@ibipora.pr.gov.br,Nutricionista,Secretaria de Educação,Alimentação Escolar,
10014,Nicolas Gabriel Oliveira,000.000.000-14,nicolas.oliveira@ibipora.pr.gov.br,Analista de Sistemas,Secretaria de Administração,Tecnologia da Informação,FG-2
10015,Olívia Beatriz Santos,000.000.000-15,olivia.santos@ibipora.pr.gov.br,Assistente Social,Secretaria de Assistência Social,CREAS,
10016,Paulo Sérgio Carvalho,000.000.000-16,paulo.carvalho@ibipora.pr.gov.br,Guarda Municipal,Secretaria de Segurança Pública,Patrulhamento Preventivo,
10017,Quézia Fernanda Araújo,000.000.000-17,quezia.araujo@ibipora.pr.gov.br,Farmacêutica,Secretaria de Saúde,Farmácia Municipal,
10018,Rafael Vinícius Barbosa,000.000.000-18,rafael.barbosa@ibipora.pr.gov.br,Técnico Administrativo,Secretaria de Planejamento,Convênios e Projetos,
10019,Sabrina Helena Martins,000.000.000-19,sabrina.martins@ibipora.pr.gov.br,Professora,Secretaria de Educação,Escola Municipal Primavera,FG-1
10020,Thiago Rodrigues Melo,000.000.000-20,thiago.melo@ibipora.pr.gov.br,Médico,Secretaria de Saúde,Unidade Básica de Saúde Sul,
10021,Ursula Camila Farias,000.000.000-21,ursula.farias@ibipora.pr.gov.br,Odontóloga,Secretaria de Saúde,Centro Odontológico,
10022,Victor Emanuel Reis,000.000.000-22,victor.reis@ibipora.pr.gov.br,Operador de Máquinas,Secretaria de Obras,Garagem Municipal,
10023,Wesley Henrique Lima,000.000.000-23,wesley.lima@ibipora.pr.gov.br,Agente Comunitário de Saúde,Secretaria de Saúde,Estratégia Saúde da Família,
10024,Yasmin Vitória Castro,000.000.000-24,yasmin.castro@ibipora.pr.gov.br,Bibliotecária,Secretaria de Cultura,Biblioteca Municipal,
10025,Zélia Regina Monteiro,000.000.000-25,zelia.monteiro@ibipora.pr.gov.br,Arquivista,Secretaria de Administração,Arquivo Geral,
10026,Adriano César Pires,000.000.000-26,adriano.pires@ibipora.pr.gov.br,Técnico em Segurança do Trabalho,Secretaria de Gestão de Pessoas,Saúde Ocupacional,
10027,Bianca Aparecida Viana,000.000.000-27,bianca.viana@ibipora.pr.gov.br,Pedagoga,Secretaria de Educação,Departamento Pedagógico,FG-2
10028,Caio Augusto Fernandes,000.000.000-28,caio.fernandes@ibipora.pr.gov.br,Auxiliar Administrativo,Secretaria de Fazenda,Arrecadação,
10029,Débora Cristina Nunes,000.000.000-29,debora.nunes@ibipora.pr.gov.br,Fisioterapeuta,Secretaria de Saúde,Centro de Reabilitação,
10030,Elton José Moraes,000.000.000-30,elton.moraes@ibipora.pr.gov.br,Fiscal de Obras,Secretaria de Obras,Fiscalização de Obras,
10031,Fernanda Lopes Vieira,000.000.000-31,fernanda.vieira@ibipora.pr.gov.br,Procuradora Municipal,Procuradoria Geral do Município,Consultivo Administrativo,FG-3
10032,Gustavo Henrique Silva,000.000.000-32,gustavo.silva@ibipora.pr.gov.br,Agente Administrativo,Secretaria de Cultura,Eventos Culturais,
10033,Helena Maria Duarte,000.000.000-33,helena.duarte@ibipora.pr.gov.br,Coordenadora Pedagógica,Secretaria de Educação,Coordenação Escolar,FG-1
10034,Ícaro Martins Ferreira,000.000.000-34,icaro.ferreira@ibipora.pr.gov.br,Técnico de Informática,Secretaria de Administração,Suporte Técnico,
10035,Jéssica Almeida Prado,000.000.000-35,jessica.prado@ibipora.pr.gov.br,Recepcionista,Secretaria de Saúde,UBS Jardim das Flores,
10036,Kelvin Rafael Campos,000.000.000-36,kelvin.campos@ibipora.pr.gov.br,Fiscal Sanitário,Secretaria de Saúde,Vigilância Sanitária,
10037,Larissa Fernanda Costa,000.000.000-37,larissa.costa@ibipora.pr.gov.br,Terapeuta Ocupacional,Secretaria de Saúde,Atendimento Especializado,
10038,Márcio Antônio Neves,000.000.000-38,marcio.neves@ibipora.pr.gov.br,Eletricista,Secretaria de Obras,Iluminação Pública,
10039,Natália Regina Barros,000.000.000-39,natalia.barros@ibipora.pr.gov.br,Agente de RH,Secretaria de Gestão de Pessoas,Folha de Pagamento,
10040,Otávio Luiz Marques,000.000.000-40,otavio.marques@ibipora.pr.gov.br,Auditor Interno,Controladoria Geral,Auditoria e Controle,FG-2
"""

def _hhmm_para_min(s):
    h, m = map(int, s.split(":"))
    return h * 60 + m

def _min_para_hhmm(m):
    return f"{m // 60:02d}:{m % 60:02d}"

def _popular_demo_render(db):
    """Popula dados de demonstração uma única vez para o ambiente online."""
    if os.environ.get("BANCO_HORAS_RUN_DEMO_SEED", "").lower() not in ("1", "true", "sim"):
        return
    if db.execute("SELECT valor FROM config WHERE chave='demo_seed_v2'").fetchone():
        return

    servidores = list(csv.DictReader(io.StringIO(_DEMO_SERVIDORES_CSV)))
    datas_base = [date(2025, 11, 12), date(2025, 12, 18), date(2026, 1, 22),
                  date(2026, 2, 20), date(2026, 3, 17), date(2026, 4, 24), date(2026, 5, 14)]
    horas_base = ["02:00", "03:30", "04:00", "05:00", "06:00", "08:00", "10:00"]

    for idx, s in enumerate(servidores):
        fg = 1 if (s.get("funcao_gratificada") or "").strip() else 0
        if db.execute("SELECT 1 FROM servidores WHERE matricula=?", (s["matricula"],)).fetchone():
            db.execute("""UPDATE servidores
                          SET nome=?,cpf=?,email=?,cargo=?,secretaria=?,setor=?,funcao_gratificada=?,arquivado=0
                          WHERE matricula=?""",
                       (s["nome"], s["cpf"], s["email"], s["cargo"], s["secretaria"],
                        s["setor"], fg, s["matricula"]))
        else:
            db.execute("""INSERT INTO servidores
                          (matricula,nome,cpf,email,cargo,secretaria,setor,funcao_gratificada,arquivado)
                          VALUES (?,?,?,?,?,?,?,?,0)""",
                       (s["matricula"], s["nome"], s["cpf"], s["email"], s["cargo"],
                        s["secretaria"], s["setor"], fg))

        if db.execute("SELECT 1 FROM lancamentos WHERE matricula=? LIMIT 1", (s["matricula"],)).fetchone():
            continue

        lanc_ids = []
        qtd_lanc = 3 + (idx % 3)
        for j in range(qtd_lanc):
            data_l = datas_base[(idx + j) % len(datas_base)] + timedelta(days=(idx * 2 + j) % 9)
            horas = horas_base[(idx + j) % len(horas_base)]
            base_min = _hhmm_para_min(horas)
            pct = 100 if (idx + j) % 4 == 0 else 50
            cred = base_min + base_min * pct // 100
            lid = db.insert("""INSERT INTO lancamentos
                (matricula,data,horas_base,minutos_base,percentual,minutos_creditados,descricao)
                VALUES (?,?,?,?,?,?,?)""",
                (s["matricula"], data_l.isoformat(), horas, base_min, pct, cred,
                 f"Demonstração: hora extra {j + 1}"))
            lanc_ids.append(lid)

        if idx % 2 == 0:
            comp_min = 240 + (idx % 4) * 60
            cid = db.insert("""INSERT INTO compensacoes
                (matricula,data,tipo,minutos_compensados,descricao)
                VALUES (?,?,?,?,?)""",
                (s["matricula"], (date(2026, 5, 3) + timedelta(days=idx % 20)).isoformat(),
                 "parcial", comp_min, "Demonstração: compensação parcial"))
            _consumir_fifo_raw(db, s["matricula"], comp_min, "compensacao", cid)

        if idx % 5 == 0:
            cid = db.insert("""INSERT INTO compensacoes
                (matricula,data,tipo,minutos_compensados,descricao)
                VALUES (?,?,?,?,?)""",
                (s["matricula"], (date(2026, 4, 8) + timedelta(days=idx % 15)).isoformat(),
                 "dia_inteiro", 480, "Demonstração: compensação dia inteiro"))
            _consumir_fifo_raw(db, s["matricula"], 480, "compensacao", cid)

        if idx % 3 == 0:
            pid = db.insert("""INSERT INTO pagamentos (matricula,data_pagamento,descricao)
                               VALUES (?,?,?)""",
                            (s["matricula"], "2026-05-31", "Demonstração: pagamento em folha"))
            base_pag = 180 + (idx % 5) * 60
            saldo_lancs = db.execute("""SELECT l.id,l.minutos_base,l.minutos_creditados,
                    l.minutos_creditados - COALESCE((SELECT SUM(c.minutos) FROM consumos c WHERE c.lancamento_id=l.id),0) AS saldo
                FROM lancamentos l WHERE l.matricula=? ORDER BY l.data ASC,l.id ASC""", (s["matricula"],)).fetchall()
            restante_base = base_pag
            for l in saldo_lancs:
                if restante_base <= 0:
                    break
                saldo = int(l["saldo"] or 0)
                if saldo <= 0:
                    continue
                base_disponivel = round(saldo * int(l["minutos_base"]) / int(l["minutos_creditados"])) if int(l["minutos_creditados"]) else 0
                base_usar = min(base_disponivel, restante_base)
                mins_consumo = round(base_usar * int(l["minutos_creditados"]) / int(l["minutos_base"])) if int(l["minutos_base"]) else base_usar
                mins_consumo = min(mins_consumo, saldo)
                if mins_consumo > 0:
                    db.execute("""INSERT INTO consumos (lancamento_id,tipo,referencia_id,minutos)
                                  VALUES (?,?,?,?)""", (l["id"], "pagamento", pid, mins_consumo))
                    restante_base -= base_usar

    db.upsert(
        "INSERT OR REPLACE INTO config (chave,valor) VALUES (?,?)",
        "INSERT INTO config (chave,valor) VALUES (?,?) ON CONFLICT (chave) DO UPDATE SET valor=EXCLUDED.valor",
        ("demo_seed_v2", date.today().isoformat())
    )
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

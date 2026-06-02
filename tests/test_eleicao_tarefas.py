import sqlite3
import unittest

import app as app_module
from database import DbConn


class EleicaoTarefasTests(unittest.TestCase):
    def setUp(self):
        raw = sqlite3.connect(":memory:")
        raw.row_factory = sqlite3.Row
        self.db = DbConn(raw, is_pg=False)
        self.db.executescript("""
            CREATE TABLE servidores (
                matricula TEXT PRIMARY KEY, nome TEXT, cpf TEXT, email TEXT,
                cargo TEXT, setor TEXT, secretaria TEXT, arquivado INTEGER DEFAULT 0
            );
            CREATE TABLE solicitacoes (
                id INTEGER PRIMARY KEY,
                matricula TEXT, tipo TEXT, quantidade INTEGER,
                data_pretendida TEXT, data_fim TEXT, justificativa TEXT,
                status TEXT, criado_por_uid INTEGER, criado_por_nome TEXT,
                aprovador_uid INTEGER, aprovador_nome TEXT, data_autorizacao TEXT,
                justificativa_rh TEXT, despacho_chefia TEXT,
                rh_uid INTEGER, rh_nome TEXT, data_lancamento TEXT, referencia_id INTEGER
            );
            CREATE TABLE eleicao_creditos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                matricula TEXT, referencia_eleicao TEXT, quantidade_dias INTEGER,
                observacao TEXT, criado_por TEXT, criado_em TEXT
            );
            CREATE TABLE eleicao_baixas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                matricula TEXT, data TEXT, observacao TEXT, criado_por TEXT, criado_em TEXT
            );
            CREATE TABLE auditoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                criado_em TEXT, usuario_id INTEGER, usuario_nome TEXT, usuario_cpf TEXT,
                acao TEXT, entidade TEXT, entidade_id TEXT,
                matricula TEXT, servidor_nome TEXT, detalhe TEXT
            );
        """)
        self.db.execute("""INSERT INTO servidores
            (matricula,nome,cpf,email,cargo,setor,secretaria,arquivado)
            VALUES (?,?,?,?,?,?,?,0)""",
            ("100", "Servidor Teste", "12345678900", "teste@example.com", "Cargo", "Setor", "Secretaria"))
        self.db.execute("""INSERT INTO eleicao_creditos
            (matricula,referencia_eleicao,quantidade_dias,observacao,criado_por)
            VALUES ('100','Eleicao Teste',5,'credito','Master')""")
        self.db.execute("""INSERT INTO solicitacoes
            (id,matricula,tipo,quantidade,data_pretendida,data_fim,status,criado_por_uid,criado_por_nome,aprovador_nome)
            VALUES (10,'100','eleicao',3,'2026-06-04','2026-06-06','autorizado',1,'Master','Master')""")
        self.db.commit()

        self.original_get_db = app_module.get_db
        app_module.get_db = lambda: self.db
        self.app = app_module.app
        self.app.config["TESTING"] = True

    def tearDown(self):
        app_module.get_db = self.original_get_db
        self.db.close()

    def test_lancar_eleicao_baixa_todo_periodo_e_estorna(self):
        client = self.app.test_client()
        with client.session_transaction() as sess:
            sess.update({'uid': 1, 'nivel': 'master', 'nome': 'Master', 'cpf': '0', 'temp': False})

        response = client.post("/admin/tarefas/10/lancar")
        self.assertEqual(response.status_code, 200)

        baixas = self.db.execute(
            "SELECT data, observacao FROM eleicao_baixas WHERE matricula='100' ORDER BY data"
        ).fetchall()
        self.assertEqual([b["data"] for b in baixas], ["2026-06-04", "2026-06-05", "2026-06-06"])
        self.assertTrue(all("Solicitação #10" in (b["observacao"] or "") for b in baixas))

        response = client.post("/admin/tarefas/10/estornar")
        self.assertEqual(response.status_code, 200)

        total = self.db.execute("SELECT COUNT(*) FROM eleicao_baixas WHERE matricula='100'").fetchone()[0]
        self.assertEqual(total, 0)


if __name__ == "__main__":
    unittest.main()

import unittest

from app import app, _historico_individual_pdf_response, _pdf_response, _xlsx_response
from utils import (
    calcular_data_fim_periodo,
    datas_periodo_consecutivo,
    formatar_cpf,
    formatar_data_br,
    formatar_datetime_br,
    horas_para_minutos,
    minutos_para_horas,
    somente_digitos,
)


class BasicRegressionTests(unittest.TestCase):
    def test_cpf_helpers(self):
        self.assertEqual(somente_digitos("123.456.789-00"), "12345678900")
        self.assertEqual(formatar_cpf("12345678900"), "123.456.789-00")
        self.assertEqual(formatar_cpf(""), "\u2013")

    def test_date_and_hour_helpers(self):
        self.assertEqual(formatar_data_br("2026-06-04"), "04/06/2026")
        self.assertEqual(formatar_datetime_br("2026-06-04 09:35:10"), "04/06/2026 09:35")
        self.assertEqual(horas_para_minutos("08:30"), 510)
        self.assertEqual(horas_para_minutos("08:99"), 0)
        self.assertEqual(minutos_para_horas(-90), "-01:30")

    def test_eleicao_period_helpers(self):
        self.assertEqual(calcular_data_fim_periodo("2026-06-04", 1, "eleicao"), "2026-06-04")
        self.assertEqual(calcular_data_fim_periodo("2026-06-04", 2, "eleicao"), "2026-06-05")
        self.assertEqual(calcular_data_fim_periodo("2026-06-04", 3, "banco_horas"), "2026-06-04")
        self.assertEqual(
            datas_periodo_consecutivo("2026-06-04", 3),
            ["2026-06-04", "2026-06-05", "2026-06-06"],
        )

    def test_no_duplicate_routes(self):
        routes = [str(rule.rule) for rule in app.url_map.iter_rules()]
        duplicates = sorted({route for route in routes if routes.count(route) > 1})
        self.assertEqual(duplicates, [])

    def test_master_view_switch_requires_login(self):
        client = app.test_client()
        response = client.post("/admin/alternar-visao", data={"visao": "chefia"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers.get("Location", ""))

    def test_old_status_route_redirects(self):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess.update({'uid': 1, 'nivel': 'master', 'nome': 'Master', 'cpf': '0', 'temp': False})
        response = client.get("/admin/saude")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/status", response.headers.get("Location", ""))

    def test_authenticated_post_requires_csrf(self):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess.update({'uid': 1, 'nivel': 'master', 'nome': 'Master', 'cpf': '0', 'temp': False, '_csrf_token': 'valid'})
        response = client.post("/admin/alternar-visao", data={"visao": "master"})
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as sess:
            self.assertNotIn("visao_master", sess)

    def test_security_headers(self):
        response = app.test_client().get("/login")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertIn("default-src", response.headers.get("Content-Security-Policy", ""))

    def test_login_does_not_expose_fixed_password(self):
        response = app.test_client().get("/login")
        self.assertNotIn(b"123456", response.data)
        self.assertNotIn(b"Ibipora@2024", response.data)

    def test_authenticated_post_accepts_valid_csrf(self):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess.update({
                'uid': 1, 'nivel': 'master', 'nome': 'Master', 'cpf': '0',
                'temp': False, '_csrf_token': 'valid',
            })
        response = client.post(
            "/admin/alternar-visao",
            data={"visao": "master", "_csrf_token": "valid"},
        )
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as sess:
            self.assertEqual(sess.get("visao_master"), "master")

    def test_master_administrative_pages_render(self):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess.update({
                'uid': 1, 'nivel': 'master', 'nome': 'Master', 'cpf': '0',
                'temp': False, 'vinculos': [],
            })
        for path in ("/admin/usuarios", "/admin/acessos", "/arquivados", "/admin/backup", "/relatorios"):
            with self.subTest(path=path):
                response = client.get(path)
                self.assertEqual(response.status_code, 200)

    def test_report_generators_return_valid_files(self):
        with app.test_request_context():
            pdf = _pdf_response("teste", "Relatório de Teste", ["Nome", "Saldo"], [["Servidor", "01:30"]])
            xlsx = _xlsx_response("teste", "Relatório de Teste", ["Nome", "Saldo"], [["Servidor", "01:30"]])
            history = _historico_individual_pdf_response(
                {
                    "nome": "Servidor Teste",
                    "matricula": "100",
                    "cargo": "Cargo",
                    "secretaria": "Secretaria",
                    "setor": "Departamento",
                },
                {
                    "lancamentos": [
                        {
                            "data": "2026-06-04",
                            "horas_base": "02:00",
                            "percentual": 50,
                            "minutos_creditados": 180,
                            "consumido": 60,
                            "descricao": f"Lançamento de teste {i}",
                        }
                        for i in range(80)
                    ],
                    "compensacoes": [],
                    "pagamentos": [],
                    "eleicao_creditos": [],
                    "eleicao_baixas": [],
                    "saldo": 0,
                    "saldo_eleicao": 0,
                },
                "historico_teste",
            )
        self.assertTrue(pdf.data.startswith(b"%PDF"))
        self.assertTrue(history.data.startswith(b"%PDF"))
        self.assertTrue(xlsx.data.startswith(b"PK"))


if __name__ == "__main__":
    unittest.main()

import unittest

from app import app, fmt_cpf, somente_digitos


class BasicRegressionTests(unittest.TestCase):
    def test_cpf_helpers(self):
        self.assertEqual(somente_digitos("123.456.789-00"), "12345678900")
        self.assertEqual(fmt_cpf("12345678900"), "123.456.789-00")
        self.assertEqual(fmt_cpf(""), "\u2013")

    def test_no_duplicate_routes(self):
        routes = [str(rule.rule) for rule in app.url_map.iter_rules()]
        duplicates = sorted({route for route in routes if routes.count(route) > 1})
        self.assertEqual(duplicates, [])

    def test_master_view_switch_requires_login(self):
        client = app.test_client()
        response = client.post("/admin/alternar-visao", data={"visao": "chefia"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers.get("Location", ""))


if __name__ == "__main__":
    unittest.main()

"""Run with:  python -m pytest -q   (or)   python -m unittest discover -s tests -v"""
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evas import engine, security
from evas.cvss import base_score, severity_from_score
from evas.demo import sample_result
from evas.models import CheckStatus, Target
from evas.reports import pdf_report
from evas.reports.html_report import build_html
from evas.reports.json_report import build_json
from evas.reports.ticket import build_ticket_md
from evas.rules import RULES, make_finding
from evas.scanners.base import CheckOutput
from evas.scanners.http_checks import _cookie_issues, _looks_like_env, _looks_like_git
from evas.scoring import compute_risk
from evas.security import TargetError, is_public_ip, parse_target


def fake_resolver(ip):
    return lambda host, *a, **k: [(2, 1, 6, "", (ip, 0))]


class CvssTests(unittest.TestCase):
    def test_reference_vectors(self):
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"), 5.4)

    def test_severity_bands(self):
        self.assertEqual([severity_from_score(x) for x in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0)],
                         ["Info", "Low", "Medium", "Medium", "High", "High", "Critical"])

    def test_every_rule_is_valid(self):
        for rule_id, rule in RULES.items():
            f = make_finding(rule_id, "h", "t", {})
            self.assertEqual(f.severity, severity_from_score(f.cvss_score), rule_id)
            self.assertTrue(rule.title["ar"] and rule.title["en"] and rule.fix["ar"] and rule.fix["en"], rule_id)


class TargetTests(unittest.TestCase):
    def test_non_public_addresses_rejected(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1",
                   "::ffff:127.0.0.1", "224.0.0.1", "0.0.0.0", "100.64.0.1"):
            self.assertFalse(is_public_ip(ip), ip)
        self.assertTrue(is_public_ip("8.8.8.8"))

    def test_ip_targets(self):
        self.assertEqual(parse_target("8.8.8.8").kind, "ip")
        for bad in ("127.0.0.1", "http://10.1.2.3/admin", "[::1]"):
            with self.assertRaises(TargetError) as ctx:
                parse_target(bad)
            self.assertEqual(ctx.exception.code, "restricted", bad)

    def test_syntax_rejections(self):
        cases = {"": "empty", "   ": "empty", "ftp://example.com": "invalid", "localhost": "invalid",
                 "0x7f000001": "invalid", "2130706433": "invalid", "exa mple.com": "invalid",
                 "https://user:pw@example.com": "credentials", "example.com:22": "port"}
        with mock.patch.object(security.socket, "getaddrinfo", fake_resolver("93.184.216.34")):
            for raw, code in cases.items():
                with self.assertRaises(TargetError, msg=raw) as ctx:
                    parse_target(raw)
                self.assertEqual(ctx.exception.code, code, raw)

    def test_domain_resolving_to_private_ip_is_blocked(self):
        with mock.patch.object(security.socket, "getaddrinfo", fake_resolver("10.0.0.7")):
            with self.assertRaises(TargetError) as ctx:
                parse_target("internal.example.com")
        self.assertEqual(ctx.exception.code, "restricted")

    def test_mixed_resolution_is_blocked(self):
        infos = [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("127.0.0.1", 0))]
        with mock.patch.object(security.socket, "getaddrinfo", return_value=infos):
            with self.assertRaises(TargetError):
                parse_target("rebind.example.com")

    def test_valid_url_and_email(self):
        with mock.patch.object(security.socket, "getaddrinfo", fake_resolver("93.184.216.34")):
            t = parse_target("Example.COM/path?x=1")
            self.assertEqual((t.kind, t.host, t.scheme, t.path, t.port), ("url", "example.com", "https", "/path", None))
            self.assertEqual(parse_target("https://example.com:8443/").port, 8443)
        e = parse_target("Admin@Example.com")
        self.assertEqual((e.kind, e.host), ("email", "example.com"))


class ScannerHelperTests(unittest.TestCase):
    def test_env_detection_ignores_html_and_redacts(self):
        self.assertEqual(_looks_like_env(b"APP_KEY=secret\nDB_PASSWORD=hunter2\n# c\n"), ["APP_KEY", "DB_PASSWORD"])
        self.assertEqual(_looks_like_env(b"<html><body>Not found</body></html>"), [])

    def test_git_detection(self):
        self.assertTrue(_looks_like_git(b"ref: refs/heads/main\n"))
        self.assertFalse(_looks_like_git(b"<html>404</html>"))

    def test_cookie_flags_never_store_values(self):
        issues = _cookie_issues(["sid=SECRETVALUE; Path=/; Secure; HttpOnly; SameSite=Lax", "pref=1; Path=/"], True)
        self.assertEqual(issues, [{"cookie": "pref", "missing": ["Secure", "HttpOnly", "SameSite"]}])
        self.assertNotIn("SECRETVALUE", json.dumps(issues))


class ScoringTests(unittest.TestCase):
    def test_bands(self):
        ok = [CheckStatus("http", "ok")]
        self.assertEqual(compute_risk([], ok).band, "none")
        self.assertEqual(compute_risk([], [CheckStatus("http", "failed")]).band, "unknown")
        crit = make_finding("EXPOSE-ENV", "h", "s", {}, confidence=0.98)
        self.assertIn(compute_risk([crit], ok).band, ("high", "critical"))
        low = make_finding("HDR-XCTO", "h", "s", {})
        self.assertEqual(compute_risk([low], ok).band, "low")

    def test_score_is_capped(self):
        many = [make_finding("EXPOSE-ENV", "h", "s", {}, key=str(i)) for i in range(50)]
        self.assertLessEqual(compute_risk(many, [CheckStatus("x", "ok")]).score, 100.0)


class EngineTests(unittest.TestCase):
    def test_failing_check_does_not_abort_scan(self):
        def boom(ctx):
            raise RuntimeError("kaput")

        def fine(ctx):
            return CheckOutput(findings=[make_finding("HDR-XCTO", ctx.target.host, "t", {})])

        plan = {"a": (boom, {"ip"}), "b": (fine, {"ip"})}
        t = Target(raw="8.8.8.8", kind="ip", host="8.8.8.8", ips=("8.8.8.8",))
        with mock.patch.dict(engine.CHECKS, plan, clear=True):
            res = engine.run_scan(t, engine.ScanOptions())
        status = {c.id: c.status for c in res.checks}
        self.assertEqual(status, {"a": "failed", "b": "ok"})
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.risk.coverage, 0.5)


class ReportTests(unittest.TestCase):
    def test_html_escapes_untrusted_values(self):
        res = sample_result()
        res.findings[0].evidence["value"] = "<script>alert(1)</script>"
        res.observations[0].value = '"><img src=x onerror=alert(1)>'
        for lang in ("en", "ar"):
            page = build_html(res, lang)
            self.assertNotIn("<script>alert(1)</script>", page)
            self.assertNotIn("<img src=x", page)
            self.assertIn("&lt;script&gt;", page)

    def test_json_and_ticket(self):
        res = sample_result()
        self.assertEqual(json.loads(build_json(res))["report_id"], res.report_id)
        self.assertIn("P1", build_ticket_md(res, "en"))
        self.assertIn("P1", build_ticket_md(res, "ar"))

    def test_pdf_english(self):
        data, used = pdf_report.generate_pdf(sample_result(), "en")
        self.assertTrue(data.startswith(b"%PDF"))
        self.assertEqual(used, "en")

    def test_pdf_arabic_falls_back_without_shaping_libs(self):
        with mock.patch.object(pdf_report, "HAVE_BIDI", False):
            _, used = pdf_report.generate_pdf(sample_result(), "ar")
        self.assertEqual(used, "en")

    def test_pdf_arabic_code_path_runs(self):
        """Exercises the RTL layout with stand-ins for arabic_reshaper / bidi."""
        fake_reshaper = SimpleNamespace(reshape=lambda s: s)
        with mock.patch.object(pdf_report, "HAVE_BIDI", True), \
             mock.patch.object(pdf_report, "arabic_reshaper", fake_reshaper, create=True), \
             mock.patch.object(pdf_report, "get_display", lambda s, base_dir=None: s, create=True):
            data, used = pdf_report.generate_pdf(sample_result(), "ar")
        self.assertEqual(used, "ar")
        self.assertTrue(data.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()

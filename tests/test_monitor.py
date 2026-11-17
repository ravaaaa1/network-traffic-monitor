import json
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch
from zoneinfo import ZoneInfo

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from traffic_monitor.__main__ import deliver
from traffic_monitor.audit import AuditJournal
from traffic_monitor.core import NetworkTrafficAnalyzer, Packet, demo_packets, read_packets
from traffic_monitor.integrations import AWSCloudWatch, AzureMonitor, BiometricVerifier, MISP, OTX, Slack, Telegram
from traffic_monitor.roi import Scenario, calculate, run_roi


KEY = bytes(range(32))


class MonitorTests(unittest.TestCase):
    def test_demo(self):
        analyzer = NetworkTrafficAnalyzer(timezone="UTC")
        report = analyzer.analyze(list(demo_packets()))
        self.assertEqual(report["packets"], 13_600)
        self.assertGreater(report["policy_violations"]["blocked_ports"][21], 0)
        incident, = report["incidents"]
        self.assertEqual(incident["type"], "SUSPECTED_DDOS")
        self.assertEqual(incident["peak_pps"], 1200)
        self.assertEqual(incident["duration_seconds"], 3)

    def test_separate_destinations_windows_and_source_counts(self):
        start = datetime(2026, 11, 16, tzinfo=UTC)
        packets = [
            Packet(start + timedelta(seconds=second), source, target, "HTTPS", 443, 100, "IT")
            for second, sources in ((0, (1, 2)), (1, (1, 2)), (3, (1, 2)), (4, (1, 1)), (5, (1, 1)))
            for source in (f"203.0.113.{value}" for value in sources)
            for target in ("192.168.1.1", "192.168.1.2")
        ]
        analyzer = NetworkTrafficAnalyzer(2, 2, 2, timezone="UTC")
        incidents = analyzer.detect_ddos(reversed(packets))
        self.assertEqual(
            [(i["destination"], i["type"], i["duration_seconds"]) for i in incidents],
            [
                ("192.168.1.1", "SUSPECTED_DDOS", 2), ("192.168.1.1", "PPS_SPIKE", 2),
                ("192.168.1.2", "SUSPECTED_DDOS", 2), ("192.168.1.2", "PPS_SPIKE", 2),
            ],
        )

    def test_csv_timezone_and_invalid_row(self):
        header = "timestamp,source_ip,destination_ip,protocol,port,size_bytes,department\n"
        with TemporaryDirectory() as folder:
            path = Path(folder) / "packets.csv"
            path.write_text(header + "2026-11-16T13:00:00+10:00,203.0.113.2,192.168.1.8,https,443,120,IT\n")
            packet, = read_packets(path, ZoneInfo("UTC"))
            self.assertEqual(packet.timestamp.hour, 3)
            self.assertEqual(packet.protocol, "HTTPS")
            path.write_text(header + "2026-11-16T13:00:00,invalid,192.168.1.8,https,443,120,IT\n")
            with self.assertRaisesRegex(ValueError, "№2"):
                list(read_packets(path, ZoneInfo("UTC")))
            path.write_text("invalid,header\n")
            with self.assertRaisesRegex(ValueError, "обязательные столбцы"):
                list(read_packets(path, ZoneInfo("UTC")))


class AuditTests(unittest.TestCase):
    def test_tamper_and_truncation(self):
        with TemporaryDirectory() as folder:
            journal = AuditJournal(Path(folder) / "audit.sqlite", KEY)
            journal.record("start", "ok", {})
            first = journal.verify()
            journal.record("finish", "ok", {})
            head = journal.verify(first)
            with journal.connection() as connection:
                connection.execute("UPDATE audit SET body = '{}' WHERE sequence = 2")
            with self.assertRaises(ValueError):
                journal.verify()
            with journal.connection() as connection:
                connection.execute("DELETE FROM audit WHERE sequence = 2")
            with self.assertRaises(ValueError):
                journal.verify(head)

    def test_replay_rollback(self):
        with TemporaryDirectory() as folder:
            journal = AuditJournal(Path(folder) / "audit.sqlite", KEY)
            journal.record("biometric_check", "ok", {}, assertion_id="issuer-jti-hash")
            with self.assertRaises(ValueError):
                journal.record("biometric_check", "ok", {}, assertion_id="issuer-jti-hash")
            self.assertEqual(journal.verify()[0], 1)


class IntegrationTests(unittest.TestCase):
    def test_incomplete_telegram_config_does_not_prevent_slack(self):
        settings = {"TELEGRAM_BOT_TOKEN": "1:token", "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/a/b/c"}
        report = {"packets": 4, "incidents": [{
            "type": "SUSPECTED_DDOS", "destination": "192.168.1.1", "peak_pps": 2,
            "duration_seconds": 2, "window_start": "2026-11-16T00:00:00+00:00",
            "top_sources": ["203.0.113.1"],
        }]}
        with (
            TemporaryDirectory() as folder,
            patch.dict("os.environ", settings, clear=True),
            patch("traffic_monitor.__main__.Slack") as slack,
        ):
            journal = AuditJournal(Path(folder) / "audit.sqlite", KEY)
            statuses = deliver(report, journal, "run")
            self.assertEqual([(x["provider"], x["outcome"]) for x in statuses],
                             [("telegram", "error"), ("slack", "ok")])
            slack.return_value.send.assert_called_once()

    def test_messaging_adapters(self):
        telegram = Mock(return_value={"ok": True})
        Telegram("1:token", "-101", telegram).send("Alert")
        telegram.assert_called_once_with(
            "https://api.telegram.org/bot1:token/sendMessage", {"chat_id": "-101", "text": "Alert"}
        )
        slack = Mock(return_value=b"ok")
        Slack("https://hooks.slack.com/services/a/b/c", slack).send("Alert")
        slack.assert_called_once_with(
            "https://hooks.slack.com/services/a/b/c", {"text": "Alert"}, json_response=False
        )
        telegram.return_value = {"ok": False}
        with self.assertRaises(ValueError):
            Telegram("1:token", "-101", telegram).send("Alert")

    def test_cloud_adapters(self):
        aws, azure = Mock(), Mock()
        AWSCloudWatch(aws).publish(10000, 1, 1200)
        metrics = aws.put_metric_data.call_args.kwargs
        self.assertEqual(metrics["Namespace"], "TechnoProfi/NetworkMonitor")
        self.assertEqual(metrics["MetricData"][2]["Value"], 1200)
        AzureMonitor(azure, "dcr-test", "Custom-Network_CL").publish(10000, 1, 1200)
        log = azure.upload.call_args.kwargs
        self.assertEqual(log["rule_id"], "dcr-test")
        self.assertEqual(log["logs"][0]["DDoSIncidents"], 1)

    def test_threat_intelligence_adapters(self):
        address = "2001:db8::5"
        misp = Mock(return_value={"response": {"Attribute": [{"value": address}, {"value": "1.1.1.1"}]}})
        self.assertEqual(MISP("https://misp.example", "key", misp).lookup(address), 1)
        self.assertEqual(misp.call_args.args[1]["value"], address)
        otx = Mock(return_value={"pulse_info": {"count": 2}})
        self.assertEqual(OTX("key", otx).lookup(address), 2)
        self.assertIn("/IPv6/", otx.call_args.args[0])

    def test_delivery_isolates_failures(self):
        report = {
            "packets": 4000, "incidents": [{
                "type": "SUSPECTED_DDOS", "destination": "192.168.1.1", "peak_pps": 2000,
                "duration_seconds": 2, "window_start": "2026-11-16T00:00:00+00:00",
                "top_sources": ["192.168.1.100", "8.8.8.8"],
            }],
        }
        channel = Mock(side_effect=RuntimeError("test secret"))
        cloud = Mock()
        tasks = [
            ("telegram", Mock(return_value=SimpleNamespace(send=channel)), (), "send", ("Alert",), []),
            ("aws", Mock(return_value=SimpleNamespace(publish=cloud)), (), "publish", (4000, 1, 2000), []),
        ]
        with TemporaryDirectory() as folder, patch("traffic_monitor.__main__.delivery_tasks", return_value=tasks):
            journal = AuditJournal(Path(folder) / "audit.sqlite", KEY)
            self.assertEqual([item["outcome"] for item in deliver(report, journal, "run")], ["error", "ok"])
            cloud.assert_called_once_with(4000, 1, 2000)
            with journal.connection() as connection:
                rows = connection.execute("SELECT body FROM audit ORDER BY sequence").fetchall()
            self.assertEqual(json.loads(rows[0][0])["details"]["error_type"], "RuntimeError")
            self.assertNotIn("test secret", rows[0][0])

    def test_biometric_assertion(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwks = Mock()
        jwks.get_signing_key_from_jwt.return_value.key = private_key.public_key()
        verifier = BiometricVerifier("https://id.example", "monitor", "https://id.example/jwks", jwks)
        now = int(time.time())
        claims = {
            "iss": "https://id.example", "aud": "monitor", "sub": "operator", "jti": "test-one",
            "auth_time": now - 5, "iat": now, "exp": now + 60, "amr": ["face"],
        }

        def sign(data):
            return jwt.encode(data, private_key, algorithm="RS256", headers={"kid": "test"})

        self.assertEqual(len(verifier.verify(sign(claims))), 64)
        with self.assertRaises(ValueError):
            verifier.verify(sign({**claims, "amr": ["pin"]}))
        for changes in ({"aud": "other"}, {"iat": now - 30, "exp": now - 15}):
            with self.assertRaises(jwt.InvalidTokenError):
                verifier.verify(sign({**claims, **changes}))
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(jwt.InvalidSignatureError):
            verifier.verify(jwt.encode(claims, wrong_key, algorithm="RS256"))


class ROITests(unittest.TestCase):
    def test_scenarios(self):
        result = run_roi()
        self.assertEqual(result["base"]["first_year_roi_percent"], 39.9)
        self.assertEqual(result["base"]["saved_hours"], 36)
        self.assertEqual(result["base"]["leakage_savings_usd"], 19_960)
        self.assertEqual(result["conservative"]["first_year_roi_percent"], -30.05)
        self.assertEqual(result["optimistic"]["first_year_roi_percent"], 87.35)
        with self.assertRaises(ValueError):
            calculate(Scenario(downtime_reduction=1.1))

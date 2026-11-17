import io
import json
import sys
import unittest
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from traffic_monitor.__main__ import main
from traffic_monitor.audit import AuditJournal
from traffic_monitor.live import LiveDetector, capture_windows


class LiveTests(unittest.TestCase):
    def test_alerts_on_second_complete_window_and_rearms_after_gap(self):
        detector = LiveDetector(3, 2, 2)
        destinations = {
            "192.168.1.1": Counter({"203.0.113.1": 2, "203.0.113.2": 1}),
            "192.168.1.2": Counter({"203.0.113.1": 3}),
        }
        self.assertEqual(detector.close_window(10, destinations), [])
        self.assertEqual(
            [event["type"] for event in detector.close_window(11, destinations)],
            ["SUSPECTED_DDOS", "PPS_SPIKE"],
        )
        self.assertEqual(detector.close_window(12, destinations), [])
        self.assertEqual(detector.close_window(14, destinations), [])
        self.assertEqual(len(detector.close_window(15, destinations)), 2)

    def test_capture_counts_only_complete_windows_and_stops_sniffer(self):
        class IPv4:
            src = "203.0.113.1"
            dst = "192.168.1.1"

        class IPv6:
            src = "2001:db8::1"
            dst = "2001:db8::2"

        now = [1000.2]
        sniffer = Mock()
        # Advance the same clock used by the sniffer callback and the reader.
        def create_sniffer(**kwargs):
            def start():
                kwargs["started_callback"]()
                kwargs["prn"](IPv4())
                now[0] = 1001.2
                kwargs["prn"](SimpleNamespace(payload=IPv4()))
                kwargs["prn"](IPv6())
                now[0] = 1002.2
                kwargs["prn"](IPv4())
            sniffer.start.side_effect = start
            return sniffer

        scapy = SimpleNamespace(AsyncSniffer=create_sniffer, IP=IPv4, IPv6=IPv6)
        with (
            patch.dict(sys.modules, {"scapy.all": scapy, "scapy.error": SimpleNamespace(Scapy_Exception=RuntimeError)}),
            patch("traffic_monitor.live.monotonic", side_effect=lambda: now[0]),
            patch("traffic_monitor.live.time", side_effect=lambda: now[0]),
        ):
            windows = capture_windows("test-device")
            second, destinations = next(windows)
            self.assertEqual(second, 1001)
            self.assertEqual(destinations, {
                "192.168.1.1": Counter({"203.0.113.1": 1}),
                "2001:db8::2": Counter({"2001:db8::1": 1}),
            })
            windows.close()
        sniffer.stop.assert_called_once()

    def test_watch_cli_audits_and_delivers_live_alert(self):
        key = bytes(range(32))
        counts = {"192.168.1.10": Counter({"203.0.113.1": 2, "203.0.113.2": 1})}
        with TemporaryDirectory() as folder:
            path = Path(folder) / "audit.sqlite"
            argv = ["traffic_monitor", "--audit-db", str(path), "watch", "--interface",
                    "test", "--pps", "3", "--sources", "2", "--deliver"]
            with (
                patch.object(sys, "argv", argv),
                patch.dict("os.environ", {"AUDIT_KEY_HEX": key.hex()}, clear=True),
                patch("traffic_monitor.__main__.capture_windows", return_value=(x for x in [(10, counts), (11, counts)])),
                patch("traffic_monitor.__main__.deliver", return_value=[]) as delivery,
                redirect_stdout(io.StringIO()) as stdout,
            ):
                self.assertEqual(main(), 0)
            event = json.loads(stdout.getvalue())
            self.assertEqual(event["peak_pps"], 3)
            self.assertTrue(delivery.call_args.kwargs["channels_only"])
            self.assertEqual(AuditJournal(path, key, read_only=True).verify()[0], 3)

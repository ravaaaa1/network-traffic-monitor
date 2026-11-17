"""Command-line entry point for the monitoring prototype."""

import argparse
import json
import os
import sqlite3
import sys
from contextlib import closing
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4
from zoneinfo import ZoneInfoNotFoundError

from .audit import AuditJournal
from .core import NetworkTrafficAnalyzer, demo_packets, read_packets
from .integrations import AWSCloudWatch, AzureMonitor, BiometricVerifier, MISP, OTX, Slack, Telegram
from .live import LiveDetector, capture_windows
from .roi import run_roi


def settings(*names):
    values = tuple(os.getenv(name, "") for name in names)
    if any(values) and not all(values):
        missing = ", ".join(name for name, value in zip(names, values) if not value)
        raise ValueError(f"Не заданы переменные: {missing}")
    return values if all(values) else None


def aws_adapter(region):
    import boto3
    from botocore.config import Config

    client = boto3.client("cloudwatch", region_name=region, config=Config(
        connect_timeout=5, read_timeout=5, retries={"total_max_attempts": 2},
    ))
    return AWSCloudWatch(client)


def azure_adapter(endpoint, rule, stream):
    from azure.identity import DefaultAzureCredential
    from azure.monitor.ingestion import LogsIngestionClient

    client = LogsIngestionClient(endpoint, DefaultAzureCredential(), retry_total=0,
                                 connection_timeout=5, read_timeout=5)
    return AzureMonitor(client, rule, stream)


def delivery_tasks(report, channels_only=False):
    ddos = [incident for incident in report["incidents"] if incident["type"] == "SUSPECTED_DDOS"]
    message = "\n".join(
        f"Подозрение на DDoS · {x['destination']} · пик {x['peak_pps']} пакетов/с · "
        f"{x['duration_seconds']} с · {x['window_start']}"
        for x in ddos[:10]
    )
    if len(ddos) > 10:
        message += f"\nОстальные инциденты в отчёте: {len(ddos) - 10}"
    metrics = (report["packets"], len(ddos), max((x["peak_pps"] for x in ddos), default=0))
    addresses = sorted({
        ip for incident in ddos for ip in incident["top_sources"] if ip_address(ip).is_global
    })[:10]

    specs = [
        ("telegram", ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"), Telegram, "send", (message,), bool(ddos)),
        ("slack", ("SLACK_WEBHOOK_URL",), Slack, "send", (message,), bool(ddos)),
    ]
    if not channels_only:
        specs.extend([
            ("aws", ("MONITOR_AWS_REGION",), aws_adapter, "publish", metrics, True),
            ("azure", ("AZURE_LOG_ENDPOINT", "AZURE_DCR_ID", "AZURE_STREAM"), azure_adapter, "publish", metrics, True),
            ("misp", ("MISP_URL", "MISP_API_KEY"), MISP, "lookup", (), bool(addresses)),
            ("otx", ("OTX_API_KEY",), OTX, "lookup", (), bool(addresses)),
        ])
    for name, variables, factory, method, arguments, enabled in specs:
        if enabled and any(os.getenv(variable) for variable in variables):
            yield name, factory, variables, method, arguments, addresses


def deliver(report, journal, run_id, channels_only=False):
    tasks = list(delivery_tasks(report, channels_only))
    if not tasks:
        journal.record("delivery", "skipped", {"reason": "no_applicable_adapters"}, run_id=run_id)
    statuses = []
    for name, factory, variables, method, arguments, addresses in tasks:
        try:
            config = settings(*variables) if variables else ()
            operation = getattr(factory(*config), method)
        except Exception as error:
            journal.record("integration", "error", {
                "provider": name, "error_type": type(error).__name__,
            }, run_id=run_id)
            statuses.append({"provider": name, "outcome": "error", "error_type": type(error).__name__})
            continue
        for parameters in ([(ip,) for ip in addresses] if method == "lookup" else [arguments]):
            details = {"provider": name}
            outcome = "ok"
            if method == "lookup":
                details["indicator"] = parameters[0]
            try:
                value = operation(*parameters)
                if method == "lookup":
                    details["matches"] = value
            except Exception as error:
                outcome = "error"
                details["error_type"] = type(error).__name__
            journal.record("integration", outcome, details, run_id=run_id)
            statuses.append({"outcome": outcome, **details})
    return statuses


def parse_args():
    parser = argparse.ArgumentParser(description="Мониторинг сетевого трафика ТехноПрофи")
    parser.add_argument("--audit-db", type=Path, default=Path("audit.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)

    monitor = commands.add_parser("monitor")
    source = monitor.add_mutually_exclusive_group(required=True)
    source.add_argument("--demo", action="store_true")
    source.add_argument("--csv", type=Path)
    monitor.add_argument("--timezone", default="Asia/Vladivostok")
    monitor.add_argument("--internal-network", action="append", default=None)
    monitor.add_argument("--output", type=Path)

    watch = commands.add_parser("watch", help="Анализ PPS с сетевого интерфейса")
    watch.add_argument("--interface", required=True)
    watch.add_argument("--duration", type=int, help="Длительность захвата в секундах")
    for command in (monitor, watch):
        command.add_argument("--pps", type=int, default=1000)
        command.add_argument("--sources", type=int, default=10)
        command.add_argument("--seconds", type=int, default=2)
        command.add_argument("--deliver", action="store_true")

    verify = commands.add_parser("verify-audit")
    verify.add_argument("--checkpoint", type=Path)

    commands.add_parser("verify-biometrics", help="Проверить утверждение провайдера из stdin")
    roi = commands.add_parser("roi")
    roi.add_argument("scenario", type=Path, nargs="?")
    return parser.parse_args()


def run_monitor(args, journal, run_id):
    if args.output and args.output.resolve() == args.audit_db.resolve():
        raise ValueError("Путь отчёта совпадает с файлом журнала")
    analyzer = NetworkTrafficAnalyzer(
        args.pps, args.sources, args.seconds, args.timezone,
        args.internal_network or ["192.168.1.0/24"],
    )
    journal.record("monitor_start", "ok", {
        "mode": "demo" if args.demo else "csv", "pps": args.pps, "sources": args.sources,
        "seconds": args.seconds,
    }, run_id=run_id)
    packets = list(demo_packets() if args.demo else read_packets(args.csv, analyzer.timezone))
    report = analyzer.analyze(packets)
    report["run_id"] = run_id
    for incident in report["incidents"]:
        journal.record("incident", "detected", incident, run_id=run_id)
    report["integrations"] = deliver(report, journal, run_id) if args.deliver else []
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    failed = any(x["outcome"] == "error" for x in report["integrations"])
    journal.record("monitor_finish", "partial" if failed else "ok", {
        "packets": report["packets"], "incidents": len(report["incidents"]),
        "policy_violations": report["policy_violations"],
    }, run_id=run_id)
    return 2 if failed else 0


def run_watch(args, journal, run_id):
    if args.duration is not None and args.duration < 1:
        raise ValueError("Длительность захвата должна быть положительной")
    detector = LiveDetector(args.pps, args.sources, args.seconds)
    journal.record("monitor_start", "ok", {
        "mode": "live", "pps": args.pps, "sources": args.sources, "seconds": args.seconds,
    }, run_id=run_id)
    packets = incidents = 0
    failed = False
    stop_reason = "duration_elapsed"
    try:
        with closing(capture_windows(args.interface, args.duration)) as windows:
            for second, counts in windows:
                packet_count = sum(sources.total() for sources in counts.values())
                packets += packet_count
                detected = detector.close_window(second, counts)
                for incident in detected:
                    incidents += 1
                    journal.record("incident", "detected", incident, run_id=run_id)
                    print(json.dumps({"run_id": run_id, **incident}, ensure_ascii=False), flush=True)
                if args.deliver and any(i["type"] == "SUSPECTED_DDOS" for i in detected):
                    statuses = deliver({"packets": packet_count, "incidents": detected},
                                       journal, run_id, channels_only=True)
                    failed |= any(status["outcome"] == "error" for status in statuses)
    except KeyboardInterrupt:
        stop_reason = "operator_stop"
    journal.record("monitor_finish", "partial" if failed else "ok", {
        "packets": packets, "incidents": incidents, "stop_reason": stop_reason,
    }, run_id=run_id)
    return 2 if failed else 0


def main():
    args = parse_args()
    run_id = uuid4().hex
    journal_ready = False
    try:
        if args.command == "roi":
            print(json.dumps(run_roi(args.scenario), ensure_ascii=False, indent=2))
            return 0

        if args.command == "verify-audit" and not args.audit_db.is_file():
            raise ValueError("Файл журнала отсутствует")
        journal = AuditJournal(
            args.audit_db, bytes.fromhex(os.getenv("AUDIT_KEY_HEX", "")),
            read_only=args.command == "verify-audit",
        )
        checkpoint = None
        if args.command == "verify-audit" and args.checkpoint:
            saved = json.loads(args.checkpoint.read_text(encoding="utf-8-sig"))
            checkpoint = (saved["records"], saved["head_mac"])
        count, head = journal.verify(checkpoint)
        journal_ready = True

        if args.command == "verify-audit":
            print(json.dumps({"records": count, "head_mac": head}))
            return 0
        if args.command == "monitor":
            return run_monitor(args, journal, run_id)
        if args.command == "watch":
            return run_watch(args, journal, run_id)

        config = settings("BIOMETRIC_ISSUER", "BIOMETRIC_AUDIENCE", "BIOMETRIC_JWKS_URL")
        if not config:
            raise ValueError("Не заданы параметры биометрического провайдера")
        try:
            assertion = BiometricVerifier(*config).verify(sys.stdin.read(16_385).strip())
            journal.record("biometric_check", "ok", {}, actor="identity_provider",
                           run_id=run_id, assertion_id=assertion)
        except Exception as error:
            journal.record("biometric_check", "denied", {"error_type": type(error).__name__},
                           actor="identity_provider", run_id=run_id)
            print("Биометрическое утверждение отклонено", file=sys.stderr)
            return 1
        print("Биометрическое утверждение подтверждено")
        return 0
    except (ValueError, KeyError, OSError, sqlite3.Error, ZoneInfoNotFoundError) as error:
        if journal_ready and args.command in {"monitor", "watch"}:
            try:
                journal.record("monitor_error", "error", {"error_type": type(error).__name__}, run_id=run_id)
            except sqlite3.Error:
                print("Не удалось записать сбой в аудит", file=sys.stderr)
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

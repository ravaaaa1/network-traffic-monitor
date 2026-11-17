"""Packet input and a batch analyzer compatible with the lecture's CSV columns."""

import csv
import ipaddress
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class Packet:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    size_bytes: int
    department: str


def read_packets(path, timezone):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for row_number, row in enumerate(csv.DictReader(stream), 2):
            try:
                timestamp = datetime.fromisoformat(row["timestamp"])
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone)
                port, size = int(row["port"]), int(row["size_bytes"])
                if not 0 <= port <= 65535 or size < 0:
                    raise ValueError()
                yield Packet(
                    timestamp.astimezone(UTC), str(ipaddress.ip_address(row["source_ip"])),
                    str(ipaddress.ip_address(row["destination_ip"])),
                    row["protocol"].strip().upper(), port, size, row["department"].strip(),
                )
            except (ValueError, KeyError, TypeError) as error:
                raise ValueError(f"Некорректная строка CSV №{row_number}") from error


def demo_packets():
    rng = random.Random(42)
    start = datetime(2026, 11, 16, tzinfo=UTC)
    protocols = {"HTTPS": 443, "HTTP": 80, "DNS": 53, "SSH": 22, "FTP": 21}
    for _ in range(10_000):
        protocol = rng.choice(tuple(protocols))
        destination = rng.choice(("192.168.1.10", "192.168.1.20", "198.51.100.10"))
        yield Packet(
            start + timedelta(seconds=rng.randrange(86400)),
            f"192.168.1.{rng.randint(40, 90)}", destination, protocol, protocols[protocol],
            rng.randint(64, 1500), rng.choice(("Продажи", "IT", "Финансы")),
        )
    for second in range(3):
        for index in range(1_200):
            yield Packet(
                start + timedelta(hours=3, seconds=second, microseconds=index * 500),
                f"203.0.113.{1 + index % 40}", "192.168.1.10", "HTTPS", 443, 80, "Внешний",
            )


def instant(seconds):
    return datetime.fromtimestamp(seconds, UTC).isoformat()


class NetworkTrafficAnalyzer:
    def __init__(self, pps_threshold=1000, min_sources=10, consecutive_seconds=2,
                 timezone="Asia/Vladivostok", internal_networks=("192.168.1.0/24",)):
        if min(pps_threshold, min_sources, consecutive_seconds) < 1:
            raise ValueError("Пороги должны быть положительными")
        self.pps_threshold = pps_threshold
        self.min_sources = min_sources
        self.consecutive_seconds = consecutive_seconds
        self.timezone = ZoneInfo(timezone)
        self.internal_networks = tuple(map(ipaddress.ip_network, internal_networks))

    def is_internal(self, address):
        return any(ipaddress.ip_address(address) in network for network in self.internal_networks)

    def detect_ddos(self, packets):
        window = defaultdict(Counter)
        for packet in packets:
            second = int(packet.timestamp.replace(microsecond=0).timestamp())
            window[packet.destination_ip, second][packet.source_ip] += 1

        incidents = []
        active = None
        for (destination, second), sources in sorted(window.items()):
            pps = sources.total()
            kind = "SUSPECTED_DDOS" if len(sources) >= self.min_sources else "PPS_SPIKE"
            if pps < self.pps_threshold:
                continue
            if active and (active["destination"], active["kind"], active["last_second"]) == (
                destination, kind, second - 1
            ):
                active["last_second"] = second
                active["peak_pps"] = max(active["peak_pps"], pps)
                active["peak_sources_per_second"] = max(
                    active["peak_sources_per_second"], len(sources)
                )
                active["sources"].update(sources)
            else:
                active = {
                    "destination": destination, "kind": kind, "first_second": second,
                    "last_second": second, "peak_pps": pps,
                    "peak_sources_per_second": len(sources), "sources": sources.copy(),
                }
                incidents.append(active)

        output = []
        for incident in incidents:
            duration = incident["last_second"] - incident["first_second"] + 1
            if duration >= self.consecutive_seconds:
                output.append({
                    "type": incident["kind"],
                    "severity": "HIGH" if incident["kind"] == "SUSPECTED_DDOS" else "MEDIUM",
                    "destination": incident["destination"], "duration_seconds": duration,
                    "window_start": instant(incident["first_second"]),
                    "window_end_exclusive": instant(incident["last_second"] + 1),
                    "peak_pps": incident["peak_pps"],
                    "peak_sources_per_second": incident["peak_sources_per_second"],
                    "top_sources": [address for address, _ in incident["sources"].most_common(3)],
                })
        return output

    def analyze(self, packets):
        protocols, departments = Counter(), Counter()
        outbound, blocked, after_hours = Counter(), Counter(), Counter()
        scan_ports, scan_targets = defaultdict(set), defaultdict(set)
        total_bytes = 0
        for packet in packets:
            local_time = packet.timestamp.astimezone(self.timezone)
            protocols[packet.protocol] += 1
            departments[packet.department] += packet.size_bytes
            total_bytes += packet.size_bytes
            if self.is_internal(packet.source_ip) and not self.is_internal(packet.destination_ip):
                outbound[local_time.date().isoformat()] += packet.size_bytes
            if packet.port in {21, 23, 135, 139, 445}:
                blocked[packet.port] += 1
            if not 9 <= local_time.hour < 18:
                after_hours[packet.department] += 1
            scan_window = packet.source_ip, int(packet.timestamp.timestamp() // 300) * 300
            scan_ports[scan_window].add(packet.port)
            scan_targets[scan_window].add(packet.destination_ip)

        incidents = self.detect_ddos(packets)
        for (source, second), ports in sorted(scan_ports.items()):
            targets = scan_targets[source, second]
            if len(ports) > 50 and len(targets) > 10:
                incidents.append({
                    "type": "PORT_SCAN", "severity": "HIGH", "source": source,
                    "window_start": instant(second), "unique_ports": len(ports),
                    "unique_targets": len(targets),
                })
        violations = {
            "blocked_ports": dict(blocked),
            "after_hours_by_department": {k: n for k, n in after_hours.items() if n > 50},
            "external_volume_limit_exceeded": {
                day: count for day, count in outbound.items() if count > 10 * 1024**3
            },
        }
        return {
            "company": "ТехноПрофи", "packets": len(packets), "total_bytes": total_bytes,
            "packets_by_protocol": dict(protocols), "bytes_by_department": dict(departments),
            "outbound_bytes_by_day": dict(outbound), "policy_violations": violations,
            "incidents": incidents,
        }

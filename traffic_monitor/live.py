"""Live packet capture and detection on completed PPS windows."""

from collections import Counter, defaultdict
from threading import Event, Lock
from time import monotonic, time

from .core import instant, pps_kind


class LiveDetector:
    def __init__(self, threshold, min_sources, consecutive_seconds):
        if min(threshold, min_sources, consecutive_seconds) < 1:
            raise ValueError("Пороги должны быть положительными")
        self.threshold = threshold
        self.min_sources = min_sources
        self.consecutive_seconds = consecutive_seconds
        self.active = {}
        self.previous_second = None

    def close_window(self, second, destinations):
        previous = self.active if self.previous_second == second - 1 else {}
        self.previous_second = second
        self.active = {}
        incidents = []
        for destination, sources in destinations.items():
            kind = pps_kind(sources, self.threshold, self.min_sources)
            if kind is None:
                continue
            key = destination, kind
            duration, peak, unique_peak, total_sources = previous.get(key, (0, 0, 0, None))
            duration += 1
            peak = max(peak, sources.total())
            unique_peak = max(unique_peak, len(sources))
            if duration <= self.consecutive_seconds:
                total_sources = sources.copy() if total_sources is None else total_sources + sources
            if duration == self.consecutive_seconds:
                incidents.append({
                    "type": kind,
                    "severity": "HIGH" if kind == "SUSPECTED_DDOS" else "MEDIUM",
                    "destination": destination,
                    "duration_seconds": duration,
                    "window_start": instant(second + 1 - duration),
                    "window_end_exclusive": instant(second + 1),
                    "peak_pps": peak,
                    "peak_sources_per_second": unique_peak,
                    "top_sources": [address for address, _ in total_sources.most_common(3)],
                })
                total_sources = None
            self.active[key] = duration, peak, unique_peak, total_sources
        return incidents


def outer_network_layer(packet, network_types):
    while packet:
        if isinstance(packet, network_types):
            return packet
        packet = packet.payload
    return None


def capture_windows(interface, duration=None):
    try:
        from scapy.all import AsyncSniffer, IP, IPv6
        from scapy.error import Scapy_Exception
    except ImportError as error:
        raise ValueError("Установите Scapy для захвата пакетов") from error

    lock = Lock()
    started = Event()
    offset = time() - monotonic()
    windows = defaultdict(lambda: defaultdict(Counter))
    max_pending_windows = 120
    overflow = Event()
    first_whole_second = None

    def bucket():
        return int(monotonic() + offset)

    def capture_started():
        nonlocal first_whole_second
        first_whole_second = bucket() + 1
        started.set()

    def collect(packet):
        network = outer_network_layer(packet, (IP, IPv6))
        if network is not None and not overflow.is_set():
            with lock:
                second = bucket()
                if first_whole_second is not None and second >= first_whole_second:
                    if second not in windows and len(windows) >= max_pending_windows:
                        overflow.set()
                    else:
                        windows[second][network.dst][network.src] += 1

    sniffer = AsyncSniffer(
        iface=interface, store=False, prn=collect, started_callback=capture_started,
        promisc=False,
    )
    sniffer.start()
    try:
        if not started.wait(timeout=5):
            if not sniffer.thread.is_alive():
                sniffer.join()
            raise ValueError("Не удалось запустить захват на указанном интерфейсе")
        deadline = monotonic() + duration if duration is not None else None
        tick = Event()
        while sniffer.thread.is_alive():
            if overflow.is_set():
                raise ValueError("Переполнение буфера PPS при захвате")
            with lock:
                finished = [second for second in windows if second < bucket()]
                completed = [(second, windows.pop(second)) for second in sorted(finished)]
            yield from completed
            if deadline is not None and monotonic() >= deadline:
                return
            tick.wait(0.1)
        sniffer.join()
        raise ValueError("Захват пакетов завершился до остановки")
    except Scapy_Exception as error:
        raise ValueError("Захват Scapy не удался. Проверьте интерфейс, драйвер и права доступа") from error
    finally:
        if started.is_set() and sniffer.thread.is_alive():
            sniffer.stop()

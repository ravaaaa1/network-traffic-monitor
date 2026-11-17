"""Adapters for notifications, cloud telemetry, threat intelligence and biometrics."""

import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


def https_url(url, hosts=None):
    parts = urlsplit(url)
    if (
        parts.scheme != "https" or not parts.hostname or parts.username or
        parts.password or parts.fragment or (hosts and parts.hostname not in hosts)
    ):
        raise ValueError("Требуется доверенный HTTPS endpoint")
    return url


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(url, payload=None, headers=None, *, json_response=True):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    header_values = {"Accept": "application/json", **(headers or {})}
    if data is not None:
        header_values["Content-Type"] = "application/json"
    query = Request(https_url(url), data=data, headers=header_values)
    with build_opener(NoRedirect).open(query, timeout=5) as response:
        body = response.read(1_048_577)
        if len(body) > 1_048_576:
            raise ValueError("Слишком большой ответ API")
        return json.loads(body) if json_response else body


@dataclass
class Telegram:
    token: str
    chat_id: str
    transport: object = request

    def send(self, message):
        if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", self.token):
            raise ValueError("Некорректный формат Telegram токена")
        result = self.transport(f"https://api.telegram.org/bot{self.token}/sendMessage", {
            "chat_id": self.chat_id, "text": message,
        })
        if result.get("ok") is not True:
            raise ValueError("Telegram не подтвердил доставку")


@dataclass
class Slack:
    webhook: str
    transport: object = request

    def send(self, message):
        url = https_url(self.webhook, {"hooks.slack.com", "hooks.slack-gov.com"})
        if self.transport(url, {"text": message}, json_response=False).strip() != b"ok":
            raise ValueError("Slack не подтвердил доставку")


@dataclass
class MISP:
    base_url: str
    key: str
    transport: object = request

    def lookup(self, address):
        address = str(ipaddress.ip_address(address))
        url = https_url(self.base_url).rstrip("/") + "/attributes/restSearch"
        result = self.transport(url, {
            "returnFormat": "json", "value": address,
            "type": ["ip-src", "ip-dst"], "to_ids": True, "limit": 20,
        }, {"Authorization": self.key})
        attributes = result["response"]["Attribute"]
        if not isinstance(attributes, list):
            raise ValueError("Недействительный ответ MISP")
        return sum(item.get("value") == address for item in attributes)


@dataclass
class OTX:
    key: str
    transport: object = request

    def lookup(self, address):
        ip = ipaddress.ip_address(address)
        result = self.transport(
            f"https://otx.alienvault.com/api/v1/indicators/IPv{ip.version}/{ip}/general",
            headers={"X-OTX-API-KEY": self.key},
        )
        count = result["pulse_info"]["count"]
        if type(count) is not int or count < 0:
            raise ValueError("Недействительный ответ OTX")
        return count


@dataclass
class AWSCloudWatch:
    client: object
    namespace: str = "TechnoProfi/NetworkMonitor"

    def publish(self, packets, incidents, peak_pps):
        self.client.put_metric_data(Namespace=self.namespace, MetricData=[
            {"MetricName": "PacketsAnalyzed", "Unit": "Count", "Value": packets},
            {"MetricName": "DDoSIncidents", "Unit": "Count", "Value": incidents},
            {"MetricName": "PeakDDoSPPS", "Unit": "Count/Second", "Value": peak_pps},
        ])


@dataclass
class AzureMonitor:
    client: object
    rule_id: str
    stream: str

    def publish(self, packets, incidents, peak_pps):
        from datetime import UTC, datetime

        self.client.upload(rule_id=self.rule_id, stream_name=self.stream, logs=[{
            "TimeGenerated": datetime.now(UTC).isoformat(),
            "PacketsAnalyzed": packets, "DDoSIncidents": incidents, "PeakDDoSPPS": peak_pps,
        }])


class BiometricVerifier:
    """Verifies a short-lived assertion from a trusted biometric identity provider."""

    def __init__(self, issuer, audience, jwks_url, key_client=None):
        import jwt

        self.issuer = https_url(issuer)
        self.audience = audience
        self.key_client = key_client or jwt.PyJWKClient(https_url(jwks_url), timeout=5)

    def verify(self, token):
        import jwt

        if len(token) > 16_384 or jwt.get_unverified_header(token).get("alg") != "RS256":
            raise ValueError("Ожидается утверждение RS256")
        key = self.key_client.get_signing_key_from_jwt(token).key
        required = ["iss", "aud", "exp", "iat", "auth_time", "sub", "amr", "jti"]
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=self.issuer, audience=self.audience,
            options={"require": required, "strict_aud": True}, leeway=5,
        )
        methods = claims["amr"]
        if not isinstance(methods, list) or not any(m in methods for m in ("face", "fpt", "iris", "vbm")):
            raise ValueError("Провайдер не подтвердил биометрический метод")
        auth_time, issued, expires = (claims[name] for name in ("auth_time", "iat", "exp"))
        if (
            any(type(value) is not int for value in (auth_time, issued, expires))
            or not auth_time <= issued < expires <= auth_time + 300
            or time.time() - auth_time > 300
        ):
            raise ValueError("Биометрическое подтверждение просрочено")
        if not claims["sub"] or not claims["jti"]:
            raise ValueError("Пустой идентификатор утверждения")
        return hashlib.sha256(f"{self.issuer}\0{claims['jti']}".encode()).hexdigest()

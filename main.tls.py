#!/usr/bin/env python3
"""Асинхронный VLESS-over-WebSocket сервер с TLS, IP routing blocklist и GeoIP.

Конфигурация полностью задаётся в config.yaml. Доменные правила из routing-источника
намеренно игнорируются: блокировка выполняется только по IP/CIDR после DNS-разрешения
целевого адреса.
"""
from __future__ import annotations

import argparse
import asyncio
from bisect import bisect_right
import hmac
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import struct
import tempfile
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

import yaml
import websockets
from websockets.exceptions import ConnectionClosed

LOG = logging.getLogger("vless-ws")
TCP_CONNECT = 1
MUX_COMMAND = 3

XUDP_STATUS_NEW = 1
XUDP_STATUS_KEEP = 2
XUDP_STATUS_END = 3
XUDP_STATUS_KEEPALIVE = 4
XUDP_OPTION_DATA = 1
XUDP_OPTION_ERROR = 2
XUDP_NETWORK_UDP = 2
XUDP_MUX_HOST = "v1.mux.cool"
XUDP_MUX_PORT = 666


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    uuid_bytes: bytes
    listen_host: str
    port: int
    sni: tuple[str, ...]
    certfile: Path
    keyfile: Path
    handshake_timeout: float
    connect_timeout: float
    idle_timeout: float
    buffer_size: int
    max_ws_message: int
    routing: dict[str, Any]
    geofilter: dict[str, Any]
    logging_cfg: dict[str, Any]


def load_config(path: Path) -> Settings:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"не удалось прочитать {path}: {exc}") from exc

    base = path.resolve().parent
    server = raw.get("server", {})
    tls = raw.get("tls", {})
    limits = raw.get("limits", {})

    try:
        uuid_bytes = uuid.UUID(str(raw["uuid"])).bytes
        port = int(server.get("port", 25323))
        if not 1 <= port <= 65535:
            raise ValueError("порт вне диапазона 1..65535")
        certfile = (base / str(tls["certfile"])).resolve()
        keyfile = (base / str(tls["keyfile"])).resolve()
    except (KeyError, ValueError, TypeError) as exc:
        raise ConfigError(f"ошибка обязательной настройки: {exc}") from exc

    sni_value = tls.get("sni", [])
    if isinstance(sni_value, str):
        sni_value = [sni_value]
    sni = tuple(str(x).strip().lower().rstrip(".") for x in sni_value if str(x).strip())

    return Settings(
        uuid_bytes=uuid_bytes,
        listen_host=str(server.get("host", "0.0.0.0")),
        port=port,
        sni=sni,
        certfile=certfile,
        keyfile=keyfile,
        handshake_timeout=float(limits.get("handshake_timeout", 10)),
        connect_timeout=float(limits.get("connect_timeout", 10)),
        idle_timeout=float(limits.get("idle_timeout", 300)),
        buffer_size=max(4096, min(int(limits.get("buffer_size", 65536)), 1048576)),
        max_ws_message=max(1024, int(limits.get("max_ws_message", 1048576))),
        routing=dict(raw.get("routing", {})),
        geofilter=dict(raw.get("geofilter", {})),
        logging_cfg=dict(raw.get("logging", {})),
    )


def configure_logging(cfg: dict[str, Any]) -> None:
    level = getattr(logging, str(cfg.get("level", "INFO")).upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if cfg.get("file"):
        handlers.append(logging.FileHandler(str(cfg["file"]), encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def parse_vless_handshake(buf: bytes) -> tuple[int, bytes, int, str, int, int]:
    """Разбирает VLESS request и возвращает version, uuid, command, host, port и offset."""
    view = memoryview(buf)
    pos = 0

    def take(n: int) -> memoryview:
        nonlocal pos
        if n < 0 or pos + n > len(view):
            raise ValueError("неполный VLESS handshake")
        chunk = view[pos : pos + n]
        pos += n
        return chunk

    version = int(take(1)[0])
    client_id = bytes(take(16))
    opt_len = int(take(1)[0])
    take(opt_len)
    command = int(take(1)[0])
    if command not in {TCP_CONNECT, MUX_COMMAND}:
        raise ValueError(f"поддерживаются TCP command=1 и XUDP/MUX command=3, получено {command}")

    # В VLESS у MUX-команды адрес отсутствует; первый XUDP frame начинается сразу
    # после command. Логическое назначение MUX у sing-box/Xray — v1.mux.cool:666.
    if command == MUX_COMMAND:
        return version, client_id, command, XUDP_MUX_HOST, XUDP_MUX_PORT, pos

    port = struct.unpack(">H", take(2))[0]
    addr_type = int(take(1)[0])
    if addr_type == 1:
        host = socket.inet_ntop(socket.AF_INET, take(4))
    elif addr_type == 2:
        length = int(take(1)[0])
        if length == 0:
            raise ValueError("пустое доменное имя")
        host = bytes(take(length)).decode("idna").rstrip(".")
    elif addr_type == 3:
        host = socket.inet_ntop(socket.AF_INET6, take(16))
    else:
        raise ValueError(f"неподдерживаемый тип адреса: {addr_type}")
    return version, client_id, command, host, port, pos


def _walk_json(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_json(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_json(item)


@dataclass(frozen=True)
class RoutingRules:
    networks: tuple[ipaddress._BaseNetwork, ...]
    domains: frozenset[str]
    full_domains: frozenset[str]
    keywords: tuple[str, ...]
    regexps: tuple[re.Pattern[str], ...]
    skipped_references: tuple[str, ...]


def _normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def parse_routing_rules(data: bytes) -> RoutingRules:
    """Разбирает IP/CIDR и доменные правила без DNS-запросов."""
    text = data.decode("utf-8-sig", "replace")
    candidates: Iterable[str]
    try:
        candidates = _walk_json(json.loads(text))
    except json.JSONDecodeError:
        candidates = text.splitlines()

    networks: set[ipaddress._BaseNetwork] = set()
    domains: set[str] = set()
    full_domains: set[str] = set()
    keywords: set[str] = set()
    regexps: list[re.Pattern[str]] = []
    skipped: set[str] = set()
    for raw in candidates:
        line = str(raw).split("#", 1)[0].strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("geosite:", "include:")):
            # Это ссылки на внешние наборы geosite, а не самостоятельные правила.
            skipped.add(line)
            continue
        if lowered.startswith("regexp:"):
            expression = line.split(":", 1)[1].strip()
            try:
                regexps.append(re.compile(expression, re.IGNORECASE))
            except re.error as exc:
                LOG.warning("пропущено неверное regexp-правило %r: %s", expression, exc)
            continue
        if lowered.startswith("keyword:"):
            keyword = _normalize_domain(line.split(":", 1)[1])
            if keyword:
                keywords.add(keyword)
            continue
        if lowered.startswith("full:"):
            domain = _normalize_domain(line.split(":", 1)[1])
            if domain:
                full_domains.add(domain)
            continue
        if lowered.startswith("domain:"):
            line = line.split(":", 1)[1].strip()

        token = line.strip("[](){}\"'")
        try:
            networks.add(ipaddress.ip_network(token, strict=False))
            continue
        except ValueError:
            pass
        domain = _normalize_domain(token)
        # Простая проверка синтаксиса без разрешения через DNS.
        if domain and "." in domain and " " not in domain:
            domains.add(domain)

    return RoutingRules(
        networks=tuple(sorted(networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen))),
        domains=frozenset(domains),
        full_domains=frozenset(full_domains),
        keywords=tuple(sorted(keywords)),
        regexps=tuple(regexps),
        skipped_references=tuple(sorted(skipped)),
    )


class RoutingBlocklist:
    def __init__(self, cfg: dict[str, Any], base_dir: Path):
        self.enabled = bool(cfg.get("enabled", True))
        self.url = str(cfg.get("source_url", "https://javascript.publicvm.com:2087/routing"))
        self.refresh_seconds = int(cfg.get("refresh_seconds", 3600))
        self.timeout = float(cfg.get("download_timeout", 15))
        self.fail_closed = bool(cfg.get("fail_closed", False))
        cache = str(cfg.get("cache_file", "routing.cache"))
        self.cache_file = (base_dir / cache).resolve()
        self._v4: tuple[ipaddress.IPv4Network, ...] = ()
        self._v6: tuple[ipaddress.IPv6Network, ...] = ()
        self._domains: frozenset[str] = frozenset()
        self._full_domains: frozenset[str] = frozenset()
        self._keywords: tuple[str, ...] = ()
        self._regexps: tuple[re.Pattern[str], ...] = ()
        self._ready = not (self.enabled and self.fail_closed)
        self._task: asyncio.Task[None] | None = None

    @property
    def ready(self) -> bool:
        return self._ready

    def blocked_ip(self, address: ipaddress._BaseAddress) -> bool:
        nets = self._v4 if address.version == 4 else self._v6
        return any(address in net for net in nets)

    def blocked_host(self, host: str) -> bool:
        try:
            return self.blocked_ip(ipaddress.ip_address(host))
        except ValueError:
            domain = _normalize_domain(host)
        if domain in self._full_domains:
            return True
        # Обычная запись блокирует домен и его поддомены, без DNS lookup.
        labels = domain.split(".")
        if any(".".join(labels[i:]) in self._domains for i in range(max(1, len(labels) - 1))):
            return True
        if any(keyword in domain for keyword in self._keywords):
            return True
        return any(pattern.search(domain) for pattern in self._regexps)

    def _install(self, rules: RoutingRules) -> None:
        self._v4 = tuple(n for n in rules.networks if n.version == 4)
        self._v6 = tuple(n for n in rules.networks if n.version == 6)
        self._domains = rules.domains
        self._full_domains = rules.full_domains
        self._keywords = rules.keywords
        self._regexps = rules.regexps
        self._ready = True
        LOG.info(
            "routing: %d доменов, %d full, %d keyword, %d regexp, %d IPv4, %d IPv6",
            len(self._domains), len(self._full_domains), len(self._keywords), len(self._regexps),
            len(self._v4), len(self._v6),
        )
        if rules.skipped_references:
            LOG.warning("пропущены внешние ссылки geosite/include: %s", ", ".join(rules.skipped_references))

    def _download(self) -> bytes:
        request = urllib.request.Request(self.url, headers={"User-Agent": "vless-ws/2.0", "Accept": "application/json,text/plain,*/*"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if response.status != 200:
                raise OSError(f"HTTP {response.status}")
            return response.read(32 * 1024 * 1024)

    async def refresh(self) -> None:
        if not self.enabled:
            self._ready = True
            return
        try:
            data = await asyncio.to_thread(self._download)
            rules = parse_routing_rules(data)
            if not (rules.networks or rules.domains or rules.full_domains or rules.keywords or rules.regexps):
                raise ValueError("источник не содержит поддерживаемых routing-правил")
            self._install(rules)
            await asyncio.to_thread(self._atomic_write, self.cache_file, data)
        except Exception as exc:
            LOG.warning("не удалось обновить routing blocklist: %s", exc)
            if self.cache_file.exists():
                try:
                    data = await asyncio.to_thread(self.cache_file.read_bytes)
                    rules = parse_routing_rules(data)
                    if rules.networks or rules.domains or rules.full_domains or rules.keywords or rules.regexps:
                        self._install(rules)
                        LOG.info("использован кэш %s", self.cache_file)
                except Exception as cache_exc:
                    LOG.error("ошибка кэша routing: %s", cache_exc)

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
            tmp.write(data)
            temp_name = tmp.name
        os.replace(temp_name, path)

    async def run(self) -> None:
        await self.refresh()
        if self.refresh_seconds <= 0:
            return
        while True:
            await asyncio.sleep(max(60, self.refresh_seconds))
            await self.refresh()

    def start(self) -> None:
        if self.enabled:
            self._task = asyncio.create_task(self.run(), name="routing-refresh")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)


class GeoFilter:
    """Фильтр клиентов по country CIDR-спискам проекта ipverse (без MMDB)."""

    def __init__(self, cfg: dict[str, Any], base_dir: Path):
        self.enabled = bool(cfg.get("enabled", False))
        self.mode = str(cfg.get("mode", "deny")).lower()
        if self.mode not in {"allow", "deny"}:
            raise ConfigError("geofilter.mode должен быть allow или deny")
        self.countries = {str(x).upper() for x in cfg.get("countries", [])}
        self.unknown = str(cfg.get("unknown", "deny" if self.mode == "allow" else "allow")).lower()
        if self.unknown not in {"allow", "deny"}:
            raise ConfigError("geofilter.unknown должен быть allow или deny")
        self.auto_download = bool(cfg.get("auto_download", True))
        self.fail_closed = bool(cfg.get("fail_closed", True))
        self.timeout = float(cfg.get("download_timeout", 30))
        self.cache_dir = (base_dir / str(cfg.get("cache_dir", "geoip-cache"))).resolve()
        self.url_template = str(cfg.get(
            "source_url_template",
            "https://raw.githubusercontent.com/ipverse/geo-ip-blocks/refs/heads/master/country/{country}/{country}.json",
        ))
        self._indexes: dict[str, tuple[list[int], list[ipaddress.IPv4Network], list[int], list[ipaddress.IPv6Network]]] = {}

    def _download_country(self, country: str) -> bytes:
        lower = country.lower()
        url = self.url_template.format(country=lower, COUNTRY=country)
        request = urllib.request.Request(url, headers={"User-Agent": "vless-ws/2.1", "Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if response.status != 200:
                raise OSError(f"HTTP {response.status}")
            return response.read(64 * 1024 * 1024)

    @staticmethod
    def _parse_country(data: bytes, expected_country: str) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
        try:
            payload = json.loads(data.decode("utf-8-sig"))
            actual = str(payload.get("countryCode", "")).upper()
            if actual and actual != expected_country:
                raise ValueError(f"ожидалась страна {expected_country}, получена {actual}")
            prefixes = payload["prefixes"]
            raw_v4 = prefixes.get("ipv4", [])
            raw_v6 = prefixes.get("ipv6", [])
        except (UnicodeError, json.JSONDecodeError, KeyError, AttributeError) as exc:
            raise ValueError("неверный формат ipverse JSON") from exc

        try:
            v4 = [ipaddress.ip_network(item, strict=False) for item in raw_v4]
            v6 = [ipaddress.ip_network(item, strict=False) for item in raw_v6]
        except ValueError as exc:
            raise ValueError(f"неверный CIDR в списке {expected_country}: {exc}") from exc
        if any(net.version != 4 for net in v4) or any(net.version != 6 for net in v6):
            raise ValueError(f"перепутано семейство IP в списке {expected_country}")
        if not v4 and not v6:
            raise ValueError(f"пустой список префиксов {expected_country}")
        return list(ipaddress.collapse_addresses(v4)), list(ipaddress.collapse_addresses(v6))

    def _load_country(self, country: str) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
        cache_file = self.cache_dir / f"{country.lower()}.json"
        download_error: Exception | None = None
        if self.auto_download:
            try:
                data = self._download_country(country)
                parsed = self._parse_country(data, country)
                RoutingBlocklist._atomic_write(cache_file, data)
                return parsed
            except Exception as exc:
                download_error = exc
                LOG.warning("GeoIP %s: загрузка не удалась: %s", country, exc)
        if cache_file.exists():
            try:
                return self._parse_country(cache_file.read_bytes(), country)
            except Exception as exc:
                raise ConfigError(f"повреждён GeoIP-кэш {cache_file}: {exc}") from exc
        if download_error:
            raise ConfigError(f"GeoIP {country} недоступен и кэш отсутствует: {download_error}")
        raise ConfigError(f"GeoIP-кэш не найден: {cache_file}")

    async def open(self) -> None:
        if not self.enabled:
            return
        if not self.countries:
            raise ConfigError("geofilter.countries пуст")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        failures: list[str] = []
        for country in sorted(self.countries):
            try:
                v4, v6 = await asyncio.to_thread(self._load_country, country)
                self._indexes[country] = (
                    [int(net.network_address) for net in v4], v4,
                    [int(net.network_address) for net in v6], v6,
                )
                LOG.info("GeoIP %s: загружено %d IPv4 и %d IPv6 префиксов", country, len(v4), len(v6))
            except Exception as exc:
                failures.append(f"{country}: {exc}")
                LOG.error("GeoIP %s", failures[-1])
        if failures and self.fail_closed:
            raise ConfigError("не удалось загрузить GeoIP: " + "; ".join(failures))
        if not self._indexes:
            LOG.warning("GeoIP работает fail-open: списки стран недоступны")

    @staticmethod
    def _contains(value: int, starts: list[int], networks: list[Any]) -> bool:
        index = bisect_right(starts, value) - 1
        return index >= 0 and value <= int(networks[index].broadcast_address)

    def allowed(self, address: str) -> tuple[bool, str | None]:
        if not self.enabled:
            return True, None
        try:
            ip = ipaddress.ip_address(address)
            if ip.is_loopback or ip.is_private:
                return True, None
        except ValueError:
            return self.unknown == "allow", None

        value = int(ip)
        matched_country: str | None = None
        for country, (starts4, nets4, starts6, nets6) in self._indexes.items():
            matched = self._contains(value, starts4, nets4) if ip.version == 4 else self._contains(value, starts6, nets6)
            if matched:
                matched_country = country
                break
        if self.mode == "deny":
            return matched_country is None, matched_country
        if matched_country is not None:
            return True, matched_country
        return self.unknown == "allow", None

    def close(self) -> None:
        self._indexes.clear()


async def resolve_target(host: str, port: int) -> list[tuple[int, str]]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    result: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for family, _, _, _, sockaddr in infos:
        key = (family, sockaddr[0])
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


async def resolve_udp_target(host: str, port: int) -> list[tuple[int, str]]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    result: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for family, _, _, _, sockaddr in infos:
        key = (family, sockaddr[0])
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


def parse_xudp_address(data: bytes, pos: int = 0) -> tuple[str, int, int]:
    """Разбирает VMess/VLESS AddressSerializer: port, type, address."""
    if pos + 3 > len(data):
        raise ValueError("неполный XUDP-адрес")
    port = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    addr_type = data[pos]
    pos += 1
    if addr_type == 1:
        if pos + 4 > len(data):
            raise ValueError("неполный XUDP IPv4")
        host = socket.inet_ntop(socket.AF_INET, data[pos : pos + 4])
        pos += 4
    elif addr_type == 2:
        if pos >= len(data):
            raise ValueError("неполный XUDP domain")
        length = data[pos]
        pos += 1
        if not length or pos + length > len(data):
            raise ValueError("неверная длина XUDP domain")
        host = data[pos : pos + length].decode("idna").rstrip(".")
        pos += length
    elif addr_type == 3:
        if pos + 16 > len(data):
            raise ValueError("неполный XUDP IPv6")
        host = socket.inet_ntop(socket.AF_INET6, data[pos : pos + 16])
        pos += 16
    else:
        raise ValueError(f"неподдерживаемый тип XUDP-адреса: {addr_type}")
    return host, port, pos


def encode_xudp_address(host: str, port: int) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = _normalize_domain(host).encode("ascii")
        if not encoded or len(encoded) > 255:
            raise ValueError("неверный XUDP domain")
        return struct.pack(">HB", port, 2) + bytes((len(encoded),)) + encoded
    if address.version == 4:
        return struct.pack(">HB", port, 1) + address.packed
    return struct.pack(">HB", port, 3) + address.packed


class WebSocketByteStream:
    """Превращает бинарные WebSocket messages в непрерывный байтовый поток."""

    def __init__(self, websocket: Any, initial: bytes = b""):
        self.websocket = websocket
        self.buffer = bytearray(initial)

    async def readexactly(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("отрицательная длина")
        while len(self.buffer) < length:
            message = await self.websocket.recv()
            if not isinstance(message, bytes):
                raise ValueError("текстовый WebSocket frame запрещён")
            self.buffer.extend(message)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result


class XUDPSession:
    def __init__(self, session_id: int, server: "VlessServer", send_frame: Any):
        self.session_id = session_id
        self.server = server
        self.send_frame = send_frame
        self.default_destination: tuple[str, int] | None = None
        self.sockets: dict[int, socket.socket] = {}
        self.tasks: set[asyncio.Task[None]] = set()
        self.closed = False

    async def _socket_for(self, family: int) -> socket.socket:
        sock = self.sockets.get(family)
        if sock is not None:
            return sock
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        if family == socket.AF_INET6:
            sock.bind(("::", 0))
        else:
            sock.bind(("0.0.0.0", 0))
        self.sockets[family] = sock
        task = asyncio.create_task(self._receive_loop(sock), name=f"xudp-{self.session_id}-{family}")
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return sock

    async def send(self, payload: bytes, destination: tuple[str, int] | None) -> None:
        if self.closed:
            return
        if destination is not None:
            self.default_destination = destination
        elif self.default_destination is None:
            raise ValueError("XUDP KEEP без адреса до NEW")
        host, port = self.default_destination if destination is None else destination
        if self.server.routing.blocked_host(host):
            raise PermissionError(f"XUDP назначение заблокировано routing-правилом: {host}")
        candidates = await asyncio.wait_for(resolve_udp_target(host, port), timeout=self.server.cfg.connect_timeout)
        candidates = [(family, ip) for family, ip in candidates if not self.server.routing.blocked_ip(ipaddress.ip_address(ip))]
        if not candidates:
            raise PermissionError(f"XUDP адрес назначения заблокирован: {host}")
        family, ip = candidates[0]
        sock = await self._socket_for(family)
        await asyncio.get_running_loop().sock_sendto(sock, payload, (ip, port))

    async def _receive_loop(self, sock: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        try:
            while not self.closed:
                data, address = await loop.sock_recvfrom(sock, 65535)
                if not data:
                    continue
                await self.send_frame(self.session_id, data, (address[0], address[1]))
        except (asyncio.CancelledError, OSError, ConnectionClosed):
            pass

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for task in tuple(self.tasks):
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        for sock in self.sockets.values():
            sock.close()
        self.sockets.clear()


class VlessServer:
    def __init__(self, settings: Settings, config_dir: Path):
        self.cfg = settings
        self.routing = RoutingBlocklist(settings.routing, config_dir)
        self.geo = GeoFilter(settings.geofilter, config_dir)

    async def handle_xudp(self, websocket: Any, initial: bytes) -> None:
        """Обслуживает совместимый с sing-box и Xray XUDP поверх MUX-потока."""
        stream = WebSocketByteStream(websocket, initial)
        sessions: dict[int, XUDPSession] = {}
        send_lock = asyncio.Lock()

        async def send_packet(session_id: int, payload: bytes, source: tuple[str, int]) -> None:
            address = encode_xudp_address(source[0], source[1])
            metadata = struct.pack(">HBB", session_id, XUDP_STATUS_KEEP, XUDP_OPTION_DATA)
            metadata += bytes((XUDP_NETWORK_UDP,)) + address
            frame = struct.pack(">H", len(metadata)) + metadata + struct.pack(">H", len(payload)) + payload
            async with send_lock:
                await websocket.send(frame)

        async def send_close(session_id: int, error: bool = False) -> None:
            option = XUDP_OPTION_ERROR if error else 0
            frame = struct.pack(">HHBB", 4, session_id, XUDP_STATUS_END, option)
            async with send_lock:
                await websocket.send(frame)

        try:
            while True:
                metadata_length = struct.unpack(">H", await stream.readexactly(2))[0]
                if not 4 <= metadata_length <= 1024:
                    raise ValueError(f"неверная длина XUDP metadata: {metadata_length}")
                metadata = await stream.readexactly(metadata_length)
                session_id, status, option = struct.unpack_from(">HBB", metadata)
                destination: tuple[str, int] | None = None
                if metadata_length > 4:
                    network = metadata[4]
                    if network != XUDP_NETWORK_UDP:
                        raise ValueError(f"XUDP поддерживает только UDP network=2, получено {network}")
                    host, port, _ = parse_xudp_address(metadata, 5)
                    destination = (host, port)
                    # Остаток metadata намеренно игнорируется: Xray добавляет 8-byte global ID.

                session = sessions.get(session_id)
                if status == XUDP_STATUS_NEW:
                    if destination is None:
                        raise ValueError("XUDP NEW без назначения")
                    if session is not None:
                        await session.close()
                    session = XUDPSession(session_id, self, send_packet)
                    session.default_destination = destination
                    sessions[session_id] = session
                elif status == XUDP_STATUS_KEEP:
                    if session is None:
                        await send_close(session_id, error=True)
                        if option & XUDP_OPTION_DATA:
                            payload_length = struct.unpack(">H", await stream.readexactly(2))[0]
                            await stream.readexactly(payload_length)
                        continue
                elif status == XUDP_STATUS_END:
                    if session is not None:
                        sessions.pop(session_id, None)
                        await session.close()
                    continue
                elif status == XUDP_STATUS_KEEPALIVE:
                    continue
                else:
                    raise ValueError(f"неизвестный XUDP status: {status}")

                if option & XUDP_OPTION_ERROR:
                    if session is not None:
                        sessions.pop(session_id, None)
                        await session.close()
                    continue
                if option & XUDP_OPTION_DATA:
                    payload_length = struct.unpack(">H", await stream.readexactly(2))[0]
                    payload = await stream.readexactly(payload_length)
                    if session is None:
                        continue
                    try:
                        await session.send(payload, destination)
                    except (PermissionError, OSError, asyncio.TimeoutError) as exc:
                        LOG.warning("XUDP session %d: %s", session_id, exc)
                        sessions.pop(session_id, None)
                        await session.close()
                        await send_close(session_id, error=True)
        finally:
            if sessions:
                await asyncio.gather(*(session.close() for session in sessions.values()), return_exceptions=True)

    async def handler(self, websocket: Any, *_: Any) -> None:
        peer = websocket.remote_address
        peer_ip = peer[0] if peer else "unknown"
        allowed, country = self.geo.allowed(peer_ip)
        if not allowed:
            LOG.warning("GeoIP: отклонён клиент %s (%s)", peer_ip, country or "unknown")
            await websocket.close(code=1008, reason="geo policy")
            return
        if not self.routing.ready:
            await websocket.close(code=1013, reason="routing list unavailable")
            return

        writer: asyncio.StreamWriter | None = None
        try:
            message = await asyncio.wait_for(websocket.recv(), timeout=self.cfg.handshake_timeout)
            if not isinstance(message, bytes):
                raise ValueError("VLESS handshake должен быть бинарным")
            version, client_id, command, host, port, offset = parse_vless_handshake(message)
            if not hmac.compare_digest(client_id, self.cfg.uuid_bytes):
                raise PermissionError("неверный UUID")

            if command == MUX_COMMAND:
                if _normalize_domain(host) != XUDP_MUX_HOST or port != XUDP_MUX_PORT:
                    raise ValueError(f"неверное XUDP/MUX назначение: {host}:{port}")
                await websocket.send(bytes((version, 0)))
                await self.handle_xudp(websocket, message[offset:])
                return

            # Домен проверяется непосредственно по строке из VLESS handshake — без DNS.
            if self.routing.blocked_host(host):
                raise PermissionError(f"назначение заблокировано routing-правилом: {host}")

            candidates = await asyncio.wait_for(resolve_target(host, port), timeout=self.cfg.connect_timeout)
            candidates = [(family, ip) for family, ip in candidates if not self.routing.blocked_ip(ipaddress.ip_address(ip))]
            if not candidates:
                raise PermissionError(f"адрес назначения заблокирован: {host}")

            last_error: Exception | None = None
            reader = None
            for family, ip in candidates:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port, family=family), timeout=self.cfg.connect_timeout
                    )
                    break
                except Exception as exc:
                    last_error = exc
            if reader is None or writer is None:
                raise OSError(f"не удалось подключиться к {host}:{port}: {last_error}")

            await websocket.send(bytes((version, 0)))
            payload = message[offset:]
            if payload:
                writer.write(payload)
                await writer.drain()

            async def ws_to_tcp() -> None:
                async for chunk in websocket:
                    if not isinstance(chunk, bytes):
                        raise ValueError("текстовый WebSocket frame запрещён")
                    writer.write(chunk)
                    await writer.drain()

            async def tcp_to_ws() -> None:
                while data := await reader.read(self.cfg.buffer_size):
                    await websocket.send(data)

            tasks = {asyncio.create_task(ws_to_tcp()), asyncio.create_task(tcp_to_ws())}
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*done, *pending, return_exceptions=True)
        except PermissionError as exc:
            LOG.warning("%s: %s", peer_ip, exc)
            await websocket.close(code=1008, reason="policy violation")
        except (ConnectionClosed, asyncio.CancelledError):
            pass
        except Exception as exc:
            LOG.info("соединение %s закрыто: %s", peer_ip, exc)
            try:
                await websocket.close(code=1011, reason="connection failed")
            except Exception:
                pass
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.load_cert_chain(str(self.cfg.certfile), str(self.cfg.keyfile))
        allowed_sni = set(self.cfg.sni)
        if allowed_sni:
            def check_sni(sock: ssl.SSLSocket, server_name: str | None, _: ssl.SSLContext) -> None:
                normalized = (server_name or "").lower().rstrip(".")
                if normalized not in allowed_sni:
                    LOG.warning("отклонён SNI: %r", server_name)
                    raise ssl.SSLError("unrecognized_name")
            ctx.set_servername_callback(check_sni)
        return ctx

    async def run(self) -> None:
        await self.geo.open()
        self.routing.start()
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:
                pass

        async with websockets.serve(
            self.handler,
            self.cfg.listen_host,
            self.cfg.port,
            ssl=self.ssl_context(),
            max_size=self.cfg.max_ws_message,
            max_queue=16,
            ping_interval=30,
            ping_timeout=20,
            close_timeout=5,
            compression=None,
            server_header=None,
        ):
            LOG.info("VLESS/WSS слушает %s:%d; SNI=%s", self.cfg.listen_host, self.cfg.port, ",".join(self.cfg.sni) or "любой")
            await stop.wait()

        await self.routing.stop()
        self.geo.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="VLESS-over-WebSocket server")
    parser.add_argument("-c", "--config", default="config.yaml", help="путь к config.yaml")
    args = parser.parse_args()
    config_path = Path(args.config).resolve()
    try:
        settings = load_config(config_path)
        configure_logging(settings.logging_cfg)
        asyncio.run(VlessServer(settings, config_path.parent).run())
    except (ConfigError, OSError, ssl.SSLError) as exc:
        logging.basicConfig(level=logging.INFO)
        LOG.critical("запуск невозможен: %s", exc)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()

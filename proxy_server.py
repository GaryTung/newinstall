#!/usr/bin/env python3
from __future__ import annotations
import base64
from collections import OrderedDict
import os
import secrets
import select
import socket
import threading
import urllib.parse
import time
from typing import Any

def parse_positive_int(value: str | None, default: int) -> int:
    try:
        return max(1, int(value or default))
    except (TypeError, ValueError):
        return default

MAX_PROXY_CONNECTIONS = parse_positive_int(os.environ.get("LOCAL_PROXY_MAX_CONNECTIONS"), 256)
proxy_connection_sem = threading.BoundedSemaphore(MAX_PROXY_CONNECTIONS)

DNS_CACHE_MAX_ENTRIES = min(8192, parse_positive_int(os.environ.get("LOCAL_PROXY_DNS_CACHE_SIZE"), 1024))
DNS_CACHE_MAX_TTL = min(3600, parse_positive_int(os.environ.get("LOCAL_PROXY_DNS_CACHE_TTL"), 300))


class _DNSFlight:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.address: str | None = None


class _DNSCache:
    """Process-local, bounded positive cache; never shared across VPN namespaces."""
    def __init__(self, max_entries: int, max_ttl: int) -> None:
        self.max_entries = max_entries
        self.max_ttl = max_ttl
        self.lock = threading.Lock()
        self.scope: Any = None
        self.entries: OrderedDict[Any, tuple[float, str]] = OrderedDict()
        self.inflight: dict[Any, _DNSFlight] = {}

    def _sync(self, scope: Any) -> None:
        if self.scope != scope:
            self.scope = scope
            self.entries.clear()
            for flight in self.inflight.values():
                flight.event.set()
            self.inflight.clear()

    def _lookup(self, key: Any) -> str | None:
        entry = self.entries.get(key)
        if entry is not None:
            if entry[0] > time.monotonic():
                self.entries.move_to_end(key)
                return entry[1]
            self.entries.pop(key, None)
        return None

    def lookup(self, scope: Any, key: Any) -> str | None:
        with self.lock:
            self._sync(scope)
            return self._lookup(key)

    def begin(self, scope: Any, key: Any) -> tuple[str | None, _DNSFlight | None, bool]:
        with self.lock:
            self._sync(scope)
            address = self._lookup(key)
            if address is not None:
                return address, None, False
            if key in self.inflight:
                return None, self.inflight[key], False
            flight = _DNSFlight()
            # Client concurrency is separately bounded; retain a hard limit here too.
            if len(self.inflight) < self.max_entries:
                self.inflight[key] = flight
            return None, flight, True

    def finish(self, scope: Any, key: Any, flight: _DNSFlight,
               answer: tuple[str, int] | None, cacheable: bool) -> None:
        with self.lock:
            if self.scope == scope and self.inflight.get(key) is flight:
                self.inflight.pop(key, None)
                if cacheable and answer is not None and answer[1] > 0:
                    self.entries[key] = (time.monotonic() + min(answer[1], self.max_ttl), answer[0])
                    self.entries.move_to_end(key)
                    while len(self.entries) > self.max_entries:
                        self.entries.popitem(last=False)
            flight.address = answer[0] if answer is not None else None
            flight.event.set()

    def clear(self) -> None:
        with self.lock:
            self._sync(None)


_dns_cache = _DNSCache(DNS_CACHE_MAX_ENTRIES, DNS_CACHE_MAX_TTL)


def _dns_cache_scope() -> tuple[Any, ...] | None:
    """Cheap kernel reads invalidate a cached answer if tun0 is replaced/down/moved.

    The daemon also restarts the namespace proxy on every VPN reconnect. This
    fingerprint protects a still-running proxy when an interface changes in place.
    No subprocess or DNS lookup is needed for a cache hit.
    """
    try:
        import fcntl
        import struct
        namespace = os.stat("/proc/thread-self/ns/net")
        index = socket.if_nametoindex("tun0")
        request = struct.pack("256s", b"tun0")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            flags = struct.unpack_from("H", fcntl.ioctl(probe.fileno(), 0x8913, request), 16)[0]
            if not flags & 1:  # IFF_UP
                return None
            try:
                address = fcntl.ioctl(probe.fileno(), 0x8915, request)[20:24]
            except OSError:
                address = b""
        try:
            with open("/proc/net/if_inet6", encoding="ascii") as source:
                ipv6 = tuple(sorted(line.split()[0] for line in source if line.split()[-1:] == ["tun0"]))
        except FileNotFoundError:  # IPv6 can be disabled on an otherwise healthy VPS.
            ipv6 = ()
        return os.getpid(), namespace.st_dev, namespace.st_ino, index, flags, address, ipv6
    except (ImportError, OSError, ValueError):
        # Unknown interface state must bypass, not reuse, a previous cache.
        return None


def _dns_host_key(host: str) -> str:
    return host.rstrip(".").encode("idna").decode("ascii").lower()


def _read_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels = []
    next_offset = None
    visited = set()
    for _ in range(128):
        if offset >= len(packet) or offset in visited:
            raise ValueError("Invalid DNS name")
        visited.add(offset)
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Truncated DNS pointer")
            if next_offset is None:
                next_offset = offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
            continue
        if length & 0xC0 or offset + 1 + length > len(packet):
            raise ValueError("Invalid DNS label")
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), next_offset if next_offset is not None else offset
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
    raise ValueError("DNS name exceeds compression limit")


def _parse_dns_answer(resp: bytes, tx_id: bytes, host: str, qtype: int) -> tuple[str, int] | None:
    try:
        if (len(resp) < 12 or resp[:2] != tx_id or not resp[2] & 0x80
                or resp[2] & 0x7A or resp[3] & 0x0F or resp[4:6] != b"\x00\x01"):
            return None
        question, offset = _read_dns_name(resp, 12)
        if question != host or resp[offset:offset + 4] != qtype.to_bytes(2, "big") + b"\x00\x01":
            return None
        offset += 4
        addresses = {}
        aliases = {}
        for _ in range(int.from_bytes(resp[6:8], "big")):
            name, offset = _read_dns_name(resp, offset)
            if offset + 10 > len(resp):
                return None
            atype = int.from_bytes(resp[offset:offset + 2], "big")
            aclass = int.from_bytes(resp[offset + 2:offset + 4], "big")
            ttl = int.from_bytes(resp[offset + 4:offset + 8], "big")
            if ttl & 0x80000000:  # RFC 2181: high-bit TTLs are treated as zero.
                ttl = 0
            size = int.from_bytes(resp[offset + 8:offset + 10], "big")
            offset += 10
            end = offset + size
            if end > len(resp):
                return None
            if aclass == 1:
                if atype == 5:
                    alias, name_end = _read_dns_name(resp, offset)
                    if name_end != end:
                        return None
                    aliases[name] = (alias, ttl)
                elif atype == qtype and ((qtype == 1 and size == 4) or (qtype == 28 and size == 16)):
                    family = socket.AF_INET if qtype == 1 else socket.AF_INET6
                    if name in addresses:
                        old_address, old_ttl = addresses[name]
                        addresses[name] = (old_address, min(old_ttl, ttl))
                    else:
                        addresses[name] = (socket.inet_ntop(family, resp[offset:end]), ttl)
            offset = end
        visited = set()
        name = host
        ttl_limit = 0x7FFFFFFF
        while name not in visited:
            visited.add(name)
            if name in addresses:
                address, ttl = addresses[name]
                return address, min(ttl, ttl_limit)
            if name not in aliases:
                return None
            name, ttl = aliases[name]
            ttl_limit = min(ttl_limit, ttl)
    except (OSError, ValueError, UnicodeError):
        return None
    return None

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def parse_host_port(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        host_part, sep, rest = authority.partition("]")
        host = host_part.lstrip("[")
        port = default_port
        if sep and rest.startswith(":"):
            port_text = rest[1:]
            port = parse_int(port_text) or default_port
        return host, port
    if authority.count(":") == 1:
        host, _, port_text = authority.rpartition(":")
        return host, parse_int(port_text) or default_port
    return authority, default_port

def get_proxy_credentials() -> tuple[str | None, str | None]:
    user = os.environ.get("LOCAL_PROXY_USER") or os.environ.get("LOCAL_PROXY_USERNAME")
    password = os.environ.get("LOCAL_PROXY_PASS") or os.environ.get("LOCAL_PROXY_PASSWORD")
    if user is None and password is None:
        return None, None
    return user or "", password or ""

def proxy_auth_enabled() -> bool:
    user, password = get_proxy_credentials()
    return user is not None and password is not None

def parse_http_basic_auth(lines: list[str]) -> tuple[str | None, str | None]:
    for line in lines:
        name, sep, value = line.partition(":")
        if not sep or name.strip().lower() != "proxy-authorization":
            continue
        scheme, _, token = value.strip().partition(" ")
        if scheme.lower() != "basic" or not token:
            return None, None
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="replace")
        except Exception:
            return None, None
        username, sep, password = decoded.partition(":")
        if not sep:
            return None, None
        return username, password
    return None, None

def check_credentials(username: str | None, password: str | None) -> bool:
    expected_user, expected_pass = get_proxy_credentials()
    if expected_user is None or expected_pass is None:
        return True
    return secrets.compare_digest(username or "", expected_user) and secrets.compare_digest(password or "", expected_pass)

def _query_dns_over_tun0(host: str, qtype: int, dns_server: str, timeout: float) -> tuple[str, int] | None:
    sock = None
    try:
        host = _dns_host_key(host)
        if not host or len(host) > 253 or qtype not in (1, 28):
            return None
        tx_id = secrets.token_bytes(2)
        flags = b"\x01\x00"
        questions = b"\x00\x01"
        rrs = b"\x00\x00\x00\x00\x00\x00"

        qname = b""
        for part in host.split("."):
            if not part:
                return None
            part_bytes = part.encode("idna")
            if len(part_bytes) > 63:
                return None
            qname += len(part_bytes).to_bytes(1, "big") + part_bytes
        qname += b"\x00"

        qtype_qclass = qtype.to_bytes(2, "big") + b"\x00\x01"
        packet = tx_id + flags + questions + rrs + qname + qtype_qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
        except OSError as e:
            if "operation not permitted" in str(e).lower() or e.errno == 1:
                print("[DNS 绑定失败] [错误代码 3006] DNS 解析绑定 tun0 权限不足，请确保程序以 root 权限运行！", flush=True)
            elif "no such device" in str(e).lower() or e.errno == 19:
                print("[DNS 绑定失败] [错误代码 3004] DNS 解析绑定 tun0 失败，网卡设备不存在，请检查 VPN 连接！", flush=True)
            return None
        # A connected UDP socket only accepts replies from the chosen resolver.
        sock.connect((dns_server, 53))
        sock.send(packet)
        resp = sock.recv(4096)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    return _parse_dns_answer(resp, tx_id, host, qtype)


def dns_query_over_tun0(host: str, qtype: int, dns_server: str, timeout: float) -> str | None:
    try:
        host = _dns_host_key(host)
    except (UnicodeError, ValueError):
        return None
    scope = _dns_cache_scope()
    if scope is None:
        _dns_cache.clear()
        answer = _query_dns_over_tun0(host, qtype, dns_server, timeout)
        return answer[0] if answer is not None else None
    key = (host, qtype, dns_server)
    address, flight, owner = _dns_cache.begin(scope, key)
    if address is not None:
        return address
    if not owner:
        # Coalesce a burst of browser lookups without holding the cache lock.
        if flight.event.wait(max(0.0, timeout) + 0.25) and _dns_cache_scope() == scope:
            return flight.address
        return None
    answer = None
    try:
        answer = _query_dns_over_tun0(host, qtype, dns_server, timeout)
        return answer[0] if answer is not None else None
    finally:
        _dns_cache.finish(scope, key, flight, answer, _dns_cache_scope() == scope)

def resolve_dns_over_tun0(host: str, dns_server: str = "8.8.8.8", timeout: float = 3.0) -> str | None:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass
    try:
        key = _dns_host_key(host)
    except (UnicodeError, ValueError):
        return None
    scope = _dns_cache_scope()
    if scope is not None:
        # An AAAA cache hit must not repeat an earlier unsuccessful A request.
        for qtype in (1, 28):
            cached = _dns_cache.lookup(scope, (key, qtype, dns_server))
            if cached is not None:
                return cached
    else:
        _dns_cache.clear()
    return dns_query_over_tun0(host, 1, dns_server, timeout) or dns_query_over_tun0(host, 28, dns_server, timeout)

def create_connection(address: tuple[str, int], timeout: float = 20) -> socket.socket:
    host, port = address
    resolved_ip = resolve_dns_over_tun0(host)
    if resolved_ip:
        host = resolved_ip

    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0")
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if "operation not permitted" in str(e).lower() or e.errno == 1:
                err = OSError(f"[错误代码 3006] [ERR_PROXY_BIND_TUN_PERM_DENIED] 绑定虚拟网卡 tun0 失败，权限不足！必须以 root 权限运行，或者进程缺少 CAP_NET_RAW 权限。")
            elif "no such device" in str(e).lower() or e.errno == 19:
                err = OSError(f"[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] 绑定虚拟网卡 tun0 失败，找不到设备！这通常是因为 OpenVPN 核心未能成功连接或已被异常终止。")
            if sock is not None:
                sock.close()
    if err is not None:
        raise err
    else:
        raise OSError("getaddrinfo returns empty list")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored or not readable:
            return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data:
                return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        if proxy_auth_enabled():
            if 2 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            auth_version = recv_exact(client, 1)[0]
            if auth_version != 1:
                client.sendall(b"\x01\x01")
                return
            username = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            password = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            if not check_credentials(username, password):
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")
        else:
            client.sendall(b"\x05\x00")
        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if address_type == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = int.from_bytes(recv_exact(client, 2), "big")
        try:
            upstream = create_connection((host, port), timeout=20)
        except Exception as e:
            print(f"[SOCKS5 代理失败] 目标 {host}:{port} 连接失败: {e}", flush=True)
            try:
                client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
            raise
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        relay(client, upstream)
    finally:
        client.close()
        if upstream:
            upstream.close()

def read_http_header(client: socket.socket, first_byte: bytes) -> bytes:
    data = first_byte
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def http_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        header = read_http_header(client, first_byte)
        if b"\r\n\r\n" not in header:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        head, rest = header.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        if not version.startswith("HTTP/"):
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        if proxy_auth_enabled():
            username, password = parse_http_basic_auth(lines[1:])
            if not check_credentials(username, password):
                client.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"AimiliVPN Proxy\"\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                return
        if method.upper() == "CONNECT":
            host, port = parse_host_port(target, 443)
            upstream = create_connection((host, port), timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            relay(client, upstream)
            return

        try:
            parsed = urllib.parse.urlsplit(target)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        hostname = parsed.hostname
        port = parsed.port
        scheme = parsed.scheme
        if not hostname:
            # Fallback to Host header
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host_val = line.split(":", 1)[1].strip()
                    if "[" in host_val and "]" in host_val:
                        host_part, _, port_part = host_val.rpartition("]")
                        hostname = host_part.lstrip("[")
                        if port_part.startswith(":"):
                            p_val = port_part.lstrip(":")
                            port = int(p_val) if p_val.isdigit() else None
                        else:
                            port = None
                    else:
                        hostname, parsed_port = parse_host_port(host_val, 0)
                        port = parsed_port or None
                    break
        if not hostname:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        port = port or (443 if scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
        upstream = create_connection((hostname, port), timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except Exception as e:
        print(f"[HTTP 代理失败] 代理请求目标连接失败: {e}", flush=True)
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
    finally:
        client.close()
        if upstream:
            upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\x05":
            socks5_client(client, first)
        else:
            http_client(client, first)
    except Exception as e:
        err_msg = str(e)
        if "[错误代码" in err_msg:
            print(f"[代理客户端连接失败] 客户端 {address} 遭遇系统性阻碍: {err_msg}", flush=True)
        try:
            client.close()
        except OSError:
            pass

def start_proxy_server(host: str, port: int) -> None:
    is_ipv6 = ":" in host or host == ""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    server = None
    try:
        server = socket.socket(af, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if is_ipv6:
            try:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        server.bind((host, port))
        server.listen(256)
        print(f"HTTP/SOCKS5 proxy listening on {host}:{port}", flush=True)
    except Exception as e:
        if server is not None:
            try:
                server.close()
            except Exception:
                pass
        if is_ipv6 and host in ("::", ""):
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 0.0.0.0 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("0.0.0.0", port))
                server.listen(256)
                print(f"HTTP/SOCKS5 proxy listening on 0.0.0.0:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="0.0.0.0")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 0.0.0.0:{port}: {diag_msg}", flush=True)
                return
        elif is_ipv6 and host == "::1":
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 127.0.0.1 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", port))
                server.listen(256)
                print(f"HTTP/SOCKS5 proxy listening on 127.0.0.1:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="127.0.0.1")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 127.0.0.1:{port}: {diag_msg}", flush=True)
                return
        else:
            import vpn_utils
            diag = vpn_utils.diagnose_local_obstructions(port, host=host)
            diag_msg = diag[1] if diag else str(e)
            print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on {host}:{port}: {diag_msg}", flush=True)
            return

    while True:
        try:
            client, address = server.accept()
            if not proxy_connection_sem.acquire(blocking=False):
                print(f"[代理限流] 当前连接数已达到上限 {MAX_PROXY_CONNECTIONS}，拒绝客户端 {address}", flush=True)
                try:
                    client.close()
                except OSError:
                    pass
                continue

            def run_client() -> None:
                try:
                    proxy_client(client, address)
                finally:
                    proxy_connection_sem.release()

            threading.Thread(target=run_client, daemon=True).start()
        except Exception as e:
            print(f"[ERROR] Proxy accept failed: {e}", flush=True)
            time.sleep(0.5)

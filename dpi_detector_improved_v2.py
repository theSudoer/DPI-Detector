#!/usr/bin/env python3
"""
dpi_detector_v3.py (JA3python integration)

- Integrates ja3python for canonical JA3/JA3S extraction when possible.
- Best-effort scapy sniff + handshake capture used to obtain raw TLS records.
- Falls back to older scapy-based heuristics when capabilities are missing.
- Rest of the tool (QUIC, ASN, fragmentation, RST, etc.) left unchanged.
"""
from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import ipaddress
import json
import socket
import ssl
import sys
import time
import statistics
import random
import hashlib
import os
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Optional imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    psutil = None
    PSUTIL_AVAILABLE = False

try:
    import dns.resolver as dns_resolver
    DNS_AVAILABLE = True
except Exception:
    dns_resolver = None
    DNS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    requests = None
    REQUESTS_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except Exception:
    x509 = None
    default_backend = None
    CRYPTO_AVAILABLE = False

# scapy optional (raw sockets / privileged)
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except Exception:
    scapy = None
    SCAPY_AVAILABLE = False

# scapy's TLS layer (TLSClientHello, TLSServerHello, TLS, ...) isn't exposed
# through scapy.all - it has to be imported explicitly, or the fallback JA3
# path below silently falls through every time even though scapy is present.
try:
    import scapy.layers.tls.all as scapy_tls
    SCAPY_TLS_AVAILABLE = True
except Exception:
    scapy_tls = None
    SCAPY_TLS_AVAILABLE = False

# aioquic for QUIC / HTTP/3 probing
try:
    from aioquic.asyncio.client import connect as quic_connect
    from aioquic.quic.events import HandshakeCompleted
    AIOQUIC_AVAILABLE = True
except Exception:
    quic_connect = None
    AIOQUIC_AVAILABLE = False

# JA3python integration (preferred JA3 library)
try:
    from ja3python import JA3Fingerprint
    JA3PY_AVAILABLE = True
except Exception:
    JA3Fingerprint = None
    JA3PY_AVAILABLE = False

# Config (unchanged)
DEFAULT_SITES = [
    'www.google.com', 'www.mozilla.org', 'www.github.com', 'www.amazon.com',
    'www.wikipedia.org', 'www.cloudflare.com', 'www.microsoft.com', 'www.apple.com'
]

DPI_INDICATORS = [
    'fortinet', 'fortigate', 'palo alto', 'cisco', 'zscaler', 'checkpoint',
    'sophos', 'mcafee', 'symantec', 'websense', 'bluecoat', 'barracuda', 'sonicwall'
]

CDN_HOSTNAME_KEYWORDS = ('cloudflare', 'google', 'amazon', 'aws', 'akamai',
                          'microsoft', 'apple', 'facebook', 'fastly')

PUBLIC_RESOLVERS = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
DOH_ENDPOINTS = [
    ('https://cloudflare-dns.com/dns-query', 'cloudflare'),
    ('https://dns.google/resolve', 'google')
]

CENSORSHIP_TEST_SITES = ['torproject.org', 'signal.org', 'eff.org', 'wikileaks.org', 'amnesty.org', 'hrw.org', 'bbc.com', 'nytimes.com', 'facebook.com', 'youtube.com']

KNOWN_BAD_JA3 = [
    'e7d705a3286e19ea42f587b344ee6865',  # Tor
    '6734f37431670b3ab4292b8f60f29984',  # Trickbot
    '4d7a28d6f2263ed61de88ca66eb011e3',  # Emotet
    '72a589da586844d7f0818ce684948eea',
    'a0e9f5d64349fb13191bc781f81f42e1'
]

# ---------- Utilities ----------
def now_iso() -> str:
    return datetime.utcnow().isoformat() + 'Z'

def median_iqr(values: List[float]) -> Tuple[Optional[float], Optional[float]]:
    if not values:
        return None, None
    vs = sorted(values)
    med = statistics.median(vs)
    half = len(vs) // 2
    q1 = statistics.median_low(vs[:half]) if half > 0 else med
    q3 = statistics.median_high(vs[-half:]) if half > 0 else med
    iqr = q3 - q1
    return med, iqr

class DetectorResult:
    def __init__(self, name: str):
        self.name = name
        self.suspicious = False
        self.score = 0
        self.details: Dict = {}

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'suspicious': self.suspicious,
            'score': self.score,
            'details': self.details
        }

# ---------- TLS / Certificate retrieval ----------
def fetch_certificate(hostname: str, port: int = 443, timeout: int = 8, connect_addr: Optional[str] = None, sni: Optional[str] = None) -> Tuple[Optional[Dict], Optional[float], Optional[bytes]]:
    target = connect_addr if connect_addr else hostname
    server_hostname = sni if sni else hostname
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.load_default_certs()
        except Exception:
            pass

        start = time.time()
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                handshake_time = time.time() - start
                try:
                    cert_der = ssock.getpeercert(binary_form=True)
                except Exception:
                    cert_der = None
                try:
                    cert_dict = ssock.getpeercert()
                except Exception:
                    cert_dict = None
                try:
                    cipher = ssock.cipher()
                except Exception:
                    cipher = None
                if isinstance(cert_dict, dict) and cipher:
                    cert_dict['__cipher'] = cipher[0]
                    try:
                        cert_dict['__tls_version'] = ssock.version()
                    except Exception:
                        cert_dict['__tls_version'] = None
                return cert_dict, handshake_time, cert_der
    except ssl.SSLCertVerificationError:
        # fallback: capture certificate despite verification error
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            start = time.time()
            with socket.create_connection((target, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                    handshake_time = time.time() - start
                    try:
                        cert_der = ssock.getpeercert(binary_form=True)
                    except Exception:
                        cert_der = None
                    try:
                        cert_dict = ssock.getpeercert()
                    except Exception:
                        cert_dict = None
                    try:
                        cipher = ssock.cipher()
                    except Exception:
                        cipher = None
                    if isinstance(cert_dict, dict) and cipher:
                        cert_dict['__cipher'] = cipher[0]
                        try:
                            cert_dict['__tls_version'] = ssock.version()
                        except Exception:
                            cert_dict['__tls_version'] = None
                    if isinstance(cert_dict, dict):
                        cert_dict['__unverified'] = True
                    return cert_dict, handshake_time, cert_der
        except Exception:
            return None, None, None
    except Exception:
        return None, None, None

# ---------- TLS timing ----------
def tls_timing_profile(hostname: str, port: int = 443, samples: int = 7, timeout: int = 5) -> DetectorResult:
    res = DetectorResult('tls_timing')
    timings: List[float] = []
    for _ in range(samples):
        jitter = random.uniform(0.02, 0.15)
        time.sleep(jitter)
        try:
            start = time.time()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    timings.append(time.time() - start)
        except Exception:
            continue

    if timings:
        med, iqr = median_iqr(timings)
        res.details['samples'] = len(timings)
        res.details['median_ms'] = round(med * 1000, 2) if med is not None else None
        res.details['iqr_ms'] = round(iqr * 1000, 2) if iqr is not None else None
        # No absolute scoring here: a fixed 450ms threshold flags anyone on a
        # slow/mobile/high-latency link regardless of DPI. run_sites() scores
        # this relative to the other sites tested in the same run instead,
        # since a single connection's baseline latency isn't meaningful on
        # its own.
    else:
        res.details['error'] = 'No successful handshakes'
        res.score += 5
    return res

# ---------- TLS version & cipher analysis ----------
def tls_version_and_cipher_check(hostname: str, port: int = 443) -> DetectorResult:
    res = DetectorResult('tls_version_cipher')
    cert, htime, cert_der = fetch_certificate(hostname, port)
    if not isinstance(cert, dict):
        res.details['error'] = 'Failed to retrieve cert'
        res.score += 5
        return res

    tls_ver = cert.get('__tls_version')
    cipher = cert.get('__cipher')
    res.details['tls_version'] = tls_ver
    res.details['cipher'] = cipher

    if tls_ver and ('TLSv1.3' not in tls_ver) and ('TLSv1.2' in tls_ver):
        res.suspicious = True
        res.score += 12
        res.details.setdefault('flags', []).append('no_tls1.3')

    if cipher:
        weak_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon', '3DES', 'CBC']
        for p in weak_patterns:
            if p in cipher:
                res.suspicious = True
                res.score += 30
                res.details.setdefault('flags', []).append(f'weak_cipher:{cipher}')
                break

    return res

# ---------- Certificate analysis ----------
def analyze_certificate(cert_dict: Dict, cert_der: Optional[bytes]) -> DetectorResult:
    res = DetectorResult('certificate')
    if not isinstance(cert_dict, dict):
        res.details['error'] = 'no_cert'
        return res

    issuer = {}
    subject = {}
    try:
        raw_issuer = cert_dict.get('issuer', [])
        for item in raw_issuer:
            try:
                if isinstance(item, (list, tuple)) and len(item) > 0:
                    first = item[0]
                    if isinstance(first, (list, tuple)) and len(first) >= 2:
                        k = str(first[0])
                        v = str(first[1])
                        issuer[k] = v
            except Exception:
                continue
    except Exception:
        issuer = {}

    try:
        raw_subject = cert_dict.get('subject', [])
        for item in raw_subject:
            try:
                if isinstance(item, (list, tuple)) and len(item) > 0:
                    first = item[0]
                    if isinstance(first, (list, tuple)) and len(first) >= 2:
                        k = str(first[0])
                        v = str(first[1])
                        subject[k] = v
            except Exception:
                continue
    except Exception:
        subject = {}

    res.details['issuer'] = issuer
    res.details['subject'] = subject

    org = issuer.get('organizationName', '') or issuer.get('org', '') or ''
    cn = subject.get('commonName', '') or subject.get('cn', '') or ''

    issuer_str = f"{org} {cn}".lower()
    # fetch_certificate() already validated the chain against the OS trust
    # store (ssl.CERT_REQUIRED); '__unverified' is only set when that failed
    # and we retried with verification disabled. Matching the issuer name
    # against a short hardcoded CA list produced false positives for any
    # legitimate CA not on the list (Buypass, SSL.com, ZeroSSL, national
    # CAs, etc). A cert that verified is trusted regardless of who issued it.
    if cert_dict.get('__unverified'):
        res.suspicious = True
        res.score += 25
        res.details.setdefault('flags', []).append('chain_verification_failed')

    for p in DPI_INDICATORS:
        if p in issuer_str:
            res.suspicious = True
            res.score += 35
            res.details.setdefault('flags', []).append(f'dpi_vendor:{p}')
            break

    san = []
    try:
        raw_san = cert_dict.get('subjectAltName', [])
        for entry in raw_san:
            try:
                if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                    san.append(entry[1])
            except Exception:
                continue
    except Exception:
        san = []

    res.details['sans'] = san
    if cn and 'localhost' in cn.lower():
        res.suspicious = True
        res.score += 20
        res.details.setdefault('flags', []).append('generic_cn')

    if cert_der and CRYPTO_AVAILABLE:
        try:
            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
            try:
                key_size = cert_obj.public_key().key_size
                if key_size and key_size < 2048:
                    res.suspicious = True
                    res.score += 18
                    res.details.setdefault('flags', []).append(f'weak_key:{key_size}')
            except Exception:
                pass
            fp = hashlib.sha256(cert_der).hexdigest().upper()
            res.details['fingerprint_sha256'] = fp
        except Exception:
            pass
    elif cert_der:
        try:
            res.details['fingerprint_sha256'] = hashlib.sha256(cert_der).hexdigest().upper()
        except Exception:
            pass

    return res

# ---------- CT log check ----------
def _ct_name_matches(hostname_lower: str, ct_hostnames: set) -> bool:
    if hostname_lower in ct_hostnames:
        return True
    # CT logs commonly list a wildcard cert (*.example.com) that also covers
    # www.example.com; an exact-string match against the CT sample missed
    # this and flagged every wildcard-covered hostname as suspicious.
    parts = hostname_lower.split('.', 1)
    if len(parts) == 2:
        wildcard = f'*.{parts[1]}'
        if wildcard in ct_hostnames:
            return True
    return False

def ct_log_check(hostname: str, observed_fingerprint_sha256: Optional[str]) -> DetectorResult:
    res = DetectorResult('ct_log')
    if not REQUESTS_AVAILABLE:
        res.details['error'] = 'requests_not_available'
        return res

    try:
        url = f'https://crt.sh/?q=%25{hostname}&output=json'
        r = requests.get(url, timeout=6)
        if r.status_code != 200:
            res.details['error'] = f'crt.sh_status_{r.status_code}'
            return res
        try:
            data = r.json()
        except Exception:
            res.details['error'] = 'crt.sh_non_json_response'
            return res

        if not data:
            res.suspicious = True
            res.score += 15
            res.details.setdefault('flags', []).append('no_ct_entries')
            return res

        issuers = set()
        hostnames = set()
        for entry in data:
            if isinstance(entry, dict):
                if 'issuer_name' in entry and entry['issuer_name']:
                    issuers.add(entry['issuer_name'])
                if 'name_value' in entry and entry['name_value']:
                    for n in str(entry['name_value']).split('\n'):
                        hostnames.add(n.strip().lower())

        res.details['issuers_sample'] = list(issuers)[:5]
        res.details['ct_hostnames_sample'] = list(hostnames)[:5]

        hostname_lower = hostname.lower()
        if observed_fingerprint_sha256:
            if not _ct_name_matches(hostname_lower, hostnames):
                res.suspicious = True
                res.score += 12
                res.details.setdefault('flags', []).append('hostname_not_in_ct_sample')
        else:
            if not _ct_name_matches(hostname_lower, hostnames):
                res.score += 5
                res.details.setdefault('flags', []).append('hostname_not_in_ct_sample_low_weight')
    except Exception as e:
        res.details['error'] = str(e)
    return res

# ---------- DNS (system + public + DoH) ----------
def resolve_system(hostname: str) -> List[str]:
    ips = []
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                for r in socket.getaddrinfo(hostname, None, family=fam):
                    ip = r[4][0]
                    ips.append(ip)
            except Exception:
                continue
    except Exception:
        pass
    return list(dict.fromkeys(ips))

def resolve_public(hostname: str) -> List[str]:
    ips = set()
    if DNS_AVAILABLE and dns_resolver:
        try:
            resolver = dns_resolver.Resolver()
            for resolver_ip in PUBLIC_RESOLVERS:
                try:
                    resolver.nameservers = [resolver_ip]
                    answers = resolver.resolve(hostname, 'A', lifetime=3)
                    for r in answers:
                        ips.add(str(r))
                except Exception:
                    continue
            for resolver_ip in PUBLIC_RESOLVERS:
                try:
                    resolver.nameservers = [resolver_ip]
                    answers = resolver.resolve(hostname, 'AAAA', lifetime=3)
                    for r in answers:
                        ips.add(str(r))
                except Exception:
                    continue
        except Exception:
            pass

    if REQUESTS_AVAILABLE:
        for doh, _name in DOH_ENDPOINTS:
            try:
                if 'cloudflare' in doh:
                    r = requests.get(f'https://cloudflare-dns.com/dns-query?name={hostname}&type=A', timeout=3,
                                     headers={'Accept': 'application/dns-json'})
                    data = r.json()
                    for a in data.get('Answer', []) or []:
                        if a.get('type') in (1,):
                            ips.add(a.get('data'))
                else:
                    r = requests.get(f'https://dns.google/resolve?name={hostname}&type=A', timeout=3)
                    data = r.json()
                    for a in data.get('Answer', []) or []:
                        ips.add(a.get('data'))
            except Exception:
                continue

    return list(ips)

def dns_spoof_check(hostname: str) -> DetectorResult:
    res = DetectorResult('dns_spoof')
    sys_ips = resolve_system(hostname)
    pub_ips = resolve_public(hostname)
    res.details['system_ips'] = sys_ips
    res.details['public_ips'] = pub_ips

    for ip in sys_ips:
        try:
            if ':' not in ip:
                octets = ip.split('.')
                if len(octets) == 4:
                    if (octets[0] == '10' or
                        (octets[0] == '172' and 16 <= int(octets[1]) <= 31) or
                        (octets[0] == '192' and octets[1] == '168')):
                        res.suspicious = True
                        res.score += 25
                        res.details.setdefault('flags', []).append('resolved_to_private')
        except Exception:
            continue

    if pub_ips and sys_ips:
        if not any(ip in pub_ips for ip in sys_ips):
            # CDNs/anycast providers (Cloudflare, Akamai, Google, etc.) route
            # different resolvers to different edge IPs by design, so a raw
            # IP-set mismatch for these hostnames is expected, not a sign of
            # DNS spoofing. Only score the mismatch for non-CDN hostnames.
            if any(k in hostname.lower() for k in CDN_HOSTNAME_KEYWORDS):
                res.details.setdefault('flags', []).append('dns_differs_but_cdn_hostname')
                res.details['note'] = 'system/public resolvers disagree, expected for CDN hostnames'
            else:
                res.suspicious = True
                res.score += 20
                res.details.setdefault('flags', []).append('dns_mismatch')

    return res

# ---------- HTTP header injection & captive portal ----------
def http_header_injection(hostname: str) -> DetectorResult:
    res = DetectorResult('http_header_injection')
    suspicious_markers = ['x-bluecoat', 'x-proxy', 'via', 'x-scan', 'x-forwarded-by', 'x-gateway']
    try:
        if REQUESTS_AVAILABLE:
            url = f'http://{hostname}/'
            r = requests.get(url, timeout=5, allow_redirects=True)
            headers = {k.lower(): v for k, v in r.headers.items()}
            for marker in suspicious_markers:
                if marker in headers:
                    res.suspicious = True
                    res.score += 25
                    res.details.setdefault('markers', []).append(marker)
            if r.status_code in (200, 302) and any(k in r.text.lower()[:2000] for k in ('login', 'sign in', 'captive', 'portal')):
                res.suspicious = True
                res.score += 18
                res.details.setdefault('flags', []).append('possible_captive_portal')
        else:
            sys_ips = resolve_system(hostname)
            addr = None
            for ip in sys_ips:
                if ':' not in ip:
                    addr = ip
                    break
            if not addr:
                res.details['error'] = 'no_ipv4_for_raw_http'
                return res
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((addr, 80))
                req = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                sock.send(req.encode())
                resp = sock.recv(8192).decode(errors='ignore')
                sock.close()
                lower = resp.lower()
                for marker in suspicious_markers:
                    if marker in lower:
                        res.suspicious = True
                        res.score += 25
                        res.details.setdefault('markers', []).append(marker)
            except Exception as e:
                res.details['error'] = f'raw_http_error:{e}'
    except Exception as e:
        res.details['error'] = f'http_probe_failed:{e}'
    return res

# ---------- VPN detection ----------
def _is_valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False

def check_vpn() -> DetectorResult:
    res = DetectorResult('vpn')
    res.details['psutil_available'] = PSUTIL_AVAILABLE
    if not PSUTIL_AVAILABLE:
        res.details['info'] = 'psutil not installed'
    else:
        try:
            if_addrs = psutil.net_if_addrs()
            for iface in if_addrs:
                lower = iface.lower()
                if any(p in lower for p in ('tun', 'tap', 'wg', 'utun', 'ppp', 'vpn')):
                    res.suspicious = True
                    res.score += 20
                    res.details.setdefault('interfaces', []).append(iface)

            for proc in psutil.process_iter(['name']):
                try:
                    name = (proc.info.get('name') or '').lower()
                    if any(vpn in name for vpn in ('openvpn', 'wireguard', 'nordvpn', 'expressvpn', 'protonvpn', 'mullvad', 'wg-quick', 'tor', 'shadowsocks')):
                        res.suspicious = True
                        res.score += 20
                        res.details.setdefault('processes', []).append(name)
                except Exception:
                    continue
        except Exception as e:
            res.details['psutil_error'] = str(e)

    # External IP checks: compare results from multiple public services
    exts = []
    if REQUESTS_AVAILABLE:
        services = ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://ipinfo.io/ip']
        for svc in services:
            try:
                r = requests.get(svc, timeout=4)
                ip = r.text.strip()
                # A service returning an error page or rate-limit notice (still
                # HTTP 200) would otherwise register as a distinct "IP" and
                # falsely trigger external_ip_mismatch below.
                if _is_valid_ip(ip):
                    exts.append(ip)
            except Exception:
                continue
    res.details['external_ips'] = list(dict.fromkeys(exts))
    if len(set(exts)) > 1:
        res.suspicious = True
        res.score += 30
        res.details.setdefault('flags', []).append('external_ip_mismatch')

    if not exts:
        res.details.setdefault('info', 'no_external_ip_services_available')

    return res

# ---------- JA3 / JA3S extraction (ja3python preferred, scapy fallback) ----------
def ja3_ja3s_check(hostname: str, port: int = 443, timeout: int = 4) -> DetectorResult:
    """
    Preferred flow:
      - If ja3python and scapy are available AND we can run a short sniff (privileged),
        try to capture real ClientHello/ServerHello bytes by sniffing the interface
        while initiating a normal TLS handshake. Feed raw bytes to JA3Fingerprint.
      - If JA3python is unavailable or we cannot capture raw bytes, fall back to
        the previous scapy-based best-effort approach.
    """
    res = DetectorResult('ja3_ja3s')
    try:
        ip_addr = socket.gethostbyname(hostname)
    except Exception as e:
        res.details['error'] = f'resolve_failed:{e}'
        return res

    res.details['server_ip'] = ip_addr

    # Try preferred path: ja3python + scapy sniff capture
    if JA3PY_AVAILABLE and SCAPY_AVAILABLE:
        # Need privileges for sniff on many platforms
        try:
            # Prepare a short sniffer in background (non-blocking)
            filter_exp = f'tcp and host {ip_addr} and port {port}'
            captured = []

            def _pkt_cb(pkt):
                try:
                    # store raw payload if present
                    if pkt.haslayer('Raw'):
                        raw = bytes(pkt['Raw'].load)
                        ts = float(pkt.time)
                        captured.append((ts, raw, pkt))
                except Exception:
                    pass

            # Start sniffer asynchronously using scapy's sniff with timeout in a thread
            sniffer_thread = None
            try:
                # Use async sniff in a separate thread to avoid blocking; scapy.sniff is blocking but we call with timeout
                sniffer_thread = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                fut = sniffer_thread.submit(lambda: scapy.sniff(filter=filter_exp, prn=_pkt_cb, timeout=timeout, store=0))
            except Exception:
                # fallback to direct sniff (may block)
                try:
                    scapy.sniff(filter=filter_exp, prn=_pkt_cb, timeout=timeout, store=0)
                except Exception:
                    pass

            # Trigger a TLS handshake by making a normal TLS connection (non-blocking)
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_NONE  # don't fail the handshake if cert invalid (we only want bytes)
                with socket.create_connection((ip_addr, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                        # try a small read to ensure handshake completes
                        try:
                            ss.settimeout(0.8)
                            ss.recv(1)
                        except Exception:
                            pass
            except Exception:
                # handshake might fail due to cert or other reasons; that's okay, sniff may still capture
                pass

            # Wait small amount for sniffer to finish
            try:
                if 'fut' in locals():
                    fut.result(timeout=timeout + 1)
            except Exception:
                pass
            try:
                if sniffer_thread:
                    sniffer_thread.shutdown(wait=False)
            except Exception:
                pass

            # Process captured raw payloads: find first ClientHello (handshake type 1) and ServerHello (type 2)
            client_raw = None
            server_raw = None
            for _ts, raw, pkt in captured:
                try:
                    if not raw or len(raw) < 5:
                        continue
                    # TLS record: first byte 0x16 for Handshake
                    if raw[0] == 0x16:
                        # handshake type is at offset 5 (first handshake msg)
                        # But record structure: content_type(1) version(2) length(2) => handshake starts at 5
                        if len(raw) > 5:
                            htype = raw[5]
                            if htype == 1 and client_raw is None:
                                client_raw = raw
                            elif htype == 2 and server_raw is None:
                                server_raw = raw
                except Exception:
                    continue

            # If we have client_raw or server_raw, feed to JA3Fingerprint
            if client_raw:
                try:
                    fp = JA3Fingerprint(client_raw)
                    # API may provide attributes; attempt to read common ones
                    ja3_str = getattr(fp, 'ja3_string', None) or getattr(fp, 'ja3', None)
                    ja3_md5 = getattr(fp, 'ja3_hash', None) or getattr(fp, 'ja3_md5', None) or None
                    res.details.setdefault('ja3', {})
                    res.details['ja3']['string'] = ja3_str
                    res.details['ja3']['md5'] = ja3_md5
                    if ja3_md5 and ja3_md5 in KNOWN_BAD_JA3:
                        res.suspicious = True
                        res.score += 40
                        res.details.setdefault('flags', []).append('known_bad_ja3')
                except Exception as e:
                    res.details['ja3_error'] = str(e)

            if server_raw:
                try:
                    fp_s = JA3Fingerprint(server_raw)
                    ja3s_str = getattr(fp_s, 'ja3s_string', None) or getattr(fp_s, 'ja3s', None)
                    ja3s_md5 = getattr(fp_s, 'ja3s_hash', None) or getattr(fp_s, 'ja3s_md5', None) or None
                    res.details.setdefault('ja3s', {})
                    res.details['ja3s']['string'] = ja3s_str
                    res.details['ja3s']['md5'] = ja3s_md5
                    if ja3s_md5 and ja3s_md5 in KNOWN_BAD_JA3:
                        res.suspicious = True
                        res.score += 40
                        res.details.setdefault('flags', []).append('known_bad_ja3s')
                except Exception as e:
                    res.details['ja3s_error'] = str(e)

            # If we captured none, set note and fall back
            if not client_raw and not server_raw:
                res.details.setdefault('note', 'no_raw_tls_records_captured_with_sniff')
                # fall through to fallback below
            else:
                return res
        except PermissionError:
            # sniff needs root; fall through to fallback
            res.details.setdefault('note', 'permission_denied_sniff')
        except Exception as e:
            res.details.setdefault('note', f'sniff_failed:{e}')

    # If JA3python isn't available or sniffing failed, fall back to prior scapy-based best-effort
    if SCAPY_AVAILABLE and SCAPY_TLS_AVAILABLE:
        try:
            # Attempt to reuse previous best-effort approach (non-exact JA3 string build)
            CH_CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0x009e, 0x009c]
            try:
                ch = None
                try:
                    ch = scapy_tls.TLSClientHello(ciphers=CH_CIPHERS,
                                              ext=[scapy_tls.TLSExt_SupportedGroups(groups=[29, 23, 24]),
                                                   scapy_tls.TLSExt_SupportedVersions(versions=[0x0304, 0x0303])])
                except Exception:
                    # If TLSClientHello not available, create basic TLS record object placeholder
                    ch = None

                ip = scapy.IP(dst=ip_addr)
                tcp = scapy.TCP(dport=port, sport=random.randint(20000, 60000), flags='S')
                synack = scapy.sr1(ip / tcp, timeout=2, verbose=0)
                if not synack:
                    res.details.setdefault('note', 'no_synack_for_fallback')
                    return res
                ack = scapy.TCP(dport=port,
                                sport=synack[scapy.TCP].dport,
                                seq=synack[scapy.TCP].ack,
                                ack=synack[scapy.TCP].seq + 1,
                                flags='A')
                scapy.send(ip / ack, verbose=0)
                if ch is not None:
                    try:
                        tls_pkt = scapy_tls.TLS(msg=[ch])
                        ans = scapy.sr1(ip / ack / tls_pkt, timeout=2, verbose=0)
                    except Exception:
                        ans = None
                    # Build JA3-like string (best effort)
                    try:
                        ssl_ver = 771
                        cipher_csv = '-'.join(str(c) for c in CH_CIPHERS)
                        ext_types = []
                        curves = []
                        ecformats = []
                        if ch and hasattr(ch, 'ext') and ch.ext:
                            for e in ch.ext:
                                if hasattr(e, 'type'):
                                    ext_types.append(str(int(e.type)))
                                if hasattr(e, 'groups') and getattr(e, 'groups') is not None:
                                    curves.extend(str(g) for g in e.groups)
                                if hasattr(e, 'ecpointformats') and getattr(e, 'ecpointformats') is not None:
                                    ecformats.extend(str(f) for f in e.ecpointformats)
                        ext_csv = '-'.join(ext_types) if ext_types else '-'
                        curves_csv = '-'.join(curves) if curves else '-'
                        ec_csv = '-'.join(ecformats) if ecformats else '-'
                        ja3_str = f"{ssl_ver},{cipher_csv},{ext_csv},{curves_csv},{ec_csv}"
                        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
                        res.details.setdefault('ja3', {})
                        res.details['ja3']['string'] = ja3_str
                        res.details['ja3']['md5'] = ja3_hash
                        if ja3_hash in KNOWN_BAD_JA3:
                            res.suspicious = True
                            res.score += 40
                            res.details.setdefault('flags', []).append('known_bad_ja3')
                    except Exception:
                        pass
                    # Attempt to parse serverhello similarly (best-effort)
                    try:
                        if ans and ans.haslayer(scapy_tls.TLSServerHello):
                            sh = ans[scapy_tls.TLSServerHello]
                            sv = int(getattr(sh, 'version', 0))
                            scipher = int(getattr(sh, 'cipher', 0))
                            sext = []
                            if hasattr(sh, 'ext') and sh.ext:
                                for e in sh.ext:
                                    if hasattr(e, 'type'):
                                        sext.append(str(int(e.type)))
                            ja3s_str = f"{sv},{scipher},{'-'.join(sext) if sext else '-'}"
                            ja3s_hash = hashlib.md5(ja3s_str.encode()).hexdigest()
                            res.details.setdefault('ja3s', {})
                            res.details['ja3s']['string'] = ja3s_str
                            res.details['ja3s']['md5'] = ja3s_hash
                            if ja3s_hash in KNOWN_BAD_JA3:
                                res.suspicious = True
                                res.score += 40
                                res.details.setdefault('flags', []).append('known_bad_ja3s')
                        else:
                            res.details.setdefault('note', 'no_parsed_serverhello_in_fallback')
                    except Exception:
                        res.details.setdefault('note', 'ja3s_fallback_failed')
                else:
                    res.details.setdefault('note', 'scapy_tls_clienthello_unavailable_fallback')
            except PermissionError:
                res.details.setdefault('error', 'permission_denied_need_root_for_scapy')
            except Exception as e:
                res.details.setdefault('note', f'scapy_fallback_error:{e}')
        except Exception as e:
            res.details.setdefault('note', f'scapy_wrapper_error:{e}')
    elif SCAPY_AVAILABLE and not SCAPY_TLS_AVAILABLE:
        res.details.setdefault('error', 'scapy_layers_tls_not_importable')
    else:
        # Neither JA3python nor scapy available
        res.details.setdefault('error', 'ja3_not_available_scapy_not_available')
    return res

# ---------- TCP Reset injection detection ----------
def detect_reset_injection(hostname: str, port: int = 443, timeout: int = 3) -> DetectorResult:
    res = DetectorResult('tcp_rst_injection')
    if not SCAPY_AVAILABLE:
        res.details['error'] = 'scapy_not_installed'
        return res

    try:
        server_ip = socket.gethostbyname(hostname)
    except Exception as e:
        res.details['error'] = f'resolve_failed:{e}'
        return res

    res.details['server_ip'] = server_ip
    try:
        sport = random.randint(10245, 65500)
        ip = scapy.IP(dst=server_ip)
        syn = scapy.TCP(dport=port, sport=sport, flags='S', seq=random.randint(0, (1 << 32) - 1))
        resp = scapy.sr1(ip / syn, timeout=timeout, verbose=0)
        if resp is None:
            res.details['note'] = 'no_response'
            res.score += 8
            return res

        if resp.haslayer(scapy.TCP):
            rflags = resp[scapy.TCP].flags
            src_ip = resp[scapy.IP].src if resp.haslayer(scapy.IP) else None
            res.details['resp_src'] = src_ip
            res.details['resp_flags'] = int(rflags)
            if rflags & 0x04:
                if src_ip and src_ip != server_ip:
                    res.suspicious = True
                    res.score += 45
                    res.details.setdefault('flags', []).append('rst_from_third_party')
                else:
                    res.suspicious = True
                    res.score += 12
                    res.details.setdefault('flags', []).append('rst_from_server')
            else:
                res.details['note'] = 'no_rst'
        else:
            res.details['note'] = 'no_tcp_layer'
    except PermissionError:
        res.details['error'] = 'permission_denied_need_root_for_scapy'
    except Exception as e:
        res.details['error'] = str(e)
    return res

# ---------- TTL manipulation check ----------
def _reverse_dns(ip: str, timeout: float = 1.5) -> Optional[str]:
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            return fut.result(timeout=timeout)[0].lower()
    except Exception:
        return None

def ttl_manipulation_check(hostname: str) -> DetectorResult:
    res = DetectorResult('ttl_manipulation')
    if not SCAPY_AVAILABLE:
        res.details['error'] = 'scapy_not_installed'
        return res
    hops = []
    try:
        for ttl in range(1, 30):
            pkt = scapy.IP(dst=hostname, ttl=ttl) / scapy.ICMP()
            ans, _ = scapy.sr(pkt, timeout=2, verbose=0)
            if ans:
                try:
                    src = ans[0][scapy.IP].src
                except Exception:
                    src = None
                if src:
                    hops.append(src)
                    # DPI_INDICATORS are vendor names (e.g. "fortinet"), which
                    # never appear in a raw hop IP address - only in its rDNS
                    # name, if any. Resolving PTR records is what makes this
                    # check able to match anything at all.
                    ptr = _reverse_dns(src)
                    if ptr and any(ind in ptr for ind in DPI_INDICATORS):
                        res.suspicious = True
                        res.score += 28
                        res.details.setdefault('flags', []).append(f'dpi_vendor_hop:{ptr}')
            else:
                break
    except PermissionError:
        res.details['error'] = 'permission_denied_need_root_for_scapy'
    except Exception as e:
        res.details['error'] = str(e)
    res.details['hops'] = hops
    if len(hops) > 15:
        res.suspicious = True
        res.score += 18
        res.details.setdefault('flags', []).append('extra_hops_detected')
    return res

# ---------- Packet fragmentation check ----------
def _tcp_handshake(ip_addr: str, port: int, timeout: float = 3) -> Optional[Dict]:
    sport = random.randint(20000, 60000)
    client_seq = random.randint(0, (1 << 32) - 1)
    syn = scapy.TCP(dport=port, sport=sport, flags='S', seq=client_seq)
    synack = scapy.sr1(scapy.IP(dst=ip_addr) / syn, timeout=timeout, verbose=0)
    if not synack or not synack.haslayer(scapy.TCP) or not (synack[scapy.TCP].flags & 0x12):
        return None
    conn = {'sport': sport, 'seq': client_seq + 1, 'ack': synack[scapy.TCP].seq + 1}
    ack_pkt = scapy.TCP(dport=port, sport=sport, seq=conn['seq'], ack=conn['ack'], flags='A')
    scapy.send(scapy.IP(dst=ip_addr) / ack_pkt, verbose=0)
    return conn

def packet_fragmentation_check(hostname: str) -> DetectorResult:
    res = DetectorResult('packet_fragmentation')
    if not SCAPY_AVAILABLE:
        res.details['error'] = 'scapy_not_installed'
        return res
    try:
        ip_addr = socket.gethostbyname(hostname)

        # Both requests need a real completed 3-way handshake first: sending
        # a data segment with an arbitrary seq/ack before one existed meant
        # every response - or lack of one - reflected a malformed connection,
        # not whether the network was blocking fragments.
        request = (b'GET / HTTP/1.1\r\nHost: ' + hostname.encode() +
                   b'\r\nConnection: close\r\n\r\n')
        padded_request = (b'GET / HTTP/1.1\r\nHost: ' + hostname.encode() +
                           b'\r\nConnection: close\r\nX-Padding: ' + b'A' * 1000 +
                           b'\r\n\r\n')

        conn1 = _tcp_handshake(ip_addr, 80)
        non_frag_success = False
        if conn1:
            datapkt = scapy.TCP(dport=80, sport=conn1['sport'], seq=conn1['seq'], ack=conn1['ack'], flags='PA')
            resp = scapy.sr1(scapy.IP(dst=ip_addr) / datapkt / scapy.Raw(request), timeout=3, verbose=0)
            non_frag_success = resp is not None

        conn2 = _tcp_handshake(ip_addr, 80)
        frag_success = False
        if conn2:
            datapkt2 = scapy.TCP(dport=80, sport=conn2['sport'], seq=conn2['seq'], ack=conn2['ack'], flags='PA')
            full_pkt = scapy.IP(dst=ip_addr) / datapkt2 / scapy.Raw(padded_request)
            frag_pkts = scapy.fragment(full_pkt, fragsize=500)
            frag_ans, _ = scapy.sr(frag_pkts, timeout=3, verbose=0)
            frag_success = bool(frag_ans)

        if not conn1 or not conn2:
            res.details['note'] = 'tcp_handshake_failed'
        elif non_frag_success and not frag_success:
            res.suspicious = True
            res.score += 30
            res.details.setdefault('flags', []).append('fragments_blocked')
    except PermissionError:
        res.details['error'] = 'permission_denied_need_root_for_scapy'
    except Exception as e:
        res.details['error'] = str(e)
    return res

# ---------- QUIC / HTTP3 probing (aioquic) ----------
async def quic_probe_async(hostname: str, port: int = 443, timeout: int = 5) -> DetectorResult:
    res = DetectorResult('quic_probe')
    if not AIOQUIC_AVAILABLE:
        res.details['error'] = 'aioquic_not_installed'
        return res
    try:
        sslctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        try:
            async with quic_connect(hostname, port=port, server_name=hostname, configuration=None, create_protocol=None, ssl=sslctx) as client:
                res.details['quic'] = 'handshake_succeeded'
                return res
        except Exception as e:
            res.details['error'] = f'quic_handshake_error:{e}'
            res.suspicious = True
            res.score += 20
            return res
    except Exception as e:
        res.details['error'] = str(e)
        return res

def quic_probe(hostname: str, timeout: int = 5) -> DetectorResult:
    res = DetectorResult('quic_probe')
    if not AIOQUIC_AVAILABLE:
        res.details['error'] = 'aioquic_not_installed'
        return res
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        coro = quic_probe_async(hostname, timeout=timeout)
        r = loop.run_until_complete(coro)
        return r
    except Exception as e:
        res.details['error'] = str(e)
        return res

# ---------- ASN / Geolocation checks ----------
def asn_geolocate_ip(ip: str) -> Dict:
    out = {'ip': ip}
    if not REQUESTS_AVAILABLE:
        out['error'] = 'requests_not_installed'
        return out
    try:
        r = requests.get(f'https://ipinfo.io/{ip}/json', timeout=4)
        if r.status_code == 200:
            data = r.json()
            out['org'] = data.get('org')
            if data.get('org'):
                parts = str(data.get('org')).split()
                if parts and parts[0].upper().startswith('AS'):
                    out['asn'] = parts[0]
                else:
                    out['asn'] = data.get('asn') or None
            out['country'] = data.get('country')
            return out
    except Exception:
        pass
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=4)
        if r.status_code == 200:
            data = r.json()
            out['org'] = data.get('org')
            out['asn'] = data.get('as')
            out['country'] = data.get('countryCode') or data.get('country')
            return out
    except Exception:
        pass
    out['note'] = 'geolocation_failed'
    return out

def asn_check(hostname: str) -> DetectorResult:
    res = DetectorResult('asn_check')
    sys_ips = resolve_system(hostname)
    res.details['system_ips'] = sys_ips
    if not sys_ips:
        res.details['error'] = 'no_resolution'
        res.score += 1
        return res
    suspicious_asns = []
    infos = []
    for ip in sys_ips:
        try:
            info = asn_geolocate_ip(ip)
            infos.append(info)
            asn = (info.get('asn') or str(info.get('org') or '')).lower()
            host_lower = hostname.lower()
            if any(k in host_lower for k in CDN_HOSTNAME_KEYWORDS):
                if not any(provider in (info.get('org') or '').lower() for provider in CDN_HOSTNAME_KEYWORDS):
                    suspicious_asns.append({'ip': ip, 'org': info.get('org'), 'asn': info.get('asn')})
            if info.get('org') and any(x in info.get('org').lower() for x in ('residential', 'dsl', 'isp', 'telecom', 'telefonica', 'vodafone', 'comcast')):
                suspicious_asns.append({'ip': ip, 'org': info.get('org'), 'asn': info.get('asn')})
        except Exception:
            continue
    res.details['asn_infos'] = infos
    if suspicious_asns:
        res.suspicious = True
        res.score += 25
        res.details.setdefault('flags', []).append('unexpected_asn_for_hostname')
        res.details['suspicious_asns'] = suspicious_asns
    return res

# ---------- Censorship check ----------
def _site_reachable(site: str, attempts: int = 2, timeout: int = 6) -> bool:
    # A single timed-out request is common on ordinary flaky networks and
    # shouldn't by itself count as evidence of censorship; retry once before
    # giving up on a site.
    for _ in range(attempts):
        try:
            if REQUESTS_AVAILABLE:
                r = requests.get(f'https://{site}', timeout=timeout)
                if r.status_code < 400:
                    return True
            else:
                socket.gethostbyname(site)
                return True
        except Exception:
            continue
    return False

def censorship_check() -> DetectorResult:
    res = DetectorResult('censorship')
    blocked = [site for site in CENSORSHIP_TEST_SITES if not _site_reachable(site)]
    if blocked:
        res.suspicious = True
        res.score += int(40 * (len(blocked) / len(CENSORSHIP_TEST_SITES)))
        res.details['blocked_sites'] = blocked
    return res

# ---------- Aggregation & decision ----------
def _recompute_suspicious(out: Dict) -> None:
    total = 0
    high_flags = 0
    for d in out['detectors'].values():
        total += d.get('score', 0)
        if d.get('suspicious') and d.get('score', 0) >= 30:
            high_flags += 1
    out['dpi_score'] = int(total)
    out['suspicious'] = high_flags >= 2 or total >= 70

def correlate_results(site: str, detectors: List[DetectorResult]) -> Dict:
    out = {'site': site, 'timestamp': now_iso(), 'detectors': {}, 'suspicious': False, 'dpi_score': 0}
    for d in detectors:
        out['detectors'][d.name] = d.to_dict()
    _recompute_suspicious(out)
    return out

# ---------- Final conclusion ----------
def generate_conclusion(summary: Dict, vpn_result: Optional[DetectorResult]) -> Dict:
    total = summary.get('summary', {}).get('total_sites', 0)
    suspicious = summary.get('summary', {}).get('suspicious_sites', 0)
    avg_score = 0
    if total:
        avg_score = sum(s.get('dpi_score', 0) for s in summary.get('sites', {}).values()) / total

    conclusion = {'likely_dpi': False, 'reasoning': [], 'recommend_vpn': False, 'visibility_level': {'headers': 'always visible', 'payloads': 'if MITM or unencrypted', 'recommendations': 'Use TLS 1.3+ and VPN for obfuscation'}}

    if total == 0:
        conclusion['reasoning'].append('No sites tested')
    else:
        ratio = suspicious / total
        if ratio >= 0.5:
            conclusion['likely_dpi'] = True
            conclusion['reasoning'].append(f'High fraction of suspicious sites: {suspicious}/{total}')
        if avg_score > 40:
            conclusion['likely_dpi'] = True
            conclusion['reasoning'].append(f'High average DPI score: {avg_score:.1f}')
        if not conclusion['likely_dpi'] and (ratio > 0 or avg_score > 20):
            conclusion['reasoning'].append('Some anomalies detected but below multi-signal threshold')

    vpn_active = False
    vpn_details = None
    if isinstance(vpn_result, DetectorResult):
        if vpn_result.suspicious:
            vpn_active = True
        vpn_details = vpn_result.details

    if conclusion['likely_dpi']:
        conclusion['recommend_vpn'] = True
        conclusion['vpn_reason'] = 'Network appears to be intercepting traffic; using a trusted VPN is recommended.'
    else:
        if not vpn_active and avg_score > 25:
            conclusion['recommend_vpn'] = True
            conclusion['vpn_reason'] = 'Some anomalies detected; a VPN may help protect privacy.'
        else:
            conclusion['recommend_vpn'] = False
            conclusion['vpn_reason'] = 'No strong evidence of interception.'

    if vpn_details:
        conclusion['vpn_details'] = vpn_details

    conclusion['suspicious_sites'] = suspicious
    conclusion['total_sites'] = total
    conclusion['avg_score'] = round(avg_score, 2)
    return conclusion

def _flag_relative_timing_outliers(sites: Dict[str, Dict]) -> None:
    # Compares each tested site's TLS handshake time against the median of
    # the *other sites tested in this same run* rather than a fixed constant,
    # so the check adapts to the user's own baseline latency (mobile,
    # satellite, distant CDN, etc.) instead of flagging everyone on a slow
    # link. Needs at least 3 sites with valid samples to be meaningful.
    samples = []
    for site, out in sites.items():
        m = out['detectors'].get('tls_timing', {}).get('details', {}).get('median_ms')
        if m is not None:
            samples.append((site, m))
    if len(samples) < 3:
        return

    values = [m for _, m in samples]
    pop_median = statistics.median(values)
    mad = statistics.median(abs(v - pop_median) for v in values)
    if mad == 0:
        return

    for site, m in samples:
        modified_z = 0.6745 * (m - pop_median) / mad
        if modified_z > 3.5:  # only flag sites slower than the rest of the batch
            td = sites[site]['detectors']['tls_timing']
            td['suspicious'] = True
            td['score'] = td.get('score', 0) + 20
            td.setdefault('details', {}).setdefault('flags', []).append('relative_timing_outlier')
            _recompute_suspicious(sites[site])

# ---------- Worker / Runner ----------
def run_sites(sites: List[str], verbose: bool = False, quick: bool = False, workers: int = 4) -> Dict:
    summary = {'timestamp': now_iso(), 'sites': {}}

    def run_one(site: str) -> Tuple[str, Dict]:
        detectors = []
        timing_samples = 3 if quick else 7

        dns_res = dns_spoof_check(site)
        detectors.append(dns_res)

        cert_dict, htime, cert_der = fetch_certificate(site)
        cert_an = analyze_certificate(cert_dict, cert_der)
        if htime:
            cert_an.details['handshake_time_s'] = round(htime, 3)
            if htime > 0.6:
                cert_an.suspicious = True
                cert_an.score += 15
                cert_an.details.setdefault('flags', []).append('slow_handshake')
        detectors.append(cert_an)

        observed_fp = cert_an.details.get('fingerprint_sha256')
        ct = ct_log_check(site, observed_fp)
        detectors.append(ct)

        tls_timing = tls_timing_profile(site, samples=timing_samples)
        detectors.append(tls_timing)

        tls_fin = tls_version_and_cipher_check(site)
        detectors.append(tls_fin)

        http_hij = http_header_injection(site)
        detectors.append(http_hij)

        # JA3 / JA3S
        ja3r = ja3_ja3s_check(site)
        detectors.append(ja3r)

        # TCP RST injection
        rst = detect_reset_injection(site)
        detectors.append(rst)

        ttl_res = ttl_manipulation_check(site)
        detectors.append(ttl_res)

        frag_res = packet_fragmentation_check(site)
        detectors.append(frag_res)

        # ASN/geolocation check
        asn_r = asn_check(site)
        detectors.append(asn_r)

        # QUIC probe - may take longer; run only if aioquic installed
        if AIOQUIC_AVAILABLE:
            quic_r = quic_probe(site)
            detectors.append(quic_r)
        else:
            detectors.append(DetectorResult('quic_probe'))  # placeholder with no-op

        return site, correlate_results(site, detectors)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(run_one, s) for s in sites]
        for fut in concurrent.futures.as_completed(futures):
            try:
                site, out = fut.result()
                summary['sites'][site] = out
            except Exception as e:
                print('Site worker error:', e)

    _flag_relative_timing_outliers(summary['sites'])

    for site, out in summary['sites'].items():
        if verbose:
            print(json.dumps(out, indent=2))
        else:
            print(f"{site}: suspicious={out['suspicious']} score={out['dpi_score']}")

    censor_res = censorship_check()
    summary['censorship'] = censor_res.to_dict()

    total = len(sites)
    suspicious_count = sum(1 for s in summary['sites'].values() if s.get('suspicious'))
    summary['summary'] = {'total_sites': total, 'suspicious_sites': suspicious_count}
    return summary

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description='Improved DPI Detection Framework (v3)')
    parser.add_argument('--sites', nargs='+', default=DEFAULT_SITES)
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--check-vpn', action='store_true')
    parser.add_argument('--passive', action='store_true')
    parser.add_argument('--quick', action='store_true')
    parser.add_argument('--output', choices=['text', 'json'], default='text')
    args = parser.parse_args()

    print('\n=== Improved DPI Detector (v3) ===\n')
    if args.quick:
        print('Quick mode: fewer samples, faster run')
    if SCAPY_AVAILABLE and (os.geteuid() != 0 if hasattr(os, 'geteuid') else False):
        print('Note: scapy is available but you may need root/administrator privileges for raw-socket probes.')

    results = run_sites(args.sites, verbose=args.verbose, quick=args.quick)
    vpn = None
    if args.check_vpn:
        vpn = check_vpn()
        results['vpn'] = vpn.to_dict()

    conclusion = generate_conclusion(results, vpn)

    if args.output == 'json':
        out = {'results': results, 'conclusion': conclusion}
        print(json.dumps(out, indent=2))
    else:
        print('\nRun complete. Summary:')
        print(f" Tested: {results['summary']['total_sites']} sites")
        print(f" Suspicious: {results['summary']['suspicious_sites']}")
        print('\nConclusion:')
        if conclusion['likely_dpi']:
            print('  ⚠️  Network likely performs DPI/interception')
        else:
            print('  ✓ Network shows no strong, multi-signal DPI evidence')
        for reason in conclusion.get('reasoning', []):
            print(f"   - {reason}")
        if conclusion['recommend_vpn']:
            print('\nRecommendation: Use a trusted VPN for privacy.')
            print(f"Reason: {conclusion.get('vpn_reason')}")
        else:
            print('\nRecommendation: VPN not strictly required based on current tests.')
            print(f"Note: {conclusion.get('vpn_reason')}")
        print('\nNetwork Visibility Insights:')
        for k, v in conclusion['visibility_level'].items():
            print(f"  {k}: {v}")

    sys.exit(1 if results['summary']['suspicious_sites'] > 0 else 0)

if __name__ == '__main__':
    main()

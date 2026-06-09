#!/usr/bin/env python3
"""
SAML Interceptor
----------------
System-wide Windows proxy that captures and decodes SAML requests/responses,
groups them into per-login flow tabs named by the authenticated email address.

Requirements:
    pip install cryptography

Flow:
  1. Click "Install CA Cert" once.
  2. Click "Start Intercepting" — sets system proxy to localhost:8080.
  3. Each login attempt gets its own tab, named by email once the response arrives.
  4. Stop or close to restore original proxy settings.
"""

import os
import re
import sys
import webbrowser
import ssl
import zlib
import base64
import queue
import select
import socket
import winreg
import hashlib
import ctypes
import logging
import threading
import traceback
import subprocess
import urllib.parse
import xml.dom.minidom
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from tkinter import ttk, scrolledtext, messagebox
from pathlib import Path
from datetime import datetime, timezone, timedelta

try:
    from _version import __version__
except ImportError:
    __version__ = 'dev'

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False


# ─── Logging ──────────────────────────────────────────────────────────────────

_LOG_DIR  = Path(os.environ.get('APPDATA', '.')) / 'SAMLInterceptor'
_LOG_DIR.mkdir(parents=True, exist_ok=True)

_log = logging.getLogger('saml')
_log.setLevel(logging.WARNING)
_log.propagate = False
_log_handler = logging.FileHandler(str(_LOG_DIR / 'debug.log'), mode='w', encoding='utf-8')
_log_handler.setLevel(logging.WARNING)
_log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
_log.addHandler(_log_handler)


# ─── SAML decode ─────────────────────────────────────────────────────────────

_BLOB_RE = re.compile(r'(?m)^([ \t]*)([A-Za-z0-9+/\r\n\t ]{80,}={0,2})$')


def _clean_xml(xml_str: str) -> str:
    def _sub(m: re.Match) -> str:
        blob = re.sub(r'\s', '', m.group(2))
        return f'{m.group(1)}[{len(blob)} base64 chars]'
    return _BLOB_RE.sub(_sub, xml_str)


def _decode_saml_value(value: str, redirect_binding: bool) -> str:
    try:
        value = urllib.parse.unquote(value)
        rem = len(value) % 4
        if rem:
            value += '=' * (4 - rem)
        raw = base64.b64decode(value)
        xml_bytes = zlib.decompress(raw, -15) if redirect_binding else raw
        return xml.dom.minidom.parseString(xml_bytes).toprettyxml(indent='  ')
    except Exception as exc:
        return f'[Decode error: {exc}]\n\nRaw:\n{value}'


def _find_saml(data: str, post_body: bool) -> list:
    results = []
    try:
        params = urllib.parse.parse_qs(data, keep_blank_values=True)
        for key, vals in params.items():
            low = key.lower()
            if low in ('samlrequest', 'samlresponse'):
                kind = 'SAMLRequest' if 'request' in low else 'SAMLResponse'
                for val in vals:
                    results.append({
                        'type': kind,
                        'binding': 'POST' if post_body else 'Redirect',
                        'raw': val,
                        'decoded': _decode_saml_value(val, redirect_binding=not post_body),
                    })
    except Exception:
        _log.debug("_find_saml parse error", exc_info=True)
    return results


# ─── SAML field extraction ────────────────────────────────────────────────────

def _xml_text(xml_str: str, *tags: str) -> str:
    for tag in tags:
        m = re.search(rf'<[^>]*:?{re.escape(tag)}[^>]*>([^<]+)<', xml_str, re.DOTALL)
        if m:
            v = m.group(1).strip()
            if v:
                return v
    return ''


def _xml_attr(xml_str: str, tag: str, attr: str) -> str:
    m = re.search(
        rf'<[^>]*:?{re.escape(tag)}[^>]+{re.escape(attr)}="([^"]+)"', xml_str)
    return m.group(1) if m else ''


def _fmt_time(t: str) -> str:
    return t.replace('T', '   ').replace('Z', ' UTC') if t else ''


def _shorten_claim(uri: str) -> str:
    """Strip URI prefix — keep only the local claim name."""
    return uri.rstrip('/').split('/')[-1].split('#')[-1]


def _extract_saml_id(xml_str: str) -> str:
    """Extract the ID attribute from the root SAML element."""
    # Try element-name-aware match first (handles attribute-reordered output from minidom)
    m = re.search(r'<[^>]*:?(?:AuthnRequest|LogoutRequest|ArtifactResolve)\b[^>]*\bID="([^"]+)"',
                  xml_str)
    if not m:
        # Fall back to any ID attribute; SAMLRequest root is always the first element with one
        m = re.search(r'\bID="([A-Za-z0-9_:.-]+)"', xml_str)
    return m.group(1) if m else ''


def _extract_in_response_to(xml_str: str) -> str:
    m = re.search(r'\bInResponseTo="([^"]+)"', xml_str)
    return m.group(1) if m else ''


def _extract_email(xml_str: str) -> str:
    """Best-effort email extraction from a SAMLResponse."""
    # Try common email claim URIs
    for pattern in (
        r'<[^>]*:?Attribute[^>]+Name="[^"]*(?:email|mail|upn|EmailAddress)[^"]*"[^>]*>'
        r'.*?<[^>]*:?AttributeValue[^>]*>([^<]+)<',
        r'<[^>]*:?Attribute[^>]+Name="email"[^>]*>.*?<[^>]*:?AttributeValue[^>]*>([^<]+)<',
    ):
        m = re.search(pattern, xml_str, re.DOTALL | re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if '@' in val:
                return val
    # NameID fallback
    nameid = _xml_text(xml_str, 'NameID', 'NameIdentifier')
    if '@' in nameid:
        return nameid
    return ''


# ─── SAML summary renderer ────────────────────────────────────────────────────

_LW = 20   # label column width
_GUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)

# Entra built-in directory role template IDs (published by Microsoft, static)
_WIDS_ROLES = {
    '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
    'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
    '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
    '29232cdf-9323-42fd-ade2-1d097af3e4de': 'Exchange Administrator',
    '75941009-915a-4869-abe7-691bff18279e': 'Skype for Business Administrator',
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator',
    '158c047a-c907-4556-b7ef-446551a6b5f7': 'Cloud Application Administrator',
    'b0f54661-2d74-4c50-afa3-1ec803f12efe': 'Billing Administrator',
    '17315797-102d-40b4-93e0-432062caca18': 'Compliance Administrator',
    'e6d1a23a-da11-4be4-9570-befc86d067a7': 'Compliance Data Administrator',
    '88d8e3e3-8f55-4a1e-953a-9b9898b8876b': 'Directory Readers',
    '9360feb5-f418-4baa-8175-e2a00bac4301': 'Directory Writers',
    'd29b2b05-8046-44ba-8758-1e26182fcf32': 'Directory Synchronization Accounts',
    'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator',
    'b79fbf4d-3ef9-4689-8143-76b194e85509': 'Message Center Reader',
    'ac16e43d-7b2d-40e0-ac05-243ff356ab5b': 'Message Center Privacy Reader',
    '4a5d8f65-41da-4de4-8968-e035b65339cf': 'Reports Reader',
    '5d6b6bb7-de71-4623-b4af-96380a352509': 'Security Reader',
    '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f': 'Security Operator',
    'f023fd81-a637-4b56-95fd-791ac0226033': 'Service Support Administrator',
    '2b499bcd-da44-4968-8aec-78e1674fa64d': 'Guest Inviter',
    '729827e3-9c14-49f7-bb1b-9608f156bbb8': 'Helpdesk Administrator',
    '966707d0-3269-4727-9be2-8c3a10f19b9d': 'Password Administrator',
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': 'Conditional Access Administrator',
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator',
    'c4e39bd9-1100-46d3-8c65-fb160da0071f': 'Authentication Administrator',
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451': 'Global Reader',
    '7698a772-787b-4ac8-901f-60d6b08affd2': 'Cloud Device Administrator',
    'e3973bdf-4987-49ae-837a-ba8e231c7286': 'Azure DevOps Administrator',
    '7495fdc4-34c4-4d15-a289-98788ce399fd': 'Azure Information Protection Administrator',
    '3a2c62db-5318-420d-8d74-23affee5d9d5': 'Intune Administrator',
    '4d6ac14f-3453-41d0-bef9-a3e0c569773a': 'License Administrator',
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2': 'Hybrid Identity Administrator',
    'fdd7a751-b60b-444a-984c-02652fe8fa1c': 'Groups Administrator',
    '11648597-926c-4cf3-9c36-bcebb0ba8dcc': 'Power Platform Administrator',
    'a9ea8996-122f-4c74-9520-8edcd192826c': 'Power BI Administrator',
    '69091246-20e8-4a56-aa4d-066075b2a7a8': 'Teams Administrator',
    'baf37b3a-610e-45da-9e62-d9d1e5e8914b': 'Teams Communications Administrator',
    'f70938a0-fc10-4177-9e90-2178f8765737': 'Teams Communications Support Engineer',
    'fcf91098-03e3-41a9-b5ba-6f0ec8188a12': 'Teams Communications Support Specialist',
    '3d762c5a-1b6c-493f-843e-55a3b42923d4': 'Teams Devices Administrator',
    '0964bb5e-9bdb-4d7b-ac29-58e794862a40': 'Search Administrator',
    '8835291a-918c-4fd7-a9ce-faa49f0cf7d9': 'Search Editor',
    '2af84b1e-32c8-42b7-82bc-daa82404023b': 'Attribute Assignment Administrator',
    '58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d': 'Attribute Assignment Reader',
    'e7cbe68f-a010-4a15-8eca-ccc20049e4b7': 'Attribute Definition Administrator',
    '1d336d2c-4ae8-42ef-9711-b3604ce3fc2c': 'Attribute Definition Reader',
    '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e': 'Identity Governance Administrator',
    '810a2642-a034-447f-a5e8-41beaa378541': 'Yammer Administrator',
    '11451d60-acb2-45eb-a7d6-43d0f0125c13': 'Windows 365 Administrator',
    'd37c8bed-0711-4417-ba38-b4abe66ce4c2': 'Network Administrator',
    'be2f45a1-457d-42af-a067-6ec1fa63bc45': 'External Identity Provider Administrator',
    'aaf43236-0c0d-4d5f-883a-6955382ac081': 'B2C IEF Keyset Administrator',
    '3edaf663-341e-4475-9f94-5c398ef6c070': 'B2C IEF Policy Administrator',
    '0526716b-113d-4c15-b2c8-68e3c22b9f80': 'Authentication Policy Administrator',
    '892c5842-a9a6-463a-8041-72aa08ca3cf6': 'Cloud App Security Administrator',
    '74ef975b-6605-40af-a5d2-b9539d836353': 'Kaizala Administrator',
    '4ba39ca4-527c-499a-b93d-d9b492c50246': 'Partner Tier1 Support',
    'e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8': 'Partner Tier2 Support',
    '95e79109-95c0-4d8e-aee3-d01accf2d47b': 'Guest User',
    '2b499bcd-da44-4968-8aec-78e1674fa64d': 'Guest Inviter',
}


def _build_summary(cap: dict) -> list:
    """
    Return a list of (tag, text) tuples for insertion into a text widget.
    Tags: 'h1', 'h2', 'sep', 'label', 'value', 'dim', 'err', 'ok', 'warn'
    """
    xml_str = cap.get('decoded', '')
    if xml_str.startswith('[Decode error'):
        return [('err', xml_str)]

    out = []

    def row(tag, text):
        out.append((tag, text))

    def field(label: str, value: str, value_tag: str = 'value'):
        if value:
            row('label', f'  {label:<{_LW}}')
            row(value_tag, f'  {value}\n')

    def section(title: str):
        row('sep', '\n')
        row('h2', f'  {title}\n')
        row('sep', '  ' + '─' * 58 + '\n')

    # ── Header ───────────────────────────────────────────────────────────────
    row('sep', '  ' + '─' * 58 + '\n')
    row('h1', f'  {cap["type"]:<18}')
    row('dim', f'{cap["binding"]} binding   ')
    row('dim', f'{cap["ts"]}\n')
    row('dim', f'  {cap["host"]}\n')
    row('sep', '  ' + '─' * 58 + '\n\n')

    # ── Core ─────────────────────────────────────────────────────────────────
    field('Issuer',       _xml_text(xml_str, 'Issuer'))

    dest = (_xml_attr(xml_str, 'Response', 'Destination') or
            _xml_attr(xml_str, 'AuthnRequest', 'AssertionConsumerServiceURL') or
            _xml_attr(xml_str, 'AuthnRequest', 'Destination'))
    field('Destination',  dest)

    irt = _xml_attr(xml_str, 'Response', 'InResponseTo')
    field('InResponseTo', irt)

    # Status — extract correctly without greedy regex bug
    status_m = re.search(r'StatusCode[^>]+Value="([^"]+)"', xml_str)
    if status_m:
        raw_status = status_m.group(1)
        local_status = re.split(r'[:#]', raw_status)[-1]
        vtag = 'ok' if local_status.lower() == 'success' else 'warn'
        field('Status', local_status, vtag)

    # ── Identity ─────────────────────────────────────────────────────────────
    nameid = _xml_text(xml_str, 'NameID', 'NameIdentifier')
    if nameid:
        section('Identity')
        field('NameID',       nameid)
        fmt = (_xml_attr(xml_str, 'NameID', 'Format') or
               _xml_attr(xml_str, 'NameIdentifier', 'Format'))
        if fmt:
            field('Format', fmt.split(':')[-1])
        field('SessionIndex', _xml_attr(xml_str, 'AuthnStatement', 'SessionIndex'))
        authn = _xml_text(xml_str, 'AuthnContextClassRef')
        if authn:
            field('AuthnContext', authn.split(':')[-1])

    # ── Validity ─────────────────────────────────────────────────────────────
    nb  = _xml_attr(xml_str, 'Conditions', 'NotBefore')
    noa = _xml_attr(xml_str, 'Conditions', 'NotOnOrAfter')
    if nb or noa:
        section('Validity')
        field('NotBefore',    _fmt_time(nb))
        field('NotOnOrAfter', _fmt_time(noa))

    # ── Attributes ───────────────────────────────────────────────────────────
    # Collect ALL values per attribute (multi-value attributes like groups).
    attr_blocks = re.findall(
        r'<[^>]*:?Attribute\b[^>]+\bName="([^"]+)"[^>]*>(.*?)</[^>]*:?Attribute>',
        xml_str, re.DOTALL)
    if attr_blocks:
        section('Attributes')
        seen_short: dict = {}
        for uri, block in attr_blocks:
            short = _shorten_claim(uri)
            # If the short name already appeared, fall back to the full URI
            count = seen_short.get(short, 0)
            seen_short[short] = count + 1
            label = short if count == 0 else uri
            values = re.findall(
                r'<[^>]*:?AttributeValue[^>]*>(.*?)</[^>]*:?AttributeValue>',
                block, re.DOTALL)
            values = [v.strip() for v in values if v.strip()]
            if not values:
                continue
            is_wids = 'wids' in uri.lower()

            def _vdisp(v):
                if is_wids:
                    name = _WIDS_ROLES.get(v.lower())
                    if name:
                        return name, 'value'
                return v, ('guid' if _GUID_RE.match(v) else 'value')

            disp0, vtag0 = _vdisp(values[0])
            field(label, disp0, vtag0)
            for v in values[1:]:
                disp, vtag = _vdisp(v)
                row('label', f'  {"":<{_LW}}')
                row(vtag, f'  {disp}\n')

    # ── Request details ───────────────────────────────────────────────────────
    acs     = _xml_attr(xml_str, 'AuthnRequest', 'AssertionConsumerServiceURL')
    nid_pol = _xml_attr(xml_str, 'NameIDPolicy', 'Format')
    req_ctx = re.findall(
        r'<[^>]*:?RequestedAuthnContext.*?<[^>]*:?AuthnContextClassRef[^>]*>([^<]+)<',
        xml_str, re.DOTALL)
    if acs or nid_pol or req_ctx:
        section('Request Details')
        field('ACS URL',      acs)
        if nid_pol:
            field('NameID Policy', nid_pol.split(':')[-1])
        for c in req_ctx:
            field('AuthnContext', c.strip().split(':')[-1])

    return out


# ─── Certificate manager ──────────────────────────────────────────────────────

class CertManager:
    _CA_CN = 'SAML Interceptor Local CA'
    _DIR   = Path(os.environ.get('APPDATA', '.')) / 'SAMLInterceptor' / 'certs'

    def __init__(self):
        self._DIR.mkdir(parents=True, exist_ok=True)
        self._ca_key  = None
        self._ca_cert = None
        self._domain_cache: dict = {}
        self._lock = threading.Lock()
        self._load_or_create_ca()

    def _load_or_create_ca(self):
        kp, cp = self._DIR / 'ca.key', self._DIR / 'ca.crt'
        if kp.exists() and cp.exists():
            with open(kp, 'rb') as f:
                self._ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(cp, 'rb') as f:
                self._ca_cert = x509.load_pem_x509_certificate(f.read())
            return
        self._ca_key = rsa.generate_private_key(65537, 2048, default_backend())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self._CA_CN),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'SAMLInterceptor')])
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key()),
                           critical=False)
            .sign(self._ca_key, hashes.SHA256(), default_backend())
        )
        with open(kp, 'wb') as f:
            f.write(self._ca_key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        with open(cp, 'wb') as f:
            f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))

    @property
    def ca_cert_path(self) -> Path:
        return self._DIR / 'ca.crt'

    def leaf_cert_files(self, domain: str) -> tuple:
        with self._lock:
            if domain in self._domain_cache:
                return self._domain_cache[domain]
            tag = hashlib.md5(domain.encode()).hexdigest()[:10]
            cp, kp = self._DIR / f'{tag}.crt', self._DIR / f'{tag}.key'
            if not cp.exists():
                key = rsa.generate_private_key(65537, 2048, default_backend())
                cert = (
                    x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
                    .issuer_name(self._ca_cert.subject)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.now(timezone.utc))
                    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=397))
                    .add_extension(
                        x509.SubjectAlternativeName([x509.DNSName(domain),
                                                     x509.DNSName(f'*.{domain}')]),
                        critical=False)
                    .sign(self._ca_key, hashes.SHA256(), default_backend())
                )
                with open(kp, 'wb') as f:
                    f.write(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
                with open(cp, 'wb') as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
            self._domain_cache[domain] = (str(cp), str(kp))
            return self._domain_cache[domain]

    def is_ca_installed(self) -> bool:
        r = subprocess.run(['certutil', '-store', '-user', 'Root'],
                           capture_output=True, text=True)
        return self._CA_CN in r.stdout

    def install_ca(self) -> bool:
        r = subprocess.run(['certutil', '-addstore', '-user', 'Root', str(self.ca_cert_path)],
                           capture_output=True, text=True)
        return r.returncode == 0

    def uninstall_ca(self):
        subprocess.run(['certutil', '-delstore', '-user', 'Root', self._CA_CN],
                       capture_output=True, text=True)

    def regenerate_ca(self):
        """Wipe and recreate the CA cert. Caller is responsible for reinstalling."""
        self.uninstall_ca()
        with self._lock:
            self._domain_cache.clear()
        for p in self._DIR.glob('*.crt'):
            p.unlink(missing_ok=True)
        for p in self._DIR.glob('*.key'):
            p.unlink(missing_ok=True)
        self._ca_key  = None
        self._ca_cert = None
        self._load_or_create_ca()


# ─── Windows system proxy ─────────────────────────────────────────────────────

_INET_REG = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'


def _inet_refresh():
    try:
        inet = ctypes.windll.wininet
        inet.InternetSetOptionW(0, 39, 0, 0)
        inet.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        _log.debug("_inet_refresh failed", exc_info=True)


class SystemProxy:
    def __init__(self):
        self._orig_enable = None
        self._orig_server = ''

    def enable(self, host: str, port: int):
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_REG, 0, winreg.KEY_ALL_ACCESS)
        try:    self._orig_enable, _ = winreg.QueryValueEx(key, 'ProxyEnable')
        except FileNotFoundError: self._orig_enable = 0
        try:    self._orig_server, _ = winreg.QueryValueEx(key, 'ProxyServer')
        except FileNotFoundError: self._orig_server = ''
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, f'{host}:{port}')
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        _inet_refresh()

    def disable(self):
        if self._orig_enable is None:
            return
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_REG, 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, self._orig_enable)
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, self._orig_server)
        winreg.CloseKey(key)
        _inet_refresh()


# ─── Proxy server ─────────────────────────────────────────────────────────────

_BUF     = 65536
_TIMEOUT = 15


class SAMLProxy:
    def __init__(self, host: str, port: int, certs: CertManager, ev: queue.Queue):
        self._host  = host
        self._port  = port
        self._certs = certs
        self._ev    = ev
        self._sock  = None
        self._alive = False
        self._pool  = None
        self._srv_ctx: dict = {}
        self._srv_ctx_lock = threading.Lock()
        self._up_ctx = ssl.create_default_context()
        self._up_ctx.check_hostname = False
        self._up_ctx.verify_mode    = ssl.CERT_NONE

    def start(self):
        self._pool  = ThreadPoolExecutor(max_workers=64, thread_name_prefix='proxy')
        self._sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(256)
        self._alive = True
        threading.Thread(target=self._accept, daemon=True, name='proxy-accept').start()

    def stop(self):
        self._alive = False
        if self._sock:
            try: self._sock.close()
            except Exception: _log.debug("error closing proxy socket", exc_info=True)
            self._sock = None
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    def _accept(self):
        self._sock.settimeout(1.0)
        while self._alive:
            try:
                client, _ = self._sock.accept()
                self._pool.submit(self._handle, client)
            except socket.timeout:
                continue
            except Exception:
                _log.debug("accept loop error", exc_info=True)
                break

    def _handle(self, sock):
        try:
            sock.settimeout(_TIMEOUT)
            data = self._read_request(sock)
            if not data:
                return
            first = data.split(b'\r\n')[0].decode('utf-8', errors='replace')
            if first.startswith('CONNECT '):
                self._do_connect(sock, first)
            else:
                self._do_http(sock, data)
        except Exception:
            _log.debug("_handle error", exc_info=True)
        finally:
            try: sock.close()
            except Exception: _log.debug("error closing client socket", exc_info=True)

    def _do_http(self, sock, data: bytes):
        parts = data.split(b'\r\n')[0].decode('utf-8', errors='replace').split(' ')
        url   = parts[1] if len(parts) > 1 else '/'
        p     = urllib.parse.urlparse(url)
        self._forward(sock, data, p.hostname or 'localhost', p.port or 80, tls=False)

    def _do_connect(self, sock, first_line: str):
        target = first_line.split(' ')[1]
        host, _, port = target.rpartition(':')
        port = int(port) if port.isdigit() else 443
        _log.info(f"CONNECT {target}")
        sock.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        ctx = self._get_srv_ctx(host)
        try:
            tls = ctx.wrap_socket(sock, server_side=True)
        except ssl.SSLError:
            return
        try:
            data = self._read_request(tls)
            if data:
                self._forward(tls, data, host, port, tls=True)
        except Exception:
            _log.debug("_do_connect forward error", exc_info=True)
        finally:
            try: tls.close()
            except Exception: _log.debug("error closing TLS socket", exc_info=True)

    def _get_srv_ctx(self, domain: str) -> ssl.SSLContext:
        with self._srv_ctx_lock:
            if domain not in self._srv_ctx:
                cp, kp = self._certs.leaf_cert_files(domain)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cp, kp)
                self._srv_ctx[domain] = ctx
            return self._srv_ctx[domain]

    def _forward(self, client, data: bytes, host: str, port: int, tls: bool):
        hdr_end     = data.find(b'\r\n\r\n')
        headers_raw = data[:hdr_end] if hdr_end != -1 else data
        body        = data[hdr_end + 4:] if hdr_end != -1 else b''
        first       = headers_raw.split(b'\r\n')[0].decode('utf-8', errors='replace')
        parts       = first.split(' ')
        method      = parts[0] if parts else 'GET'
        path        = parts[1] if len(parts) > 1 else '/'
        pp          = urllib.parse.urlparse(path)

        if method == 'POST':
            _log.info(f"POST {host}{pp.path} body_len={len(body)}")

        findings = []
        if pp.query:
            findings += _find_saml(pp.query, post_body=False)
        if method == 'POST' and body:
            findings += _find_saml(body.decode('utf-8', errors='replace'), post_body=True)

        ts = datetime.now().strftime('%H:%M:%S')
        for f in findings:
            entry = {'ts': ts, 'host': host, 'path': pp.path, 'method': method, **f}
            _log.info(f"Captured {f['type']} {f['binding']} from {host}{pp.path}")
            self._ev.put(entry)

        try:
            up = socket.create_connection((host, port), timeout=_TIMEOUT)
        except Exception:
            _log.debug("upstream connection failed to %s:%s", host, port, exc_info=True)
            try: client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            except Exception: _log.debug("error sending 502", exc_info=True)
            return

        if tls:
            up = self._up_ctx.wrap_socket(up, server_hostname=host)

        if not tls and path.startswith('http'):
            rel  = pp.path + (f'?{pp.query}' if pp.query else '')
            data = data.replace(path.encode(), rel.encode(), 1)

        data = self._strip_hop_headers(data)
        try:
            up.sendall(data)
        except Exception:
            _log.debug("upstream send failed for %s", host, exc_info=True)
            up.close()
            return

        self._relay(client, up, host=host)
        try: up.close()
        except Exception: _log.debug("error closing upstream socket", exc_info=True)

    def _relay(self, a, b, host: str = ''):
        """Bidirectional relay. Scans client→upstream data for SAML on keep-alive tunnels."""
        a.settimeout(0); b.settimeout(0)
        buf = b''
        try:
            while True:
                r, _, e = select.select([a, b], [], [a, b], _TIMEOUT)
                if e or not r:
                    break
                for s in r:
                    dst = b if s is a else a
                    try:
                        chunk = s.recv(_BUF)
                        if not chunk:
                            return
                        if s is a and host:
                            buf += chunk
                            if len(buf) > 4 * 1024 * 1024:
                                buf = b''  # guard against memory runaway
                            else:
                                buf = self._relay_scan(buf, host)
                        dst.sendall(chunk)
                    except (BlockingIOError, ssl.SSLWantReadError):
                        pass
                    except Exception:
                        _log.debug("relay socket error", exc_info=True)
                        return
        except Exception:
            _log.debug("relay select error", exc_info=True)

    def _relay_scan(self, buf: bytes, host: str) -> bytes:
        """
        Scan client→upstream buffer for SAML POST bodies on keep-alive tunnels.
        Bails out immediately for anything that can't be a SAML assertion so that
        normal web traffic (downloads, API calls, video, etc.) has no overhead.
        """
        hdr_end = buf.find(b'\r\n\r\n')
        if hdr_end == -1:
            # Not enough data for headers yet; discard if suspiciously large
            return b'' if len(buf) > 8192 else buf

        lines = buf[:hdr_end].decode('utf-8', errors='replace').splitlines()
        first = lines[0] if lines else ''
        parts = first.split(' ', 2)
        method = parts[0] if parts else ''

        # SAMLResponse only arrives in POST bodies — skip everything else fast
        if method != 'POST':
            return b''

        ct = ''
        cl = 0
        for line in lines[1:]:
            ll = line.lower()
            if ll.startswith('content-type:'):
                ct = ll.split(':', 1)[1].strip()
            elif ll.startswith('content-length:'):
                try: cl = int(line.split(':', 1)[1].strip())
                except ValueError: pass

        # SAML is always form-encoded and never a large payload
        if 'x-www-form-urlencoded' not in ct or cl > 200_000:
            return b''

        body_start = hdr_end + 4
        if len(buf) < body_start + cl:
            return buf  # body not fully arrived yet; keep buffering

        body      = buf[body_start: body_start + cl]
        remainder = buf[body_start + cl:]

        try:
            path = parts[1] if len(parts) > 1 else '/'
            pp   = urllib.parse.urlparse(path)
            for f in _find_saml(body.decode('utf-8', errors='replace'), post_body=True):
                ts = datetime.now().strftime('%H:%M:%S')
                entry = {'ts': ts, 'host': host, 'path': pp.path, 'method': 'POST', **f}
                _log.info(f"Captured {f['type']} {f['binding']} from {host}{pp.path} (relay)")
                self._ev.put(entry)
        except Exception:
            _log.debug("_relay_scan SAML parse error", exc_info=True)

        if remainder:
            return self._relay_scan(remainder, host)
        return b''

    @staticmethod
    def _read_request(sock) -> bytes:
        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = sock.recv(_BUF)
            if not chunk:
                return buf
            buf += chunk
        hdr_end     = buf.index(b'\r\n\r\n')
        headers     = buf[:hdr_end].decode('utf-8', errors='replace')
        body        = buf[hdr_end + 4:]
        cl = 0
        for line in headers.splitlines():
            if line.lower().startswith('content-length:'):
                try: cl = int(line.split(':', 1)[1].strip())
                except ValueError: pass
        while len(body) < cl:
            chunk = sock.recv(_BUF)
            if not chunk:
                break
            body += chunk
        return buf[:hdr_end + 4] + body

    @staticmethod
    def _strip_hop_headers(data: bytes) -> bytes:
        hop = {b'proxy-connection', b'keep-alive', b'te',
               b'trailers', b'transfer-encoding', b'upgrade'}
        return b'\r\n'.join(
            l for l in data.split(b'\r\n')
            if l.split(b':')[0].strip().lower() not in hop)


# ─── Flow model ───────────────────────────────────────────────────────────────

class SAMLFlow:
    def __init__(self, num: int):
        self.num            = num
        self.request_id     = ''    # ID attr of the SAMLRequest
        self.email          = ''    # extracted from response
        self.idp_host       = ''
        self.started        = ''
        self.request: dict  = None
        self.response: dict = None
        # UI widgets (filled by _build_flow_tab)
        self.tab_frame      = None
        self.w_resp_sum     = None
        self.w_req_sum      = None
        self.w_resp_xml     = None
        self.w_req_xml      = None
        self.w_raw          = None
        self.w_waiting      = None  # unused; kept for compat


# ─── GUI palette ──────────────────────────────────────────────────────────────

_BG   = '#1e1e1e'
_BG2  = '#252526'
_BG3  = '#2d2d2d'
_FG   = '#d4d4d4'
_FG2  = '#858585'
_SEL  = '#094771'
_GRN  = '#0e7a0d'
_RED  = '#b71c1c'
_TEAL = '#4ec9b0'
_ERR  = '#f44747'
_YEL  = '#dcdcaa'
_BLU  = '#9cdcfe'
_GRY  = '#6a737d'
_OK   = '#4ec9b0'
_WARN = '#ce9178'
_FONT = ('Segoe UI', 9)
_MONO = ('Consolas', 10)

PROXY_HOST = '127.0.0.1'
PROXY_PORT = 8080


# ─── App ──────────────────────────────────────────────────────────────────────

class App:
    def __init__(self):
        self._q         = queue.Queue()
        self._certs     = CertManager()
        self._proxy     = SAMLProxy(PROXY_HOST, PROXY_PORT, self._certs, self._q)
        self._sysproxy  = SystemProxy()
        self._running       = False
        self._debug_on      = False
        self._warn_shown    = False
        self._flows: list[SAMLFlow] = []
        self._by_req_id: dict[str, SAMLFlow] = {}
        self._flow_num  = 0
        self._build_ui()
        self._root.after(200, self._update_ca_status)
        self._poll()

    # ── Build main window ─────────────────────────────────────────────────────

    def _build_ui(self):
        r = tk.Tk()
        r.title(f'SAML Interceptor  v{__version__}')
        r.geometry('1380x800')
        r.configure(bg=_BG)
        r.protocol('WM_DELETE_WINDOW', self._close)
        self._root = r

        s = ttk.Style()
        s.theme_use('clam')
        s.configure('TFrame',           background=_BG)
        s.configure('TLabel',           background=_BG, foreground=_FG)
        s.configure('TPanedwindow',     background=_BG)
        s.configure('TNotebook',        background=_BG2, tabmargins=[0, 2, 0, 0])
        s.configure('TNotebook.Tab',    background=_BG3, foreground=_FG2,
                    padding=[14, 6], font=('Segoe UI', 9))
        s.map('TNotebook.Tab',          background=[('selected', _BG)],
                                        foreground=[('selected', _FG)])
        # Sub-notebook tabs slightly smaller
        s.configure('Sub.TNotebook',        background=_BG2, tabmargins=[0, 1, 0, 0])
        s.configure('Sub.TNotebook.Tab',    background=_BG3, foreground=_FG2,
                    padding=[10, 4], font=('Segoe UI', 8))
        s.map('Sub.TNotebook.Tab',          background=[('selected', _BG2)],
                                            foreground=[('selected', _FG)])

        # ── Toolbar ───────────────────────────────────────────────────────
        bar = tk.Frame(r, bg=_BG3, height=50)
        bar.pack(fill='x')
        bar.pack_propagate(False)

        self._go_btn = tk.Button(bar, text='▶  Start Intercepting',
            command=self._toggle, bg=_GRN, fg='white',
            font=('Segoe UI', 10, 'bold'), relief='flat', padx=14, pady=9, cursor='hand2')
        self._go_btn.pack(side='left', padx=10, pady=6)

        _btn = lambda text, cmd: tk.Button(bar, text=text, command=cmd,
            bg='#3c3c3c', fg=_FG, font=_FONT, relief='flat',
            padx=10, pady=9, cursor='hand2')

        _btn('Install CA', self._install_ca).pack(side='left', padx=3, pady=6)
        _btn('Remove CA',  self._remove_ca ).pack(side='left', padx=3, pady=6)
        _btn('Regen CA',   self._regen_ca  ).pack(side='left', padx=3, pady=6)
        _btn('View Cert',  self._view_cert ).pack(side='left', padx=3, pady=6)
        _btn('Clear',      self._clear     ).pack(side='left', padx=3, pady=6)

        self._status = tk.Label(bar, text='● Stopped', bg=_BG3, fg=_ERR, font=_FONT)
        self._status.pack(side='left', padx=16)

        self._ca_status = tk.Label(bar, text='CA …', bg=_BG3, fg=_FG2, font=_FONT)
        self._ca_status.pack(side='left', padx=6)

        tk.Label(bar, text=f'Proxy  {PROXY_HOST}:{PROXY_PORT}',
                 bg=_BG3, fg=_FG2, font=('Consolas', 9)).pack(side='right', padx=14)

        tk.Button(bar, text='Open Log', command=self._open_log,
                  bg='#3c3c3c', fg=_FG, font=_FONT, relief='flat',
                  padx=10, pady=9, cursor='hand2'
                  ).pack(side='right', padx=3, pady=6)

        self._debug_btn = tk.Button(bar, text='Debug: Off', command=self._toggle_debug,
                  bg='#3c3c3c', fg=_FG2, font=_FONT, relief='flat',
                  padx=10, pady=9, cursor='hand2')
        self._debug_btn.pack(side='right', padx=3, pady=6)

        # ── Flow notebook ────────────────────────────────────────────────
        self._nb = ttk.Notebook(r)
        self._nb.pack(fill='both', expand=True)

        # Empty-state frame shown when no flows exist
        self._empty = tk.Frame(self._nb, bg=_BG)
        self._nb.add(self._empty, text='  No flows yet  ')
        tk.Label(self._empty,
                 text='Start intercepting, then trigger a SAML login.\n'
                      'Each login attempt will appear as a tab named by email address.',
                 bg=_BG, fg=_FG2, font=('Segoe UI', 11), justify='center'
                 ).place(relx=0.5, rely=0.5, anchor='center')

    # ── Flow tab builder ──────────────────────────────────────────────────────

    def _build_flow_tab(self, flow: SAMLFlow):
        frame = tk.Frame(self._nb, bg=_BG)

        # Remove empty-state tab if this is our first flow
        if len(self._flows) == 1 and self._empty.winfo_ismapped():
            self._nb.forget(self._empty)

        self._nb.add(frame, text=f'  Flow {flow.num}  ')
        self._nb.select(frame)
        flow.tab_frame = frame

        sub = ttk.Notebook(frame, style='Sub.TNotebook')
        sub.pack(fill='both', expand=True)

        flow.w_resp_sum = self._make_text_tab(sub, 'Response')
        flow.w_req_sum  = self._make_text_tab(sub, 'Request')
        flow.w_resp_xml = self._make_text_tab(sub, 'Resp. XML')
        flow.w_req_xml  = self._make_text_tab(sub, 'Req. XML')
        flow.w_raw      = self._make_text_tab(sub, 'Raw')

        # Show waiting placeholder as text (avoids z-order issues with a floating Label)
        flow.w_resp_sum.configure(state='normal')
        flow.w_resp_sum.insert('end', '\n\n\n  Waiting for SAMLResponse…', 'dim')
        flow.w_resp_sum.configure(state='disabled')

    def _make_text_tab(self, nb, title: str) -> scrolledtext.ScrolledText:
        frame = tk.Frame(nb, bg=_BG)
        nb.add(frame, text=f' {title} ')
        t = scrolledtext.ScrolledText(frame, bg=_BG, fg=_FG, font=_MONO,
            wrap='none', insertbackground='white', selectbackground=_SEL,
            relief='flat', borderwidth=0, state='disabled')
        t.pack(fill='both', expand=True)
        # Text tags
        t.tag_configure('h1',    foreground=_BLU,  font=('Consolas', 11, 'bold'))
        t.tag_configure('h2',    foreground=_BLU,  font=('Consolas', 10, 'bold'))
        t.tag_configure('sep',   foreground=_GRY)
        t.tag_configure('dim',   foreground=_FG2)
        t.tag_configure('label', foreground=_YEL)
        t.tag_configure('value', foreground=_FG)
        t.tag_configure('ok',    foreground=_OK)
        t.tag_configure('warn',  foreground=_WARN)
        t.tag_configure('err',   foreground=_ERR)
        t.tag_configure('blob',  foreground='#6a9955', font=('Consolas', 9))
        t.tag_configure('xmltag',foreground='#569cd6')
        return t

    # ── Rendering ─────────────────────────────────────────────────────────────

    def _render_summary(self, cap: dict, widget: scrolledtext.ScrolledText):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        for tag, text in _build_summary(cap):
            if tag == 'guid':
                guid = text.strip()
                url  = (f'https://portal.azure.com/#view/Microsoft_AAD_IAM/'
                        f'GroupDetailsMenuBlade/~/Overview/groupId/{guid}')
                utag = f'guid_{guid}'
                widget.insert('end', text, (utag,))
                widget.tag_configure(utag, foreground=_TEAL,
                                     underline=True, font=_FONT)
                widget.tag_bind(utag, '<Button-1>',
                                lambda e, u=url: webbrowser.open(u))
                widget.tag_bind(utag, '<Enter>',
                                lambda e: widget.configure(cursor='hand2'))
                widget.tag_bind(utag, '<Leave>',
                                lambda e: widget.configure(cursor=''))
            else:
                widget.insert('end', text, tag)
        widget.configure(state='disabled')

    def _render_xml(self, decoded: str, widget: scrolledtext.ScrolledText):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        if decoded.startswith('[Decode error'):
            widget.insert('1.0', decoded, 'err')
            widget.configure(state='disabled')
            return
        cleaned = _clean_xml(decoded)
        for line in cleaned.splitlines(keepends=True):
            if '[base64 chars]' in line:
                widget.insert('end', line, 'blob')
            else:
                m = re.match(r'(\s*)(<[^>]+>)(.*)', line.rstrip('\n'))
                if m:
                    widget.insert('end', m.group(1))
                    widget.insert('end', m.group(2), 'xmltag')
                    widget.insert('end', m.group(3) + '\n', 'value')
                else:
                    widget.insert('end', line, 'value')
        widget.configure(state='disabled')

    def _render_raw(self, flow: SAMLFlow, widget: scrolledtext.ScrolledText):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        if flow.request:
            widget.insert('end', '── SAMLRequest ──────────────────────────────────────────\n', 'sep')
            widget.insert('end', flow.request.get('raw', ''), 'value')
            widget.insert('end', '\n\n')
        if flow.response:
            widget.insert('end', '── SAMLResponse ─────────────────────────────────────────\n', 'sep')
            widget.insert('end', flow.response.get('raw', ''), 'value')
        widget.configure(state='disabled')

    # ── Flow management ───────────────────────────────────────────────────────

    def _new_flow(self, cap: dict, request_id: str) -> SAMLFlow:
        self._flow_num += 1
        flow = SAMLFlow(self._flow_num)
        flow.request_id = request_id
        flow.idp_host   = cap.get('host', '')
        flow.started    = cap.get('ts', '')
        self._flows.append(flow)
        if request_id:
            self._by_req_id[request_id] = flow
        self._build_flow_tab(flow)
        return flow

    def _update_tab_title(self, flow: SAMLFlow):
        title = flow.email if flow.email else f'Flow {flow.num}'
        self._nb.tab(flow.tab_frame, text=f'  {title}  ')

    def _add_capture(self, cap: dict):
        decoded = cap.get('decoded', '')
        kind    = cap['type']

        if kind == 'SAMLRequest':
            req_id = _extract_saml_id(decoded)
            _log.debug(f"SAMLRequest req_id={req_id!r} host={cap.get('host')}")
            flow   = self._new_flow(cap, req_id)
            flow.request = cap
            self._render_xml(decoded, flow.w_req_xml)
            # Request summary
            self._render_summary(cap, flow.w_req_sum)
            self._render_raw(flow, flow.w_raw)

        elif kind == 'SAMLResponse':
            irt  = _extract_in_response_to(decoded)
            flow = self._by_req_id.get(irt) if irt else None
            _log.debug(f"SAMLResponse irt={irt!r} -> {'Flow '+str(flow.num) if flow else 'no match'}")
            if flow is None:
                # Fallback: if exactly one request flow has no response yet, use it.
                # Handles keep-alive tunnels where the SAMLRequest ID lookup failed.
                waiting = [f for f in self._flows if f.response is None]
                if len(waiting) == 1:
                    flow = waiting[0]
                    _log.debug(f"SAMLResponse fallback -> Flow {flow.num} (stored_id={flow.request_id!r})")
            if flow is None:
                flow = self._new_flow(cap, '')
            flow.response = cap
            flow.email    = _extract_email(decoded)
            self._update_tab_title(flow)
            self._render_summary(cap, flow.w_resp_sum)
            self._render_xml(decoded, flow.w_resp_xml)
            self._render_raw(flow, flow.w_raw)

    # ── Poll queue ────────────────────────────────────────────────────────────

    def _poll(self):
        try:
            while True:
                cap = self._q.get_nowait()
                try:
                    _log.debug(f"Processing {cap.get('type')} from {cap.get('host')}")
                    self._add_capture(cap)
                except Exception:
                    _log.error("_add_capture failed", exc_info=True)
        except queue.Empty:
            pass
        self._root.after(100, self._poll)

    # ── Controls ──────────────────────────────────────────────────────────────

    def _toggle(self):
        self._stop() if self._running else self._start()

    def _start(self):
        if not self._warn_shown:
            ok = messagebox.askokcancel(
                'Start Intercepting',
                'SAML Interceptor routes all system HTTPS traffic through a local proxy.\n\n'
                '⚠  Other web traffic (browser tabs, apps, background services) may '
                'fail or behave unexpectedly while interception is active.\n\n'
                'Stop intercepting when you are done to restore normal traffic.\n\n'
                'Continue?',
                icon='warning',
            )
            if not ok:
                return
            self._warn_shown = True
        try:
            self._proxy.start()
            self._sysproxy.enable(PROXY_HOST, PROXY_PORT)
            self._running = True
            self._go_btn.configure(text='■  Stop Intercepting', bg=_RED)
            self._status.configure(text='● Intercepting', fg=_TEAL)
        except Exception as exc:
            messagebox.showerror('Error', f'Could not start proxy:\n{exc}')

    def _stop(self):
        self._sysproxy.disable()
        self._proxy.stop()
        self._running = False
        self._go_btn.configure(text='▶  Start Intercepting', bg=_GRN)
        self._status.configure(text='● Stopped', fg=_ERR)

    def _update_ca_status(self):
        self._ca_status.configure(text='CA: Checking…', fg=_FG2)
        def _check():
            installed = self._certs.is_ca_installed()
            self._root.after(0, lambda: self._ca_status.configure(
                text='CA ✓ Installed' if installed else 'CA ✗ Not installed',
                fg=_TEAL if installed else _ERR,
            ))
        threading.Thread(target=_check, daemon=True).start()

    def _install_ca(self):
        ok = self._certs.install_ca()
        self._update_ca_status()
        if ok:
            messagebox.showinfo('CA Installed',
                f'CA installed in your Trusted Root store.\n'
                f'HTTPS SAML flows will now be decoded.\n\n'
                f'Path: {self._certs.ca_cert_path}')
        else:
            messagebox.showwarning('Manual Install Needed',
                f'certutil failed.  Install manually:\n\n{self._certs.ca_cert_path}\n\n'
                f'Double-click → Install Certificate → Current User\n'
                f'→ Trusted Root Certification Authorities')

    def _remove_ca(self):
        self._certs.uninstall_ca()
        self._update_ca_status()
        messagebox.showinfo('CA Removed', 'Local CA removed from Trusted Root store.')

    def _view_cert(self):
        p = self._certs.ca_cert_path
        if p.exists():
            os.startfile(str(p))
        else:
            messagebox.showwarning('No Certificate', 'CA certificate file not found.')

    def _regen_ca(self):
        if not messagebox.askyesno('Regenerate CA',
                'This will delete the current CA certificate and generate a new one.\n\n'
                'Any previously installed CA cert will stop being trusted — you must '
                'reinstall it after regenerating.\n\n'
                'Active HTTPS interception will break until the new cert is installed.\n\n'
                'Continue?'):
            return
        self._certs.regenerate_ca()
        ok = self._certs.install_ca()
        self._update_ca_status()
        if ok:
            messagebox.showinfo('CA Regenerated',
                'New CA certificate generated and installed in your Trusted Root store.\n\n'
                f'Path: {self._certs.ca_cert_path}')
        else:
            messagebox.showwarning('CA Regenerated — Install Required',
                f'New CA generated but auto-install failed.\n\n'
                f'Install manually:\n{self._certs.ca_cert_path}\n\n'
                f'Double-click → Install Certificate → Current User\n'
                f'→ Trusted Root Certification Authorities')

    def _toggle_debug(self):
        self._debug_on = not self._debug_on
        level = logging.DEBUG if self._debug_on else logging.WARNING
        _log.setLevel(level)
        _log_handler.setLevel(level)
        if self._debug_on:
            self._debug_btn.configure(text='Debug: On', bg=_TEAL, fg='black')
        else:
            self._debug_btn.configure(text='Debug: Off', bg='#3c3c3c', fg=_FG2)

    def _open_log(self):
        log_path = _LOG_DIR / 'debug.log'
        if log_path.exists():
            os.startfile(str(log_path))
        else:
            messagebox.showinfo('No Log', f'Debug log not yet created.\n{log_path}')

    def _clear(self):
        for flow in self._flows:
            try: self._nb.forget(flow.tab_frame)
            except Exception: _log.debug("error removing flow tab", exc_info=True)
        self._flows.clear()
        self._by_req_id.clear()
        self._flow_num = 0
        if not self._nb.tabs():
            self._nb.add(self._empty, text='  No flows yet  ')

    def _close(self):
        if self._running:
            self._stop()
        self._root.destroy()
        os._exit(0)

    def run(self):
        self._root.mainloop()


# ─── Entry ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if not CRYPTO_OK:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror('Missing dependency',
            'The cryptography package is required:\n\n    pip install cryptography\n\n'
            'Then re-run this script.')
        sys.exit(1)
    App().run()

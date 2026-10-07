"""Tests for saml_interceptor.

Run from the repo root:  python -m unittest discover -s tests

The registry is always faked. DPAPI is real on Windows and faked elsewhere, so the
rest of the suite can also run on a non-Windows development machine.
"""
import base64
import hashlib
import json
import os
import queue
import re
import socket
import ssl
import sys
import tempfile
import threading
import types
import unittest
import urllib.parse
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

# The module derives its data directory from APPDATA at import time.
_TMP = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
os.environ['APPDATA'] = _TMP.name
if sys.platform != 'win32':
    sys.modules.setdefault('winreg', types.ModuleType('winreg'))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import saml_interceptor as si  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

if sys.platform != 'win32':
    def _fake_dpapi(data: bytes, protect: bool) -> bytes:
        flip = lambda b: bytes(c ^ 0x5A for c in b)
        return b'FAKE' + flip(data) if protect else flip(data[4:])
    si._dpapi = _fake_dpapi


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _deflate(data: bytes) -> str:
    return _b64(zlib.compress(data)[2:-4])


def _clear_cert_dir():
    si.CertManager._DIR.mkdir(parents=True, exist_ok=True)
    for p in si.CertManager._DIR.iterdir():
        p.unlink()


class DecodeTests(unittest.TestCase):
    def test_post_and_redirect_bindings_decode(self):
        self.assertIn('<a', si._decode_saml_value(_b64(b'<a ID="1"/>'), False))
        self.assertIn('<a', si._decode_saml_value(_deflate(b'<a ID="1"/>'), True))

    def test_dtd_is_rejected(self):
        bomb = b'<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><l>&b;</l>'
        self.assertTrue(si._decode_saml_value(_b64(bomb), False).startswith('[Decode error: DTD'))

    def test_utf16_is_rejected(self):
        doc = '<!DOCTYPE a><a/>'.encode('utf-16')
        self.assertTrue(si._decode_saml_value(_b64(doc), False).startswith('[Decode error'))

    def test_deflate_bomb_is_rejected(self):
        payload = _deflate(b'<a>' + b'A' * (20 * 1024 * 1024) + b'</a>')
        self.assertTrue(si._decode_saml_value(payload, True)
                        .startswith('[Decode error: payload too large'))

    def test_oversize_value_is_rejected_before_decoding(self):
        self.assertEqual(si._decode_saml_value('A' * (2 * si._MAX_SAML + 1), False),
                         '[Decode error: payload too large]')


class HeaderFilterTests(unittest.TestCase):
    REQ = (b'POST /x HTTP/1.1\r\nHost: a\r\nProxy-Connection: keep-alive\r\n'
           b'Transfer-Encoding: chunked\r\n\r\nline1\r\nte: body\r\nupgrade: body\r\n')

    def test_body_is_left_alone(self):
        out = si.SAMLProxy._strip_hop_headers(self.REQ)
        self.assertTrue(out.endswith(b'\r\n\r\nline1\r\nte: body\r\nupgrade: body\r\n'))

    def test_hop_headers_removed_but_transfer_encoding_kept(self):
        out = si.SAMLProxy._strip_hop_headers(self.REQ)
        self.assertNotIn(b'Proxy-Connection', out)
        self.assertIn(b'Transfer-Encoding: chunked', out)


class ReadRequestTests(unittest.TestCase):
    def test_large_body_is_not_fully_buffered(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        big = b'x' * (4 * si._MAX_BODY)
        head = b'POST / HTTP/1.1\r\nContent-Length: %d\r\n\r\n' % len(big)

        def send():
            try:
                a.sendall(head + big)
            except OSError:
                pass            # the reader stops early by design

        threading.Thread(target=send, daemon=True).start()
        got = si.SAMLProxy._read_request(b)
        self.assertLess(len(got), si._MAX_BODY + 2 * si._BUF)


class EmitTests(unittest.TestCase):
    def test_capture_is_parsed_before_it_reaches_the_ui_queue(self):
        proxy = si.SAMLProxy.__new__(si.SAMLProxy)
        proxy._ev = queue.Queue()
        decoded = ('<samlp:Response InResponseTo="_r1"><saml:Attribute Name="email">'
                   '<saml:AttributeValue>u@example.com</saml:AttributeValue>'
                   '</saml:Attribute></samlp:Response>')
        proxy._emit({'ts': 't', 'host': 'h', 'path': '/', 'method': 'POST',
                     'type': 'SAMLResponse', 'binding': 'POST', 'raw': '', 'decoded': decoded})
        cap = proxy._ev.get_nowait()
        self.assertEqual((cap['irt'], cap['email']), ('_r1', 'u@example.com'))
        self.assertTrue(cap['summary'])
        self.assertIn('clean_xml', cap)


class SystemProxyTests(unittest.TestCase):
    def setUp(self):
        self.reg = {'ProxyEnable': 1, 'ProxyServer': 'corp-proxy:3128'}
        reg = self.reg

        class Key:
            def __enter__(self): return self
            def __exit__(self, *exc): return False

        def query(key, name):
            if name not in reg:
                raise FileNotFoundError(name)
            return reg[name], 0

        fake = types.SimpleNamespace(
            HKEY_CURRENT_USER=1, KEY_QUERY_VALUE=1, KEY_SET_VALUE=2, REG_SZ=1, REG_DWORD=4,
            OpenKey=lambda *a: Key(), QueryValueEx=query,
            SetValueEx=lambda key, name, res, typ, val: reg.__setitem__(name, val))
        for target, value in (('winreg', fake), ('_inet_refresh', lambda: None)):
            patcher = mock.patch.object(si, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.state = si.SystemProxy._STATE
        self.state.unlink(missing_ok=True)

    def test_enable_then_disable_round_trips(self):
        sp = si.SystemProxy()
        sp.enable('127.0.0.1', 8080)
        self.assertEqual(self.reg, {'ProxyEnable': 1, 'ProxyServer': '127.0.0.1:8080'})
        self.assertEqual(json.loads(self.state.read_text()),
                         {'enable': 1, 'server': 'corp-proxy:3128'})
        sp.disable()
        self.assertEqual(self.reg, {'ProxyEnable': 1, 'ProxyServer': 'corp-proxy:3128'})
        self.assertFalse(self.state.exists())

    def test_recover_after_a_crash(self):
        si.SystemProxy().enable('127.0.0.1', 8080)        # ...and the process dies here
        self.assertTrue(si.SystemProxy().recover())
        self.assertEqual(self.reg, {'ProxyEnable': 1, 'ProxyServer': 'corp-proxy:3128'})
        self.assertFalse(self.state.exists())

    def test_recover_is_a_no_op_after_a_clean_exit(self):
        self.assertFalse(si.SystemProxy().recover())

    def test_never_restores_to_its_own_address(self):
        self.reg.update(ProxyEnable=1, ProxyServer='127.0.0.1:8080')
        sp = si.SystemProxy()
        sp.enable('127.0.0.1', 8080)
        sp.disable()
        self.assertEqual(self.reg, {'ProxyEnable': 0, 'ProxyServer': ''})

    def test_corrupt_restore_file_switches_the_proxy_off(self):
        self.state.write_text('{not json')
        self.reg.update(ProxyEnable=1, ProxyServer='127.0.0.1:8080')
        self.assertTrue(si.SystemProxy().recover())
        self.assertEqual(self.reg['ProxyEnable'], 0)
        self.assertFalse(self.state.exists())


@unittest.skipUnless(sys.platform == 'win32', 'DPAPI exists only on Windows')
class DpapiTests(unittest.TestCase):
    def test_round_trip_and_ciphertext_differs(self):
        secret = b'-----BEGIN PRIVATE KEY-----\nnot really\n-----END PRIVATE KEY-----\n'
        blob = si._dpapi(secret, protect=True)
        self.assertNotIn(b'PRIVATE KEY', blob)
        self.assertEqual(si._dpapi(blob, protect=False), secret)

    def test_garbage_does_not_decrypt(self):
        with self.assertRaises(OSError):
            si._dpapi(b'not a dpapi blob', protect=False)


class CertManagerTests(unittest.TestCase):
    def setUp(self):
        _clear_cert_dir()
        self.dir = si.CertManager._DIR

    def _plaintext_keys(self):
        return [p.name for p in self.dir.iterdir() if b'PRIVATE KEY' in p.read_bytes()]

    def test_no_private_key_is_stored_in_plaintext(self):
        certs = si.CertManager()
        certs.leaf_context('example.com')
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ['ca.crt', 'ca.key.dpapi'])
        self.assertEqual(self._plaintext_keys(), [])

    def test_ca_survives_a_restart(self):
        self.assertEqual(si.CertManager()._ca_cert, si.CertManager()._ca_cert)

    def test_legacy_plaintext_layout_is_migrated(self):
        first = si.CertManager()
        pem = first._ca_key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption())
        (self.dir / 'ca.key.dpapi').unlink()
        (self.dir / 'ca.key').write_bytes(pem)
        (self.dir / '0123456789.key').write_bytes(pem)
        (self.dir / '0123456789.crt').write_bytes(b'old leaf')
        upgraded = si.CertManager()
        self.assertEqual(upgraded._ca_cert, first._ca_cert)      # no reinstall needed
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ['ca.crt', 'ca.key.dpapi'])
        self.assertEqual(self._plaintext_keys(), [])

    def test_undecryptable_key_yields_a_fresh_ca(self):
        first = si.CertManager()
        (self.dir / 'ca.key.dpapi').write_bytes(b'garbage')
        self.assertNotEqual(si.CertManager()._ca_cert, first._ca_cert)

    def test_leaf_contexts_cover_ips_and_long_names_and_are_cached(self):
        certs = si.CertManager()
        for host in ('192.168.1.10', '[::1]', 'a' * 70 + '.example.com'):
            self.assertIsInstance(certs.leaf_context(host), ssl.SSLContext)
        self.assertIs(certs.leaf_context('example.com'), certs.leaf_context('example.com'))

    def test_regenerate_replaces_the_ca_and_drops_cached_leaves(self):
        certs = si.CertManager()
        old = certs._ca_cert
        certs.leaf_context('example.com')
        with mock.patch.object(certs, 'uninstall_ca'):
            certs.regenerate_ca()
        self.assertNotEqual(certs._ca_cert, old)
        self.assertEqual(certs._ctx_cache, {})


class ProxyEndToEndTests(unittest.TestCase):
    """A browser-like client talks through the proxy to a local TLS server."""

    @classmethod
    def setUpClass(cls):
        _clear_cert_dir()
        cls.certs = si.CertManager()
        key  = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now  = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .sign(key, hashes.SHA256()))
        cls.upstream_pem = Path(_TMP.name) / 'upstream.pem'
        cls.upstream_pem.write_bytes(
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption())
            + cert.public_bytes(serialization.Encoding.PEM))

    def setUp(self):
        self.requests_seen = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.upstream_pem)
        self.server = socket.socket()
        self.server.bind(('127.0.0.1', 0))
        self.server.listen(5)
        self.addCleanup(self.server.close)
        threading.Thread(target=self._serve, args=(ctx,), daemon=True).start()

        self.captures = queue.Queue()
        self.proxy = si.SAMLProxy('127.0.0.1', 0, self.certs, self.captures)
        self.proxy.start()
        self.proxy_port = self.proxy._sock.getsockname()[1]
        self.addCleanup(self.proxy.stop)

    def _serve(self, ctx):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                buf = tls.recv(65536)
                length = re.search(rb'Content-Length: (\d+)', buf)
                if length:
                    need = buf.index(b'\r\n\r\n') + 4 + int(length.group(1))
                    while len(buf) < need:
                        buf += tls.recv(65536)
                self.requests_seen.append(buf)
                body = hashlib.sha256(buf.split(b'\r\n\r\n', 1)[1]).hexdigest().encode()
                tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n'
                            b'Connection: close\r\n\r\n%s' % (len(body), body))
                tls.close()
            except (OSError, ValueError):
                continue        # the proxy refused our certificate

    def _through_proxy(self, request: bytes) -> bytes:
        port = self.server.getsockname()[1]
        raw = socket.create_connection(('127.0.0.1', self.proxy_port), timeout=20)
        self.addCleanup(raw.close)
        raw.sendall(f'CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
        self.assertIn(b'200', raw.recv(4096))
        client = ssl.create_default_context(cafile=str(self.certs.ca_cert_path))
        tls = client.wrap_socket(raw, server_hostname='localhost')   # trusts only the local CA
        self.addCleanup(tls.close)
        tls.sendall(request)
        response = b''
        try:
            while chunk := tls.recv(65536):
                response += chunk
        except OSError:
            pass
        return response

    def _saml_get(self) -> bytes:
        saml = _deflate(b'<samlp:AuthnRequest xmlns:samlp="x" ID="_abc123"/>')
        return (f'GET /sso?SAMLRequest={urllib.parse.quote(saml)} HTTP/1.1\r\n'
                f'Host: localhost\r\n\r\n').encode()

    def test_untrusted_upstream_is_refused(self):
        response = self._through_proxy(self._saml_get())
        self.assertTrue(response.startswith(b'HTTP/1.1 502'), response[:80])
        self.assertIn(b'could not be verified', response)
        self.assertEqual(self.requests_seen, [])      # nothing was sent to the impostor

    def test_trusted_upstream_is_relayed_and_saml_is_captured(self):
        self.proxy._up_ctx.load_verify_locations(self.upstream_pem)
        response = self._through_proxy(self._saml_get())
        self.assertTrue(response.startswith(b'HTTP/1.1 200'), response[:80])
        cap = self.captures.get(timeout=5)
        self.assertEqual((cap['type'], cap['binding'], cap['saml_id']),
                         ('SAMLRequest', 'Redirect', '_abc123'))

    def test_large_upload_arrives_intact(self):
        self.proxy._up_ctx.load_verify_locations(self.upstream_pem)
        payload = os.urandom(3 * si._MAX_BODY)
        head = (f'POST /upload HTTP/1.1\r\nHost: localhost\r\n'
                f'Content-Type: application/octet-stream\r\n'
                f'Content-Length: {len(payload)}\r\n\r\n').encode()
        response = self._through_proxy(head + payload)
        self.assertTrue(response.endswith(hashlib.sha256(payload).hexdigest().encode()),
                        response[:80])


if __name__ == '__main__':
    unittest.main()

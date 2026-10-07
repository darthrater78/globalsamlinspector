"""Capture the README screenshots from seeded sample data.

    python scripts/screenshots.py [output dir]      (default: docs/screenshots)

Nothing real is touched: the app runs against a temporary data directory, the
proxy is never started, the system proxy setting is never changed and no
certificate is installed. All names and identifiers in the sample are made up.

Run it on Windows for the images used in the README. It also runs on other
platforms (with the registry and DPAPI stubbed) for a quick layout check.
"""
import os
import sys
import tempfile
import base64
import types
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else REPO / 'docs' / 'screenshots')
SIZE = (1380, 800)     # the app's default window size at 100% scaling

_TMP = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
os.environ['APPDATA'] = _TMP.name          # the app derives its data directory from this
if sys.platform != 'win32':
    sys.modules.setdefault('winreg', types.ModuleType('winreg'))
sys.path.insert(0, str(REPO))
sys.dont_write_bytecode = True

import saml_interceptor as si  # noqa: E402
from PIL import ImageGrab      # noqa: E402

if sys.platform != 'win32':
    si._dpapi = lambda data, protect: data
si.__version__ = (REPO / 'VERSION').read_text(encoding='utf-8').strip()
si.CertManager.is_ca_installed = lambda self: True     # show the usual, set-up state
si.SystemProxy.recover = lambda self: False

REQUEST = (
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{id}" Version="2.0" '
    'IssueInstant="2026-10-07T08:14:02Z" Destination="https://login.example-idp.com/saml2" '
    'AssertionConsumerServiceURL="https://app.example.com/saml/acs">'
    '<saml:Issuer>https://app.example.com</saml:Issuer>'
    '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>'
    '</samlp:AuthnRequest>')

_CLAIMS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims'
_MS = 'http://schemas.microsoft.com'
RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
    'Destination="https://app.example.com/saml/acs" InResponseTo="_req1">'
    '<saml:Issuer>https://sts.example-idp.com/11111111-2222-3333-4444-555555555555/</saml:Issuer>'
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
    '</samlp:Status><saml:Assertion ID="_assert1" Version="2.0">'
    '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>'
    + 'c2FtcGxlLXNpZ25hdHVyZS1ub3QtcmVhbC0' * 12 +
    '</ds:SignatureValue></ds:Signature>'
    '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
    'alex.rivera@example.com</saml:NameID></saml:Subject>'
    '<saml:Conditions NotBefore="2026-10-07T08:09:09Z" NotOnOrAfter="2026-10-07T09:14:09Z"/>'
    '<saml:AuthnStatement AuthnInstant="2026-10-07T08:14:07Z" SessionIndex="_session-7f3a">'
    '<saml:AuthnContext><saml:AuthnContextClassRef>'
    'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
    '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
    '<saml:AttributeStatement>'
    f'<saml:Attribute Name="{_CLAIMS}/emailaddress">'
    '<saml:AttributeValue>alex.rivera@example.com</saml:AttributeValue></saml:Attribute>'
    f'<saml:Attribute Name="{_CLAIMS}/givenname">'
    '<saml:AttributeValue>Alex</saml:AttributeValue></saml:Attribute>'
    f'<saml:Attribute Name="{_CLAIMS}/surname">'
    '<saml:AttributeValue>Rivera</saml:AttributeValue></saml:Attribute>'
    f'<saml:Attribute Name="{_MS}/ws/2008/06/identity/claims/groups">'
    '<saml:AttributeValue>0a1b2c3d-1111-2222-3333-444455556666</saml:AttributeValue>'
    '<saml:AttributeValue>9f8e7d6c-aaaa-bbbb-cccc-ddddeeeeffff</saml:AttributeValue>'
    '</saml:Attribute>'
    f'<saml:Attribute Name="{_MS}/ws/2008/06/identity/claims/wids">'
    '<saml:AttributeValue>b79fbf4d-3ef9-4689-8143-76b194e85509</saml:AttributeValue>'
    '<saml:AttributeValue>f2ef992c-3afb-46b9-b7cf-a126ee74c451</saml:AttributeValue>'
    '</saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>')


def _capture(kind: str, xml_text: str, host: str, ts: str, binding: str) -> dict:
    raw = base64.b64encode(xml_text.encode()).decode()
    return {'ts': ts, 'host': host, 'path': '/saml', 'method': 'POST' if binding == 'POST' else 'GET',
            'type': kind, 'binding': binding, 'raw': raw,
            'decoded': si._decode_saml_value(raw, redirect_binding=False)}   # the app's own decoder


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    app = si.App()
    root = app._root
    root.geometry(f'{SIZE[0]}x{SIZE[1]}+40+40')
    root.attributes('-topmost', True)
    root.lift()

    def grab(name: str) -> None:
        root.update_idletasks()
        root.update()
        # Outer window, including the title bar where the platform draws one.
        frame = root.winfo_rootx() - root.winfo_x()
        title = root.winfo_rooty() - root.winfo_y()
        left, top = root.winfo_x(), root.winfo_y()
        right = left + root.winfo_width() + 2 * frame
        bottom = top + root.winfo_height() + title + frame
        ImageGrab.grab(bbox=(left, top, right, bottom)).save(OUT / name, optimize=True)
        print(f'saved {OUT / name}')

    def seeded() -> None:
        app._add_capture(_capture('SAMLRequest', REQUEST.format(id='req1'),
                                  'login.example-idp.com', '08:14:02', 'Redirect'))
        app._add_capture(_capture('SAMLResponse', RESPONSE, 'app.example.com', '08:14:09', 'POST'))
        app._add_capture(_capture('SAMLRequest', REQUEST.format(id='req2'),
                                  'login.example-idp.com', '08:15:30', 'Redirect'))
        # Show the "intercepting" state without starting the proxy.
        app._go_btn.configure(text='■  Stop Intercepting', bg=si._RED)
        app._status.configure(text=f'● Intercepting on {si.PROXY_HOST}:{si.PROXY_PORT}', fg=si._AMBER)
        first = app._flows[0]
        app._nb.select(first.tab_frame)
        views = first.w_resp_sum.master.master        # the flow's inner notebook
        grab('summary.png')
        views.select(2)
        grab('response-xml.png')
        root.destroy()

    def start() -> None:
        grab('first-run.png')
        root.after(200, seeded)

    root.after(1500, start)
    root.mainloop()


if __name__ == '__main__':
    main()

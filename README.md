# Global SAML Inspector

> **Disclosure:** This is a vibe-coded app built with AI assistance. All source files are available in this repository for inspection before running.

A Windows desktop tool that intercepts, decodes, and displays SAML authentication flows in real time. Acts as a system-wide HTTPS proxy, transparently man-in-the-middles every browser connection, and surfaces SAMLRequest and SAMLResponse payloads in a tabbed GUI — one tab per login flow, named by the authenticated email address.

[GitHub](https://github.com/darthrater78/globalsamlinspector) · [Release notes for v1.2.0](https://github.com/darthrater78/globalsamlinspector/releases/tag/v1.2.0) · [Changelog](CHANGELOG.md)

---

## Use Cases

- **Debugging SAML integrations** — see exactly what your IdP is asserting before it reaches the SP
- **Auditing attributes** — inspect every claim, group membership, and role assignment in a response
- **Testing IdP configurations** — verify NameID format, ACS URL, session validity windows, and authn context
- **Comparing flows** — run multiple logins back-to-back and compare tabs side by side
- **Onboarding / troubleshooting** — understand why a user can or can't access an app based on their actual assertions

---

## Architecture

```
Browser ──CONNECT──▶ Local Proxy (127.0.0.1:8080)
                          │
                    TLS MITM (forged leaf cert signed by local CA)
                          │
               ┌──────────┴──────────┐
               │  _do_connect()      │  Wraps browser socket in TLS using
               │                     │  per-domain cert signed by local CA
               └──────────┬──────────┘
                          │
               ┌──────────┴──────────┐
               │  _forward()         │  Reads first HTTP request, scans
               │                     │  query string + POST body for SAML
               └──────────┬──────────┘
                          │
               ┌──────────┴──────────┐
               │  _relay()           │  Bidirectional keep-alive relay.
               │  + _relay_scan()    │  Scans client→upstream chunks for
               │                     │  SAML POST bodies on reused tunnels
               └──────────┬──────────┘
                          │
                    Queue (thread-safe)
                          │
               ┌──────────┴──────────┐
               │  _poll() / tkinter  │  100ms poll, renders pre-parsed
               │  GUI                │  captures into flow tabs
               └─────────────────────┘
```

### Key Components

| Component | Description |
|---|---|
| `SAMLProxy` | Raw TCP server on `127.0.0.1:8080`. `ThreadPoolExecutor(64)` handles concurrent connections. Recreated on each Start so Stop→Start works without restarting the app. Verifies every upstream server certificate against the Windows trust store and answers `502` instead of relaying one that fails. Parses captures on its worker threads before queueing them for the GUI. |
| `CertManager` | Generates a local CA cert + RSA key on first run (stored in `%APPDATA%\SAMLInterceptor\certs\`; the private key is encrypted with Windows DPAPI). Issues per-domain leaf certs on demand, held in memory only. Installs/removes CA via `certutil -addstore/-delstore -user Root`. |
| `SystemProxy` | Writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` and calls `InternetSetOptionW` to make the change live without a browser restart. Restores original settings on Stop. The original settings are also saved to `%APPDATA%\SAMLInterceptor\proxy_restore.json` first, so a session that crashed or was killed is undone on the next launch. |
| `_relay_scan` | Buffers client→upstream bytes on keep-alive CONNECT tunnels. Bails immediately for non-POST or non-`application/x-www-form-urlencoded` traffic (zero overhead for downloads, API calls, streaming). Only buffers small form-encoded POSTs — the exact shape of a SAMLResponse. |
| `_build_summary` | Regex-based SAML XML parser. Extracts issuer, destination, NameID, validity window, and all attributes. Resolves Entra `wids` GUIDs to built-in role names. Renders Entra group GUIDs as clickable links to the Azure portal. |
| `App` / tkinter | Dark-themed `ttk.Notebook` GUI. Each SAML login flow gets a tab named by email. Five sub-tabs per flow: Response summary, Request summary, Response XML, Request XML, Raw base64. Middle-click or Ctrl+W closes a flow; right-click a text pane to copy. Colours, fonts and layout rules are in [`DESIGN.md`](DESIGN.md). |

### SAML Capture Paths

Two paths capture SAML payloads:

1. **Fresh CONNECT** — browser opens a new TLS tunnel. `_forward` reads the first request and scans the query string (SAMLRequest, Redirect binding) or POST body (SAMLResponse, POST binding).

2. **Keep-alive relay** — browser reuses an existing tunnel (common with Microsoft/Azure AD). `_relay_scan` buffers and scans subsequent requests on the same connection. This was the root cause of Microsoft flows not being captured in early versions.

### Flow Correlation

SAMLRequests and SAMLResponses are correlated using:
- SAMLRequest `ID` attribute → stored in `_by_req_id` dict
- SAMLResponse `InResponseTo` attribute → looked up in `_by_req_id`

If the lookup fails (ID extraction edge case), the fallback routes the response to the only waiting request-only flow (if exactly one exists).

---

## Setup

### Requirements

- Windows 10/11
- No installation required — single `.exe`

### Download

Get `SAMLInterceptor_v<version>.exe` from the [latest release](https://github.com/darthrater78/globalsamlinspector/releases/latest). The exe is not code-signed, so Windows SmartScreen may warn before running it. Each release's notes list the file's SHA-256; to check your download:

```
certutil -hashfile SAMLInterceptor_v1.2.0.exe SHA256
```

### First Run

1. Launch the exe
2. Click **Install CA** — installs the local CA into your Windows Trusted Root store (Windows asks you to confirm)
3. Restart your browser (Chrome/Edge pick up the new CA on next launch)
4. Click **▶ Start Intercepting** and accept the one-time warning that all traffic will pass through the proxy
5. Trigger a SAML login in your browser
6. A tab appears for each login flow, named by email once the response arrives
7. Click **■ Stop Intercepting** when you are done; closing the window also stops it

When you no longer need the tool, click **Remove CA** so the local CA is no longer trusted.

### Cert Management

| Button | Action |
|---|---|
| Install CA | Adds local CA to Windows Trusted Root (current user) |
| Remove CA | Removes it, after confirmation, and reports whether removal worked |
| Regen CA | Wipes and regenerates the CA, discards the per-site certificates issued from the old one, then reinstalls |
| View Cert | Opens the CA cert in Windows' native certificate viewer |

The CA status indicator in the toolbar shows **CA ✓ Installed** or **CA ✗ Not installed**, checked on launch and after every cert operation.

### Debug Logging

Click **Debug: Off** to toggle detailed proxy logging. While it is on, the log records the host and path of every request that passes through the proxy, not only SAML traffic, so turn it off when you are done. Logs write to `%APPDATA%\SAMLInterceptor\debug.log`, which is started afresh each time the app launches. Click **Open Log** to open it in your default text editor.

### What Is Stored on Disk

Everything lives under `%APPDATA%\SAMLInterceptor\`.

| File | Contents | Encrypted at rest |
|---|---|---|
| `certs\ca.key.dpapi` | The local CA's private key | Yes, with Windows DPAPI for the current user |
| `certs\ca.crt` | The local CA's public certificate | No; it is public |
| `debug.log` | Warnings, plus hosts and paths while Debug is on | No |
| `proxy_restore.json` | Your original proxy setting, only while intercepting | No |

Captured SAML requests and responses are held in memory only and are gone when the app closes. Per-site certificates and their key are generated per session and never stored.

---

## Building from Source

```
pip install -r requirements.txt
```

Edit `VERSION` to set the version (the window title, the exe's file properties and its name all come from it), then:

```
build_saml_interceptor.bat
```

The script installs the pinned requirements, runs `bandit`, `pip-audit` and the tests, and only then builds the exe and prints its SHA-256. Any of those failing stops the build. CI runs the same script on Windows for every push and pull request.

To run the tests on their own:

```
python -m unittest discover -s tests
```

**Python 3.10+ required.** Tested on Python 3.14.

`saml.ico` is committed; `python gen_icon.py` regenerates it. `python scripts/screenshots.py` regenerates the README screenshots from made-up sample data without starting the proxy or touching any system setting.

---

## Caveats

### Traffic Impact
The proxy routes **all traffic that uses the Windows system proxy** through itself while active, not only your SAML login. Stop intercepting as soon as you're done.

Stopping, or closing the window, restores your previous proxy setting. If the app is killed or crashes while intercepting, the setting is left pointing at a proxy that is no longer running and browsing fails until you start the app again, which restores it on launch.

### Untrusted Upstream Certificates
The proxy verifies the real server's certificate before relaying anything. An IdP or SP that presents a self-signed certificate, or one issued by a CA that Windows does not trust, is refused with a `502` page naming the reason. Add the issuing CA to the Windows trust store to inspect such a server.

Windows downloads some public root certificates only when they are first needed, and the proxy sees only the ones already on disk. A legitimate site can therefore be refused the first time; opening it once with interception off normally fixes that.

### Browser Compatibility
| Browser | Works | Notes |
|---|---|---|
| Chrome | ✓ | Uses Windows cert store |
| Edge | ✓ | Uses Windows cert store |
| Firefox 120+ | Expected ✓, untested | Trusts CAs you add to Windows by default; if that is switched off under Settings → Privacy & Security → Certificates, all HTTPS fails |
| Firefox before 120 | ✗ | Uses only its own cert store — all HTTPS fails |
| Safari | — | Not applicable (Windows only) |

### Certificate Pinning
Desktop apps that embed their own CA trust list (Slack, Teams and Spotify are examples) will reject the proxy's certs and fail to connect while interception is on. This is by design and cannot be worked around without modifying those apps.

### Protocol Support
The proxy speaks HTTP/1.1 only. HTTP/2 and HTTP/3 (QUIC) connections are not supported. Modern browsers negotiate HTTP/1.1 fallback automatically for proxy connections, so standard web browsing works correctly.

### HSTS
HSTS does not get in the way: the browser trusts the local CA, so it sees no certificate error to enforce.

### Scope
This tool is intended for **local debugging on your own machine** against your own IdP/SP configurations. It is not a network-level interceptor and does not affect other devices.

### Entra Group Names
Group GUIDs in SAML assertions are Entra object IDs. The tool renders them as clickable links to the Azure portal group overview page. Resolving GUIDs to display names requires a Microsoft Graph API call with `Group.Read.All` permission — this is not implemented automatically.

### Entra Role Names (`wids`)
The `wids` claim contains directory role template IDs. These are static and well-known — the tool resolves all 60+ built-in Entra role template IDs to their display names automatically (e.g. `b79fbf4d-…` → **Message Center Reader**).

---

## License

[MIT](LICENSE)

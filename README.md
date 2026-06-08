# Global SAML Inspector

> **Disclosure:** This is a vibe-coded app built with AI assistance. All source files are available in this repository for inspection before running.

A Windows desktop tool that intercepts, decodes, and displays SAML authentication flows in real time. Acts as a system-wide HTTPS proxy, transparently man-in-the-middles every browser connection, and surfaces SAMLRequest and SAMLResponse payloads in a tabbed GUI — one tab per login flow, named by the authenticated email address.

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
               │  _poll() / tkinter  │  100ms poll, decodes + renders
               │  GUI                │  captures into flow tabs
               └─────────────────────┘
```

### Key Components

| Component | Description |
|---|---|
| `SAMLProxy` | Raw TCP server on `127.0.0.1:8080`. `ThreadPoolExecutor(64)` handles concurrent connections. Recreated on each Start so Stop→Start works without restarting the app. |
| `CertManager` | Generates a local CA cert + RSA key on first run (stored in `%APPDATA%\SAMLInterceptor\certs\`). Issues per-domain leaf certs on demand, cached in memory. Installs/removes CA via `certutil -addstore/-delstore -user Root`. |
| `SystemProxy` | Writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` and calls `InternetSetOptionW` to make the change live without a browser restart. Restores original settings on Stop. |
| `_relay_scan` | Buffers client→upstream bytes on keep-alive CONNECT tunnels. Bails immediately for non-POST or non-`application/x-www-form-urlencoded` traffic (zero overhead for downloads, API calls, streaming). Only buffers small form-encoded POSTs — the exact shape of a SAMLResponse. |
| `_build_summary` | Regex-based SAML XML parser. Extracts issuer, destination, NameID, validity window, and all attributes. Resolves Entra `wids` GUIDs to built-in role names. Renders Entra group GUIDs as clickable links to the Azure portal. |
| `App` / tkinter | Dark-themed `ttk.Notebook` GUI. Each SAML login flow gets a tab named by email. Four sub-tabs per flow: Response summary, Request summary, Response XML, Raw base64. |

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

### First Run

1. Launch `SAMLInterceptor.exe`
2. Click **Install CA** — installs the local CA into your Windows Trusted Root store
3. Restart your browser (Chrome/Edge pick up the new CA on next launch)
4. Click **▶ Start Intercepting**
5. Trigger a SAML login in your browser
6. A tab appears for each login flow, named by email once the response arrives

### Cert Management

| Button | Action |
|---|---|
| Install CA | Adds local CA to Windows Trusted Root (current user) |
| Remove CA | Removes it |
| Regen CA | Wipes and regenerates the CA + all leaf certs, then reinstalls |
| View Cert | Opens the CA cert in Windows' native certificate viewer |

The CA status indicator in the toolbar shows **CA ✓ Installed** or **CA ✗ Not installed**, checked on launch and after every cert operation.

### Debug Logging

Click **Debug: Off** to toggle detailed proxy logging. Logs write to `%APPDATA%\SAMLInterceptor\debug.log`. Click **Open Log** to open it in your default text editor.

---

## Building from Source

```
pip install cryptography pyinstaller pillow
```

Edit `VERSION` to set the version, then:

```
build_saml_interceptor.bat
```

Or run the steps manually (see `build_saml_interceptor.bat` for the full sequence).

**Python 3.10+ required.** Tested on Python 3.14.

---

## Caveats

### Traffic Impact
The proxy routes **all system HTTPS traffic** through itself while active. Stop intercepting as soon as you're done.

### Browser Compatibility
| Browser | Works | Notes |
|---|---|---|
| Chrome | ✓ | Uses Windows cert store |
| Edge | ✓ | Uses Windows cert store |
| Firefox | ✗ | Maintains its own cert store — all HTTPS fails |
| Safari | — | Not applicable (Windows only) |

### Certificate Pinning
Apps that embed their own CA trust list (Slack, Teams, Spotify, most mobile apps) will reject the proxy's certs and fail to connect. This is by design and cannot be worked around without modifying those apps.

### Protocol Support
The proxy speaks HTTP/1.1 only. HTTP/2 and HTTP/3 (QUIC) connections are not supported. Modern browsers negotiate HTTP/1.1 fallback automatically for proxy connections, so standard web browsing works correctly.

### HSTS / HPKP
Sites with strict HPKP (HTTP Public Key Pinning) may reject the proxied connection. HPKP is deprecated and rarely encountered in practice.

### Scope
This tool is intended for **local debugging on your own machine** against your own IdP/SP configurations. It is not a network-level interceptor and does not affect other devices.

### Entra Group Names
Group GUIDs in SAML assertions are Entra object IDs. The tool renders them as clickable links to the Azure portal group overview page. Resolving GUIDs to display names requires a Microsoft Graph API call with `Group.Read.All` permission — this is not implemented automatically.

### Entra Role Names (`wids`)
The `wids` claim contains directory role template IDs. These are static and well-known — the tool resolves all 60+ built-in Entra role template IDs to their display names automatically (e.g. `b79fbf4d-…` → **Message Center Reader**).

---

## License

MIT

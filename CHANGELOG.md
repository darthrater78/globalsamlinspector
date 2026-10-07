# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.2.1] - 2026-10-07

### Fixed

- The "Intercepting on 127.0.0.1:8080" status text could push the Debug and Open Log buttons
  out of view on a narrow window. The buttons now keep their space and the status text is
  cut short instead.
- Group ID links in the response summary used a different font from the values around them
  and sat out of line; the underline also covered their indent.

### Added

- Screenshots in the README, captured on Windows from made-up sample data by
  `scripts/screenshots.py`.

### Changed

- README corrections: the release file name and how to check its SHA-256, first-run steps,
  Firefox 120+ behaviour, what happens if the app is killed while intercepting, and the
  Windows root-store and HSTS notes.

## [1.2.0] - 2026-10-07

### Security

- Upstream servers are now verified against the system trust store. Before this, the proxy
  relayed any certificate while the browser trusted the proxy's own CA, so interception
  removed server authentication for all traffic. A server that fails verification gets a
  `502` with the reason, and nothing is sent to it.
- The CA private key is encrypted with Windows DPAPI. An existing plaintext `ca.key` is
  re-wrapped and deleted on first launch; the installed CA keeps working.
- Per-domain leaf keys are no longer written to disk, and old leaf files are removed on
  startup. Leaf certificates cover the exact host only.
- `cryptography` 48.0.0 → 50.0.2 and `pillow` 12.2.0 → 12.3.0, both of which carried High
  advisories. The build now installs from the pinned `requirements.txt`.
- SAML payloads are capped at 1 MB, including after inflation, and anything containing a
  DTD is rejected.
- The proxy listener binds exclusively, `certutil` is called by absolute path, and the
  registry key is opened with read/set rights only.
- The exe is no longer UPX-packed, and the build prints its SHA-256.

### Added

- The system proxy setting is restored on the next launch if the app was killed or crashed
  while intercepting.
- Close a single flow with middle-click or Ctrl+W; right-click a flow tab for close options.
- Right-click Copy / Copy all in every text pane, and a horizontal scrollbar. The Raw tab
  wraps.
- GitHub and release-notes links in the toolbar.
- `DESIGN.md`, a unit and end-to-end test suite, CI on Windows for every push and pull
  request, dependency review, workflow linting and a Dependabot configuration.
- `LICENSE` (MIT).

### Changed

- "Stopped" is shown in neutral grey and "Intercepting" in amber with the proxy address.
  Dim text and error red now meet WCAG AA contrast.
- Remove CA and Clear ask for confirmation, and Remove CA reports whether it worked.
- The CA status indicator matches the certificate itself, not only its name.
- The window is DPI-aware and its default size scales with the display.
- A bandit finding, a vulnerable dependency or a failing test now fails the build.

### Fixed

- The hop-by-hop header filter also rewrote request bodies and stripped
  `Transfer-Encoding`, corrupting some uploads.
- Large uploads and downloads could be silently truncated by the relay.
- Parsing a slow or hostile SAML payload could freeze the window.
- After Regen CA, the proxy kept serving certificates signed by the old CA until restart.
- Hostnames longer than 64 characters and IP-literal hosts could not be intercepted.

### Upgrade notes

- An IdP that presents a self-signed certificate is now refused. Certificates issued by a
  private CA in the Windows trust store still work.

## [1.1.3] - 2026-06-09

- Icon overhaul, bandit fixes, window icon.
- Security hardening and pinned dependencies.

## [1.1.2] - 2026-06-08

- Initial public release.

[1.2.1]: https://github.com/darthrater78/globalsamlinspector/releases/tag/v1.2.1
[1.2.0]: https://github.com/darthrater78/globalsamlinspector/releases/tag/v1.2.0
[1.1.3]: https://github.com/darthrater78/globalsamlinspector/releases/tag/v1.1.3
[1.1.2]: https://github.com/darthrater78/globalsamlinspector/releases/tag/v1.1.2

---
version: alpha
name: SAML Interceptor
description: Dark, dense desktop inspector for SAML traffic. Windows, tkinter.
colors:
  primary: "#4ec9b0"
  surface: "#1e1e1e"
  surface-strip: "#252526"
  surface-raised: "#2d2d2d"
  button: "#3c3c3c"
  on-surface: "#d4d4d4"
  on-surface-dim: "#8f8f8f"
  on-raised-dim: "#b0b0b0"
  selection: "#094771"
  start: "#0e7a0d"
  stop: "#b71c1c"
  on-action: "#ffffff"
  active: "#e8b339"
  error: "#ff7b72"
  label: "#dcdcaa"
  heading: "#9cdcfe"
  rule: "#6a737d"
  warn: "#ce9178"
  xml-tag: "#569cd6"
  blob: "#6a9955"
typography:
  ui:
    fontFamily: Segoe UI
    fontSize: 12px
    fontWeight: 400
  ui-small:
    fontFamily: Segoe UI
    fontSize: 11px
    fontWeight: 400
  ui-action:
    fontFamily: Segoe UI
    fontSize: 13px
    fontWeight: 700
  ui-empty:
    fontFamily: Segoe UI
    fontSize: 15px
    fontWeight: 400
  data:
    fontFamily: Consolas
    fontSize: 13px
    fontWeight: 400
  data-small:
    fontFamily: Consolas
    fontSize: 12px
    fontWeight: 400
  data-heading:
    fontFamily: Consolas
    fontSize: 15px
    fontWeight: 700
rounded:
  none: 0px
spacing:
  xs: 3px
  sm: 6px
  md: 10px
  lg: 16px
components:
  toolbar:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.on-raised-dim}"
    padding: 6px
  button:
    backgroundColor: "{colors.button}"
    textColor: "{colors.on-surface}"
    typography: "{typography.ui}"
    rounded: "{rounded.none}"
    padding: 10px
  button-quiet:
    backgroundColor: "{colors.button}"
    textColor: "{colors.on-raised-dim}"
  button-toggled:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
  button-start:
    backgroundColor: "{colors.start}"
    textColor: "{colors.on-action}"
    typography: "{typography.ui-action}"
    padding: 14px
  button-stop:
    backgroundColor: "{colors.stop}"
    textColor: "{colors.on-action}"
    typography: "{typography.ui-action}"
  button-link:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.primary}"
  status-stopped:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.on-raised-dim}"
  status-intercepting:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.active}"
  status-error:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.error}"
  tab-strip:
    backgroundColor: "{colors.surface-strip}"
  divider:
    backgroundColor: "{colors.rule}"
    width: 1px
  text-selection:
    backgroundColor: "{colors.selection}"
    textColor: "{colors.on-surface}"
  tab:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.on-raised-dim}"
  tab-selected:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
  text-pane:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface}"
    typography: "{typography.data}"
  text-pane-dim:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.on-surface-dim}"
  text-pane-label:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.label}"
  text-pane-heading:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.heading}"
    typography: "{typography.data-heading}"
  text-pane-link:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.primary}"
  text-pane-error:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.error}"
  text-pane-warn:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.warn}"
  text-pane-xml-tag:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.xml-tag}"
  text-pane-blob:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.blob}"
    typography: "{typography.data-small}"
---

# SAML Interceptor

## Overview

A diagnostic tool for identity engineers, used for a few minutes at a time on their own Windows machine, next to a browser and an IdP admin console. It shows decoded SAML: structured text, GUIDs and XML. It should read like an editor or a network inspector: dense, monospace where the content is data, and quiet until something needs attention. The one thing that needs attention is that interception is on, because all of the machine's HTTPS traffic is being decrypted while it is.

Every token above is a constant at the top of the GUI section of `saml_interceptor.py`. The file and the code change together.

## Colors

The palette is the VS Code "Dark+" editor palette, kept on purpose: the audience reads XML and logs in that scheme all day, and its syntax colours already separate tags, labels and values.

- **Surfaces:** content `#1e1e1e`, tab strip `#252526`, toolbar and inactive tabs `#2d2d2d`, neutral buttons `#3c3c3c`. Depth is tone only.
- **Text:** `#d4d4d4`. Dim text is `#8f8f8f` on the content surface and `#b0b0b0` on the toolbar, tabs and buttons, where the darker grey fails contrast.
- **Primary `#4ec9b0` (teal):** links, the keyboard focus ring, positive status ("CA ✓ Installed", "Success"), and the toggled-on button.
- **Start `#0e7a0d` / Stop `#b71c1c`:** only the Start/Stop button, with white text.
- **Active `#e8b339` (amber):** only the "Intercepting" status.
- **Error `#ff7b72`:** decode errors and "CA ✗ Not installed".
- **Data colours:** field labels `#dcdcaa`, headings `#9cdcfe`, XML tags `#569cd6`, collapsed base64 `#6a9955`, non-success status `#ce9178`, rules `#6a737d`.

## Typography

- **Segoe UI** for chrome: 9pt for buttons, tabs and status, 8pt for sub-tabs, 10pt bold for Start/Stop, 11pt for the empty state.
- **Consolas** for everything captured: 10pt body, 9pt for collapsed blobs, 10pt and 11pt bold for section and capture headings. Captured data is never shown in a proportional font; the summary relies on a 20-character label column.

Sizes in the tokens are the pixel equivalents at 96 DPI.

## Layout

One window, default 1380x800 at 100% scaling, scaled by the display's DPI and never smaller than 1180x480. A single toolbar row, then a notebook of flows, each holding a notebook of five views (Response, Request, Resp. XML, Req. XML, Raw).

Toolbar order, left to right: Start/Stop, divider, the four CA actions, divider, Clear, interception status, CA status; on the right: Debug toggle, Open Log, divider, GitHub, Release notes. Buttons are 3px apart with 6px above and below; dividers are 1px with 8px either side.

Text panes do not wrap and have both scrollbars, except Raw, which wraps by character because base64 is one line.

## Elevation & Depth

Flat. No shadows and no borders around panes. The three surface tones are the only depth cue, and 1px `#6a737d` dividers separate toolbar groups.

## Shapes

Square corners everywhere (tkinter's flat relief). No rounded or pill shapes.

## Components

- **Button:** flat, `#3c3c3c`, 10px horizontal padding. Keyboard focus shows a 1px teal ring.
- **Start/Stop:** the only filled, coloured button. Green "▶ Start Intercepting", red "■ Stop Intercepting".
- **Link button:** toolbar-coloured background with teal text; opens the browser.
- **Toggle (Debug):** dim text when off, teal fill with dark text when on, and the label states the state.
- **Status text:** "● Stopped" is dim grey, because stopped is the safe, normal state. "● Intercepting on host:port" is amber. Status never relies on colour alone; the words carry it.
- **Flow tab:** named by the user's email once known, otherwise "Flow N". Middle-click or Ctrl+W closes it; right-click offers close and close all.
- **Text pane:** read-only, selectable, with a right-click Copy / Copy all menu.
- **GUID link:** teal, underlined, hand cursor.
- **Destructive actions** (Remove CA, Regen CA, Clear with captures present) ask first and report what actually happened.

## Do's and Don'ts

- Do add a colour or font as a named constant and a token here before using it; no hex values or font tuples inside widget code.
- Do keep normal text at 4.5:1 or better against its own surface; check dim text on raised surfaces separately.
- Do keep amber for "interception is on" and nothing else.
- Don't use red for a state that is normal or safe.
- Don't use emoji as icons; the only glyphs are ▶ ■ ● ✓ ✗.
- Don't add gradients, shadows, rounded corners or a second accent colour.
- Don't show captured data in a proportional font.
- Don't add a destructive action without a confirmation.

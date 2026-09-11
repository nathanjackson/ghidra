# ghidra-fido native helper

`ghidra-fido` is the client-side FIDO2 helper spawned by Ghidra during `-a5`
login. Unix builds statically link vendored **libfido2** and **libcbor**.
macOS also statically links a pinned **OpenSSL** so the helper does not depend
on Homebrew at runtime. Windows uses the platform WebAuthn API
(`webauthn.dll`) and does not use libfido2.

## Pinned sources

Fetched by `gradle -I gradle/support/fetchDependencies.gradle init` into
`dependencies/FileSystem/`:

| Tarball | Version | License |
|---|---|---|
| `libfido2-1.17.0.tar.gz` | 1.17.0 | BSD-2-Clause (Yubico) |
| `libcbor-0.12.0.tar.gz` | 0.12.0 | MIT |
| `openssl-3.5.8.tar.gz` | 3.5.8 (macOS static only) | Apache-2.0 |

Rebuild with `gradle :FileSystem:buildNatives`. That unpacks the tarballs and
runs `build-fido-deps.sh` per Ghidra platform (cmake required).

libfido2 is configured with USB HID only: `USE_HIDAPI=OFF`, `USE_PCSC=OFF`,
`NFC_LINUX=OFF`.

PIN handling (Linux/macOS): a PIN is sent on the first attempt when
`fido_dev_has_pin` is true for that device (YubiKeys return
`FIDO_ERR_UNSUPPORTED_OPTION` for `uv=true` without a PIN). Devices without
a PIN are tried without one; `UNSUPPORTED_OPTION` / `PIN_REQUIRED` then retry
that device with a PIN. A wrong PIN stops the device loop.

`clientDataJSON` origin/type/challenge strings are JSON-escaped. Windows uses a
helper-owned message-only window as the WebAuthn parent HWND, not the
foreground window.

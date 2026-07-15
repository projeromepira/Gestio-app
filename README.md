# Gestio

A free, local, encrypted password manager for Windows. Your passwords stay on
your computer: no account, no cloud, no tracking. Made by [Rovrix](https://rovrix.tech).

Download: **https://rovrix.tech/gestio/**

## Features

- Encrypted local vault, unlocked by a single master password (Argon2id +
  XChaCha20-Poly1305)
- Password and passphrase generator
- Built-in two-factor authenticator (TOTP) in a separate vault
- Breach alerts using Have I Been Pwned with k-anonymity (passwords never leave
  the device in clear)
- Optional recovery key
- Encrypted backup and CSV import from other managers
- Health dashboard: weak, reused, old, and leaked passwords
- Signed automatic updates
- Interface in 6 languages (French, English, Spanish, German, Italian,
  Portuguese)

Everything runs offline. Nothing is sent anywhere except an optional update check
and the on-demand breach check. See [SECURITY.md](SECURITY.md) for the full
security model and its honest limitations.

## Build from source

Prerequisites:

- [Rust](https://rustup.rs/) (stable toolchain)
- [Node.js](https://nodejs.org/) 18 or newer
- The platform prerequisites for [Tauri](https://tauri.app/start/prerequisites/)
  (on Windows: the Microsoft C++ Build Tools and WebView2)

Then:

```sh
npm install
npm run tauri build
```

The installer is produced in `src-tauri/target/release/bundle/`. For a live dev
build, use `npm run tauri dev`.

Note: released binaries are signed for the auto-updater with a private key that
is not in this repository. A build from source is unsigned, which is expected and
does not affect the app itself; only the auto-update signature check requires the
maintainer's key.

## Security

Gestio is a security tool, so its design is documented honestly, including what it
does not protect against, in [SECURITY.md](SECURITY.md). To report a vulnerability,
see the disclosure process there.

## License

Gestio is free software, licensed under the **GNU General Public License v3.0**
([LICENSE](LICENSE)). You can use, study, modify, and redistribute it; derivative
works must also be released under the GPL.

Third-party attributions (fonts, wordlist, dependencies) are in
[NOTICE.md](NOTICE.md).

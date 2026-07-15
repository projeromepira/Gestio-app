# Security policy

Gestio is a local password manager. Its security is only meaningful if the design
is honest about what it does and does not protect. This document is that honesty.

## Reporting a vulnerability

Please report security issues **privately**, not in public issues.

- Preferred: GitHub's private vulnerability reporting ("Report a vulnerability"
  on the Security tab).
- Alternative: contact the maintainer via https://jerome-pira.be

Please include steps to reproduce and the affected version. You will get a reply
as soon as possible. Do not disclose publicly until a fix is available.

## Supported versions

Only the latest released version receives security fixes.

## Security model

- **Local and offline.** The vault is stored and decrypted on your device. There
  is no account, no server, and no synchronization. Nothing is sent anywhere
  except the two network calls listed below.
- **Encryption.** The data key encrypts the vault with XChaCha20-Poly1305 (AEAD).
  That data key is itself wrapped by a key derived from your master password with
  Argon2id (memory-hard), and optionally by a key derived from a recovery code.
  The master password is never stored and is zeroized in memory after use.
- **Separate 2FA vault.** The authenticator (TOTP) lives in a distinct vault with
  its own master password.
- **Signed updates.** Updates are verified against a public key embedded in the
  app (minisign). An update that is not signed by the maintainer's private key is
  rejected.
- **Secrets in memory** are zeroized when the vault is locked.

## Network activity

The app makes only two kinds of outbound requests, both optional or on demand:

1. **Update check** (if enabled, on by default): on launch the app contacts the
   update endpoint over HTTPS and sends its IP and version. It can be turned off
   in settings.
2. **Breach check** (on demand): uses the Have I Been Pwned range API with
   k-anonymity. Only the first 5 characters of a password's SHA-1 hash are sent;
   the password itself is never transmitted.

There is no analytics, no telemetry, and no tracking.

## What Gestio does NOT protect against (limitations)

Being honest matters more than looking bulletproof.

- **A compromised machine.** If malware, a keylogger, or someone with access is
  already on your computer, they can capture your master password as you type it.
  No local password manager can defend against that.
- **Memory while unlocked.** Secrets are zeroized on lock, but while the vault is
  unlocked they exist in RAM and could be read via a memory dump, cold-boot, or
  swap/hibernation file.
- **The frontend, while unlocked.** The main password uses reveal-on-demand
  (decrypted server-side and copied to the clipboard, never resident in the UI).
  However, notes and "secret" custom fields are sent to the webview while the
  vault is unlocked, and are only masked visually. A compromised webview could
  read them. Treat the "secret" toggle as on-screen masking, not as protection
  against a compromised frontend.
- **Discreet mode is not deniability.** The disguised ("Notely") build hides the
  app from a casual look at installed programs, and the in-app decoy hides the
  vault behind a notepad. This is camouflage, not cryptography and not forensic
  deniability: the encrypted vault file and local settings can still reveal to a
  determined examiner that a password manager is present. It does not weaken the
  encryption; it only changes what is shown.
- **Auto-lock is enforced by the app.** Locking on inactivity is driven by the
  app; a frozen or suspended window could delay it. Lock manually (Ctrl+L) when
  you step away.
- **Clipboard history.** A copied password is cleared from the clipboard after a
  delay, but the operating system's clipboard history (e.g. Windows Win+V) or a
  cloud clipboard may retain it.
- **TOTP vault password.** Using a different password for the 2FA vault is
  recommended for defense in depth, but it is not enforced.
- **If you lose the master password** and did not set up a recovery key, the
  vault is unrecoverable by design.

## Cryptography

Standard, reviewed primitives, no home-made cryptography:

- KDF: Argon2id (memory-hard), parameters scale with the chosen security level.
- AEAD: XChaCha20-Poly1305 with random 24-byte nonces.
- CSPRNG: the operating system RNG (getrandom) for all keys, salts, and nonces.
- Update signatures: minisign / Ed25519.

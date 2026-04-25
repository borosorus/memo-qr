# Memo QR

Memo QR is a static local webpage for encrypting an existing BIP39 English mnemonic into a printable QR payload, then recovering it later with the same QR unlock password.

```text
Mnemonic + QR unlock password -> encrypted QR payload
Encrypted QR payload + password -> mnemonic
```

## Use

Open `index.html` in a modern browser. The app runs fully in the browser with plain HTML, CSS, and JavaScript.

Use the Encrypt tab to enter a BIP39 English mnemonic and QR unlock password. Print the generated QR or keep the encrypted text payload as a backup.

Use the Recover tab to paste the encrypted payload and enter the QR unlock password. The mnemonic is only shown after successful decryption.

## Security Model

This protects against someone seeing, scanning, photographing, or copying the printed encrypted QR code. They still need the QR unlock password to recover the mnemonic.

This does not protect against weak passwords, malware, compromised browser extensions, a modified copy of the webpage, or shoulder-surfing while the mnemonic is visible.

Anyone with the QR can try unlimited password guesses offline. Use at least 6 random words or 16+ random characters.

## Implementation

- Crypto: browser Web Crypto API only.
- KDF: PBKDF2-HMAC-SHA-256, 600,000 iterations.
- Encryption: AES-256-GCM with a random 16-byte salt and random 12-byte IV.
- Payload: `MNQR1.<base64url-json>`.
- QR: local vendored `qrcode-generator` runtime.
- Storage: none.

The app intentionally does not use cookies, `localStorage`, `sessionStorage`, IndexedDB, service workers, analytics, remote fonts, CDN imports, or server calls.

## V1 Scope

Included:

- Encrypt an existing BIP39 English mnemonic.
- Decrypt an encrypted Memo QR payload.
- Render a printable encrypted QR.
- Provide encrypted text payload backup.

Excluded:

- Mnemonic generation.
- QR camera scanning.
- BIP39 passphrase storage.
- Wallet derivation paths or address generation.
- Password recovery.
- Multilingual BIP39 wordlists.

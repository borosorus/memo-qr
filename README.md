# Memo QR

Memo QR is a static local webpage for encrypting validated mnemonics or plain text into a printable QR payload, then recovering it later with the same QR unlock password.

```text
Mnemonic or text + QR unlock password -> encrypted QR payload
Encrypted QR payload + password -> original content
```

## Use

Open `index.html` in a modern browser. The app runs fully in the browser with plain HTML, CSS, and JavaScript.

Use the Encrypt tab to choose Mnemonic or Text mode, then enter the content and QR unlock password. Mnemonic mode auto-detects BIP39 English and Monero 13 or 25-word phrases. Text mode preserves exact content and is limited to 2048 UTF-8 bytes.

Use the Recover tab to paste the encrypted payload, choose the same mode, and enter the QR unlock password. The recovered content is only shown after successful decryption and mode validation.

Use the Check tab to verify a QR and password without displaying the decrypted content.

The fingerprint identifies one encrypted payload. Re-encrypting the same content creates a new salt and IV, so it also creates a new fingerprint.

Recover and Check also include optional camera scanning and QR image import. Browsers usually allow camera access only on HTTPS origins or `localhost`; if camera access is unavailable, you can still import an image or paste the encrypted payload.

## Security Model

This protects against someone seeing, scanning, photographing, or copying the printed encrypted QR code. They still need the QR unlock password to recover the content.

This does not protect against weak passwords, malware, compromised browser extensions, a modified copy of the webpage, or shoulder-surfing while the decrypted content is visible.

Anyone with the QR can try unlimited password guesses offline. Use at least 6 random words or 16+ random characters.

## Best-Effort Cleanup

The Clear buttons remove visible secrets from the page, stop the camera, clear generated QR output, and zero temporary byte arrays controlled by the app where browser JavaScript allows it.

This is not guaranteed secure memory erasure. Browser strings, DOM input internals, Web Crypto internals, clipboard contents, browser or OS snapshots, extensions, malware, screenshots, and swap memory cannot be reliably overwritten by this page.

## Implementation

- Crypto: browser Web Crypto API only.
- KDF: PBKDF2-HMAC-SHA-256, 600,000 iterations.
- Encryption: AES-256-GCM with a random 16-byte salt and random 12-byte IV.
- Payload: `MNQR1.<base64url-json>`.
- Payload includes encrypted content ciphertext, encrypted password-check verifier, and encrypted-payload fingerprint.
- QR: local vendored `qrcode-generator` runtime.
- QR scanning: local vendored `jsQR` runtime.
- Storage: none.

The app intentionally does not use cookies, `localStorage`, `sessionStorage`, IndexedDB, service workers, analytics, remote fonts, CDN imports, or server calls.

## V1 Scope

Included:

- Encrypt BIP39 English mnemonics.
- Encrypt Monero 13 or 25-word mnemonics.
- Encrypt plain text up to 2048 UTF-8 bytes.
- Decrypt an encrypted Memo QR payload.
- Check a QR and password without displaying the decrypted content.
- Render a printable encrypted QR.
- Scan an encrypted QR with a desktop webcam or mobile camera when the browser allows camera access.
- Import a QR image locally for recovery or check mode.
- Provide encrypted text payload backup.

Excluded:

- Mnemonic generation.
- Additional mnemonic families beyond BIP39 English and Monero.
- Wallet derivation paths or address generation.
- Password recovery.
- Arbitrary structured wallet metadata.

# Memo QR

Memo QR is a static local webpage for encrypting text into a printable QR payload, then recovering it later with the same QR unlock password.

```text
 Plain text + QR unlock password -> encrypted QR payload
 Encrypted QR payload + password -> plain text
```

## Use

Open `index.html` in a modern browser. The app runs fully in the browser with plain HTML, CSS, and JavaScript.

Use the Encrypt tab to enter text and a QR unlock password. Text is preserved exactly as entered and is limited to 2048 UTF-8 bytes. Print the generated QR or keep the encrypted text payload as a backup.

Use the Recover tab to paste the encrypted payload and enter the QR unlock password. The text is only shown after successful decryption.

Use the Check tab to verify a QR and password without displaying the text.

The fingerprint identifies one encrypted payload. Re-encrypting the same text creates a new salt and IV, so it also creates a new fingerprint.

Recover and Check also include optional camera scanning and QR image import. Browsers usually allow camera access only on HTTPS origins or `localhost`; if camera access is unavailable, you can still import an image or paste the encrypted payload.

## Security Model

This protects against someone seeing, scanning, photographing, or copying the printed encrypted QR code. They still need the QR unlock password to recover the text.

This does not protect against weak passwords, malware, compromised browser extensions, a modified copy of the webpage, or shoulder-surfing while the text is visible.

Anyone with the QR can try unlimited password guesses offline. Use at least 6 random words or 16+ random characters.

## Best-Effort Cleanup

The Clear buttons remove visible secrets from the page, stop the camera, clear generated QR output, and zero temporary byte arrays controlled by the app where browser JavaScript allows it.

This is not guaranteed secure memory erasure. Browser strings, DOM input internals, Web Crypto internals, clipboard contents, browser or OS snapshots, extensions, malware, screenshots, and swap memory cannot be reliably overwritten by this page.

## Implementation

- Crypto: browser Web Crypto API only.
- KDF: PBKDF2-HMAC-SHA-256, 600,000 iterations.
- Encryption: AES-256-GCM with a random 16-byte salt and random 12-byte IV.
- Payload: `MNQR1.<base64url-json>`.
- Payload includes encrypted text ciphertext, encrypted password-check verifier, and encrypted-payload fingerprint.
- QR: local vendored `qrcode-generator` runtime.
- QR scanning: local vendored `jsQR` runtime.
- Storage: none.

The app intentionally does not use cookies, `localStorage`, `sessionStorage`, IndexedDB, service workers, analytics, remote fonts, CDN imports, or server calls.

## V1 Scope

Included:

- Encrypt text up to 2048 UTF-8 bytes.
- Decrypt an encrypted Memo QR payload.
- Check a QR and password without displaying the text.
- Render a printable encrypted QR.
- Scan an encrypted QR with a desktop webcam or mobile camera when the browser allows camera access.
- Import a QR image locally for recovery or check mode.
- Provide encrypted text payload backup.

Excluded:

- Structured wallet data support.
- Wallet derivation paths or address generation.
- Password recovery.
- Automatic text normalization.

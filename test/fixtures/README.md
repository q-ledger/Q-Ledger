# Test vectors

These files were produced by the Q-Ledger iOS app's own encryption code, compiled for macOS. They let the retrieval scripts be checked against the exact format the app writes.

| File | Contents |
|---|---|
| `test-vector-keyfile.json` | A key file in the app's export format, holding **throwaway test keys** created only for these vectors |
| `envelope-current.json` | A Pro (X-Wing + ML-KEM-768) wallet envelope in the current format (app builds from 2025-11-16 onward) |
| `envelope-legacy.json` | The same plaintext in the legacy format (app builds before 2025-11-16) |
| `plaintext.txt` | The expected decryption result: the public BIP39 test mnemonic, which holds no funds |

How they were generated:
- The app's `QSCryptionManager.swift` was compiled unmodified. The current vector used the app at commit `555f592`; the legacy vector used the version just before commit `6bf44f8`.
- ML-KEM-768 came from SwiftKyber 2.5.0 (FIPS 203) and X-Wing from CryptoKit.
- Only the keychain access was replaced by in-memory keys.
- Each envelope was round-tripped through the app's own `decryptData` before it was written.

Never use these keys for real data. They are public.

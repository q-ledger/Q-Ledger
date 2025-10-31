# Q-Ledger Wallet Retrieval Manual

## Overview

The Q-Ledger Retrieval Tool retrieves and decrypts wallet backups from Arweave's permanent storage network using your exported Q-Ledger key file and ML-KEM-768 quantum-safe cryptography.

**Use cases:**
- Emergency recovery when Q-Ledger app is unavailable
- Platform-independent wallet access
- Estate planning and beneficiary recovery
- Disaster recovery scenarios

---

## Quick Start

Assuming you have completed installation (see README), run:

```bash
node scripts/retrieve.js
```

The script will guide you through an interactive retrieval process.

---

## Using the Retrieval Script

### Step 1: Load Key File

The script automatically loads the most recent `QLedgerKeys_*.json` file from the `./keys/` directory.

```
Loading Q-Ledger key file...

✓ Key file loaded successfully
  Version: 1.4.0
  User ID: FAE7E8FF-22F7-4380-9506-716D7D6EE0EB
  Wallets: 8
```

### Step 2: Query Arweave

Your unique user identifier (UUID) is used to query Arweave for all wallet backups.

```
Querying Arweave for wallet backups...

✓ Found 8 wallet(s) on Arweave
```

### Step 3: Review Wallet List

All found wallets are displayed with their status and metadata:

```
WALLETS FOUND ON ARWEAVE
=========================

Total: 8 wallet(s)

[ 1] ✗ Revoked    Keystore Wallet - JSON Keystore File (2025-10-26 12:16)
     OGxgTANKVHArqA--UnGnTqzGhh-Swc2sFqZl5mscZNw

[ 2] ✓ Active     Test Wallet - Document (2025-10-26 13:41)
     0Uy-J_NQ0AlbMVMOk06m-AgWH1rY8TxAh5WbR7mlywM

[ 3] ✓ Active     Test bin - Document (2025-10-27 17:12)
     5OHaOI4tcmC1qelCSxC6Rdj1-hSnDvVExJaifOPWBg0

Status Legend:
  ✓ Active    - Wallet is active in your key file
  ✗ Revoked   - Wallet has been revoked
  ◆ Recovered - Wallet found on Arweave but not in your local key file
```

**Status Meanings:**

- **✓ Active** - Currently active wallet in your Q-Ledger app
- **✗ Revoked** - Previously revoked wallet backup (still retrievable but use with caution)
- **◆ Recovered** - Exists on Arweave but not in your current key file (may be from old backup or different device)

### Step 4: Select Wallet

Enter the wallet number or paste the full transaction ID:

```
Enter the Arweave transaction ID (or "q" to quit): 2
```

Or use the full transaction ID:

```
Enter the Arweave transaction ID (or "q" to quit): 0Uy-J_NQ0AlbMVMOk06m-AgWH1rY8TxAh5WbR7mlywM
```

Type `q` to quit at any time.

### Step 5: Decrypt and Save

The script displays wallet information, then fetches and decrypts the data:

```
SELECTED WALLET
===============
Transaction ID: 0Uy-J_NQ0AlbMVMOk06m-AgWH1rY8TxAh5WbR7mlywM
Status: active
Name: Test Wallet
Format: Document
Created: 10/26/2025, 1:41:17 PM

Fetching encrypted data from Arweave...
✓ Data retrieved from Arweave

Decrypting wallet...
  Encryption version: 1
  Algorithm: X-Wing/ML-KEM-768 + AES-256-GCM
  Recipients: 2
  Recipient types: X-Wing, ML-KEM-768

✓ Wallet decrypted successfully

===============================================
✓ RETRIEVAL SUCCESSFUL
===============================================

Wallet decrypted and saved to:
./wallets/Test_Wallet.txt

⚠️  SECURITY WARNINGS:

1. The decrypted file contains sensitive data in plaintext
2. Import it into secure wallet software IMMEDIATELY
3. DELETE the decrypted file after importing
4. Never share the decrypted file with anyone

===============================================
```

---

## Understanding the Output

### File Naming

Decrypted wallets are saved to `./wallets/` with the wallet name as filename:

```
Test_Wallet.txt
Q-Ledger_Key_File.json
Ethereum_Wallet.bin
```

Special characters in wallet names are replaced with underscores for filesystem compatibility.

### File Extensions

The file extension is determined by the wallet's key format and content:

- **`.txt`** - Text-based formats (BIP39 seed phrases, private keys, documents)
- **`.json`** - JSON Keystore files, JWK keys, Q-Ledger key files
- **`.bin`** - Binary document data

Binary detection uses strict UTF-8 validation - only Document format wallets can be binary.

### Decrypted Wallet Formats

Depending on what you backed up in Q-Ledger, the decrypted file will contain:

**BIP39 Seed Phrase:**
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

**Private Key (Hex):**
```
0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

**JSON Keystore:**
```json
{
  "version": 3,
  "id": "...",
  "address": "...",
  "crypto": { ... }
}
```

**Document:**
Plain text or binary data you uploaded as a document.

**Q-Ledger Key File:**
JSON file containing your ML-KEM-768 keys and wallet metadata (if you backed up your entire key file).

---

## Security Warnings

### Critical Reminders

1. **Decrypted files contain sensitive data in plaintext** - treat them like cash
2. **Import immediately** into secure wallet software
3. **Delete securely** after importing using secure deletion tools
4. **Never share** decrypted files with anyone
5. **Use trusted devices** only - avoid public or shared computers

### Secure Deletion

After importing your wallet, securely delete the decrypted file:

**Linux:**
```bash
shred -vfz -n 10 ./wallets/Test_Wallet.txt
```

**macOS:**
```bash
rm -P ./wallets/Test_Wallet.txt
```

**Windows:**
Use a secure deletion tool like Eraser or SDelete.

### Emergency Recovery

If retrieving on a potentially compromised device:
1. Transfer funds to a new wallet generated on a secure device
2. Revoke the recovered wallet backup in Q-Ledger app
3. Never reuse the recovered wallet

---

## Troubleshooting

### "No QLedgerKeys.json file found"

**Solution:** Ensure your key file is in the `./keys/` directory. Check README for setup instructions.

### "Invalid key file: missing ML-KEM secret key"

**Cause:** Key file exported from Q-Ledger Standard (free version).

**Solution:** Q-Ledger Pro version is required for ML-KEM keys. The free version only includes X-Wing keys which cannot be used for platform-independent recovery.

### "No wallets found on Arweave"

**Possible causes:**
- No wallets have been backed up yet
- Arweave hasn't indexed your transactions (wait 5-10 minutes)
- Wrong key file

**Solution:** Verify you've backed up wallets in Q-Ledger app and wait a few minutes for Arweave indexing.

### "Transaction not found"

**Possible causes:**
- Transaction not yet confirmed on Arweave
- Temporary gateway issue

**Solution:** Wait 5-10 minutes for confirmation or try again later. If persisting, the Arweave gateway may be slow.

### "Failed to decrypt symmetric key"

**Possible causes:**
- Wrong ML-KEM private key
- Wallet encrypted with a different key
- Corrupted data

**Solution:** Ensure you're using the same key file that was active when the wallet was backed up. If you have multiple key file exports, try an earlier one.

### "Rate limit exceeded"

**Cause:** Arweave gateway rate limiting.

**Solution:** Wait a few minutes and try again.

---

## Wallet Status Reference

### Active Wallets (✓)
- Currently in your Q-Ledger app
- Safe to retrieve and use
- Most common status for recent backups

### Revoked Wallets (✗)
- Previously marked as revoked in Q-Ledger app
- Still retrievable from Arweave (permanent storage)
- **Warning:** May have been compromised or superseded
- Only retrieve if you specifically need historical data

### Recovered Wallets (◆)
- Found on Arweave but not in your current key file
- **Possible reasons:**
  - Backed up from a different device
  - Old backup before you revoked/deleted the wallet
  - Restored key file from an earlier date
- **Caution:** Verify these are actually your wallets before retrieving

---

## Support

For issues not covered in this manual:

1. Check the troubleshooting section above
2. Review the README for setup instructions
3. Report issues on the GitHub repository issues page

---

## License

This tool is released into the public domain under CC0-1.0.

**Disclaimer:** This tool is provided as-is for emergency wallet recovery. Always verify decrypted wallet data before importing into wallet software.

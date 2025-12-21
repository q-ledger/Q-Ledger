# Q-Ledger Retrieval - Public Domain Recovery Tools

## About Q-Ledger Retrieval

Permanent, quantum-safe backup retrieval for your cryptocurrency private keys.

**[Read the Case For Q-Ledger](CaseForQLedger.pdf)** for a comprehensive overview of Q-Ledger's architecture and security model.

This repository hosts the **public-domain reference tools** that guarantee you can always retrieve your encrypted wallet backups from Arweave, even if the Q-Ledger iOS app becomes unavailable:

- **Retrieval script** for Q-Ledger Pro users with ML-KEM-768 dual-recipient encryption (platform-independent recovery)
- **Utility modules** for Arweave GraphQL queries, data retrieval, and quantum-safe decryption
- **Interactive CLI** that discovers all your wallet backups automatically

These tools exercise Q-Ledger's core architecture:

- **Quantum-safe encryption** — X-Wing (iOS) and ML-KEM-768 (cross-platform) protect against future quantum computing threats
- **Permanent distributed storage** — Encrypted backups stored forever on Arweave's decentralized network
- **Dual-recipient encryption** — Pro version encrypts for both X-Wing (iOS Keychain) and ML-KEM-768 (exportable) recipients
- **Open format, public domain** — The encryption format and recovery scripts are public so anyone can verify, audit, and build compatible tools

**Who this repo is for**

- Cryptocurrency holders who need emergency access to backed-up private keys
- Developers and auditors who want to verify Q-Ledger's security model
- Estate executors helping beneficiaries recover inherited cryptocurrency
- Anyone wanting platform-independent backup recovery outside Apple's ecosystem

## Repository Contents

```
Q-Ledger-Retrieval/
├── Manuals/
│   └── RetrievalManual.md       # Complete user guide
├── keys/                         # Directory for exported QLedgerKeys.json files
├── wallets/                      # Directory for retrieved wallet files (created automatically)
├── scripts/
│   ├── utils.js                 # Shared utilities (Arweave, decryption, ML-KEM-768)
│   └── retrieve.js              # Main interactive retrieval script
├── .gitignore
├── CaseForQLedger.pdf           # Comprehensive case for Q-Ledger's architecture
├── LICENSE                       # CC0-1.0 Public Domain dedication
├── README.md
├── package-lock.json
├── package.json
```

## Retrieval Tool

**Important:** This tool requires **Q-Ledger Pro** version with exported ML-KEM-768 keys.

The retrieval script (`scripts/retrieve.js`) provides:

### Automatic Discovery
- Queries Arweave's GraphQL endpoint for all your wallet backups
- Displays wallets with status: **Active**, **Revoked**, or **Recovered**
- Shows wallet names, creation dates, and formats from your key file

### Interactive Selection
- Browse all your backed-up wallets in a formatted table
- Select by transaction ID or list number
- View detailed information before decryption

### Platform-Independent Decryption
- Decrypt using exported ML-KEM-768 private key
- Full quantum-safe decryption without iOS device
- Extract wallet private keys, seed phrases, or documents
- Save in original format (.txt, .bin, etc.)

### Status Tracking
- **✓ Active** - Currently in your Q-Ledger app
- **✗ Revoked** - Previously revoked but still on Arweave
- **◆ Recovered** - Found on Arweave but not in current key file

**Note:** Standard (free) Q-Ledger users cannot use this tool, as X-Wing keys are non-exportable for security. Standard users must use the Q-Ledger iOS app for decryption.

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Export your key file from Q-Ledger iOS app (Pro version)
#    Place QLedgerKeys_YYYY-MM-DD.json in ./keys/ directory

# 3. Run the retrieval script
node scripts/retrieve.js
```

The script will automatically:
1. Load your key file
2. Display your user identifier
3. Query Arweave for all your wallet backups
4. Let you select and decrypt any wallet

**Full Manual:** See [Manuals/RetrievalManual.md](Manuals/RetrievalManual.md) for detailed instructions, troubleshooting, and security best practices.

### Prerequisites

- **Node.js** (v16.0.0 or higher) - [Download](https://nodejs.org/)
- **Q-Ledger Pro** version (requires ML-KEM-768 key export capability)
- **Exported key file** from Q-Ledger iOS app
- Basic command-line knowledge

## Security Considerations

These tools provide access to your encrypted cryptocurrency private keys. Always follow these security practices:

- Run these tools only on secure, trusted devices
- Never share your exported ML-KEM key files or decrypted wallet data
- Secure your `keys/` directory - it contains quantum-safe private keys
- Use these tools when Q-Ledger app is unavailable or for emergency recovery
- Verify Arweave transaction IDs before retrieval
- Move decrypted private keys to secure wallet software immediately
- Delete decrypted wallet files after importing to secure storage
- Consider encrypting the entire `keys/` and `wallets/` directories with tools like VeraCrypt

### ML-KEM-768 Private Key Protection

Q-Ledger Pro uses post-quantum cryptography (ML-KEM-768) for platform-independent recovery. Your ML-KEM private key is the master key to decrypt all your backed-up wallets:

- **Export only when needed:** Only export ML-KEM keys if you need cross-platform recovery or emergency access
- **Secure storage:** Encrypt exported key files using strong encryption (7-Zip AES-256, VeraCrypt, etc.)
- **Trust Apple ecosystem:** Most users should rely on automatic iCloud Keychain sync rather than manual key export
- **Emergency preparedness:** Think of key export as a "break glass in emergency" option, not a primary workflow

## Installation

### 1. Install Node.js

Ensure you have Node.js v16.0.0 or higher installed:

```bash
node --version
```

If not installed, download from [nodejs.org](https://nodejs.org/).

### 2. Clone or Download Repository

Clone this repository:

```bash
git clone https://github.com/q-ledger/Q-Ledger-Retrieval.git
cd Q-Ledger-Retrieval
```

Or download and extract the ZIP file from the GitHub repository page.

### 3. Install Dependencies

```bash
npm install
```

This installs the required packages:
- `@noble/post-quantum` - ML-KEM-768 quantum-safe cryptography
- `axios` - HTTP client for Arweave queries

### 4. Export Your Key File from Q-Ledger App

**Important:** You must have Q-Ledger Pro version to export ML-KEM keys.

**Steps to export:**

1. Open Q-Ledger iOS app
2. Navigate to **Settings** → **Key Management**
3. Tap **Export Key File**
4. Authenticate with Face ID/Touch ID/Passcode
5. Save or share the file (named `QLedgerKeys_YYYY-MM-DD.json`)
6. Transfer the file to your computer via AirDrop, email, or cloud storage

**Security note:** This file contains your quantum-safe private keys. Keep it secure and encrypted!

### 5. Place Key File in Keys Directory

Create the keys directory (if it doesn't exist) and place your exported key file:

```bash
mkdir -p keys
mv ~/Downloads/QLedgerKeys_2025-10-30.json ./keys/
```

The retrieval script automatically uses the most recent key file in the `./keys/` directory.

### 6. Run the Retrieval Script

```bash
node scripts/retrieve.js
```

The script will guide you through the interactive retrieval process.

### Customizing Arweave Gateway (Optional)

By default, the tool uses `https://arweave.net`. To use a different Arweave gateway:

1. Open `scripts/utils.js` in a text editor
2. Find line 22: `const ARWEAVE_GATEWAY = 'https://arweave.net';`
3. Change to your preferred gateway: `const ARWEAVE_GATEWAY = 'https://ar-io.net';`
4. Save and run the script

Popular Arweave gateways:
- `https://arweave.net` (default)
- `https://ar-io.net`
- `https://arweave.dev`

## Use Cases

### Emergency Recovery
Q-Ledger app unavailable, phone lost/broken, or App Store access restricted - use these scripts to retrieve your encrypted backups and restore access to your cryptocurrency.

### Platform Migration
Moving from iOS to Android or desktop wallet - Pro users can retrieve and decrypt wallet data for import into any compatible wallet software.

### Estate Planning
Include ML-KEM key export and these retrieval scripts in your inheritance plans. Beneficiaries can recover your backed-up cryptocurrency without needing your iPhone or Apple ID.

### Disaster Recovery
House fire, natural disaster, or device failure - as long as you have your ML-KEM key (or access to iCloud Keychain), your encrypted backups are permanently retrievable from Arweave's distributed network.

### Vendor Independence
Trust Apple's ecosystem for convenience, but maintain the option for complete vendor independence by exporting ML-KEM keys and using these public domain scripts.

## How Q-Ledger Encryption Works

### Standard Version (X-Wing Encryption)
- **Encryption:** X-Wing (hybrid X25519 + ML-KEM-768)
- **Key Storage:** iOS Keychain (syncs via iCloud, non-exportable)
- **Decryption:** Q-Ledger iOS app only
- **Security:** Quantum-resistant, maximum key protection
- **Trade-off:** Requires iOS device for decryption

### Pro Version (Dual-Recipient Encryption)
- **Encryption:** Both X-Wing AND ML-KEM-768 in dual-recipient format
- **Key Storage:**
  - X-Wing: iOS Keychain (syncs via iCloud)
  - ML-KEM: iOS Keychain + optional export
- **Decryption:** Q-Ledger iOS app OR these public domain scripts with exported key
- **Security:** Quantum-resistant with platform independence option
- **Trade-off:** Exporting ML-KEM key creates another private key to secure

Both versions provide quantum-safe protection. Pro adds flexibility for cross-platform recovery and complete vendor independence.

## Why Public Domain?

These retrieval scripts are released into the public domain to guarantee:

1. **Liveness:** You can always retrieve your encrypted backups, even if Q-Ledger the company disappears
2. **Auditability:** Security researchers can verify the encryption format and recovery process
3. **Interoperability:** Anyone can build compatible tools, alternative clients, or enhanced features
4. **Trust:** Transparency enables verification - you don't need to trust Q-Ledger's claims
5. **Permanence:** Public domain ensures these tools remain freely available forever

Security in Q-Ledger does not depend on secrecy - openness enables trust and allows anyone to audit the cryptography and data format.

## Encryption Format Specification

Q-Ledger's encrypted backup format is fully documented and open:

- **Envelope format:** JSON structure with metadata, ciphertext, and authentication tags
- **Standard encryption:** X-Wing encapsulation key + symmetric encryption (AES-256-GCM)
- **Pro dual-recipient:** Independent X-Wing and ML-KEM-768 encryptions of the same wallet data
- **Arweave storage:** Encrypted envelope uploaded to permanent decentralized storage

The implementation details can be reviewed in the source code at `scripts/utils.js`.

## License

This project is released into the public domain under CC0-1.0. See [LICENSE](LICENSE) for details.

## Open Source & Community

The Q-Ledger retrieval tools are public domain to guarantee liveness and auditability. Anyone can study, fork, or build upon these tools.

Note: The Q-Ledger iOS app remains the reference implementation for wallet backup creation. Community developers are welcome to build clients that retrieve and decrypt backups, though creating encrypted backups is optimized for the official app to ensure proper encryption and Arweave upload.

We encourage contributions, interoperability, and adoption of Q-Ledger's dual-recipient encryption format as an open standard for quantum-safe backup solutions.

## Contact

For support or questions:
- Website: [www.q-ledger.app](https://www.q-ledger.app)
- Telegram: [Join our Telegram](https://t.me/+6QS77mPO5V40YjU1)

---

**Disclaimer:** These tools are provided as-is for emergency wallet recovery. While efforts have been made to ensure their security and accuracy, use them at your own risk. Always verify decrypted wallet data before importing into wallet software. Q-Ledger is not responsible for loss of funds due to misuse of these tools.

## Acknowledgments

- The Arweave project for permanent decentralized storage
- The NIST Post-Quantum Cryptography team for ML-KEM standardization
- Apple's Security Engineering team for X-Wing implementation in iOS
- All contributors to the Node.js packages used in this project

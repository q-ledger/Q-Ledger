/**
 * Q-Ledger Retrieval Utilities
 *
 * Shared utilities for retrieving and decrypting Q-Ledger wallet backups from Arweave
 * Based on dual-recipient encryption format with ML-KEM-768
 *
 * Public domain - released under CC0-1.0
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');

// ============================================================================
// CONSTANTS
// ============================================================================

// Arweave Configuration
// To use a different Arweave gateway, modify the ARWEAVE_GATEWAY constant below
const ARWEAVE_GATEWAY = 'https://arweave.net';
const ARWEAVE_GRAPHQL = `${ARWEAVE_GATEWAY}/graphql`;
const MAX_GRAPHQL_RESULTS = 100;
const HTTP_TIMEOUT_MS = 30000;

// Cryptographic Constants
const ML_KEM_768_PRIVATE_KEY_LENGTH = 2400;
const SHA256_OUTPUT_LENGTH = 32;
const GCM_NONCE_LENGTH = 12;
const GCM_TAG_LENGTH = 16;

// File System Constants
const MAX_FILENAME_LENGTH = 50;

// ============================================================================
// KEY FILE MANAGEMENT
// ============================================================================

/**
 * Load the most recent QLedgerKeys.json file from the keys directory
 *
 * @returns {Promise<object>} - Parsed key file data
 */
async function loadKeyFile() {
    const keysDir = path.join(process.cwd(), 'keys');

    try {
        const files = await fs.readdir(keysDir);
        const keyFiles = files.filter(f => f.match(/QLedgerKeys.*\.json$/i));

        if (keyFiles.length === 0) {
            throw new Error('No QLedgerKeys.json file found in ./keys/ directory');
        }

        // Sort by modification time (most recent first)
        const fileStats = await Promise.all(
            keyFiles.map(async f => {
                const filePath = path.join(keysDir, f);
                return {
                    name: f,
                    path: filePath,
                    mtime: (await fs.stat(filePath)).mtime
                };
            })
        );

        fileStats.sort((a, b) => b.mtime - a.mtime);
        const keyFilePath = fileStats[0].path;

        console.log(`Loading key file: ${keyFilePath}\n`);

        const fileContent = await fs.readFile(keyFilePath, 'utf8');
        const keyData = JSON.parse(fileContent);

        // Validate key file structure
        if (!keyData.appName || keyData.appName !== 'Q-Ledger') {
            throw new Error('Invalid key file: not a Q-Ledger key file');
        }

        if (!keyData.userIdentifier) {
            throw new Error('Invalid key file: missing userIdentifier');
        }

        if (!keyData.mlKemSecretKey) {
            throw new Error('Invalid key file: missing ML-KEM secret key (Pro version required)');
        }

        console.log(`✓ Key file loaded successfully`);
        console.log(`  Version: ${keyData.version}`);
        console.log(`  User ID: ${keyData.userIdentifier}`);
        console.log(`  Wallets: ${keyData.wallets?.length || 0}\n`);

        return keyData;

    } catch (error) {
        if (error.code === 'ENOENT') {
            throw new Error('Keys directory not found. Please create ./keys/ and add your QLedgerKeys.json file.');
        }
        throw error;
    }
}

/**
 * Load ML-KEM-768 private key from key data
 *
 * @param {object} keyData - Parsed key file data
 * @returns {Uint8Array} - ML-KEM-768 private key (2400 bytes)
 */
function loadMLKEMKey(keyData) {
    const privateKeyBase64 = keyData.mlKemSecretKey;
    const privateKeyBytes = Buffer.from(privateKeyBase64, 'base64');

    // Validate ML-KEM-768 private key length
    if (privateKeyBytes.length !== ML_KEM_768_PRIVATE_KEY_LENGTH) {
        throw new Error(`Invalid ML-KEM-768 private key length: ${privateKeyBytes.length} (expected ${ML_KEM_768_PRIVATE_KEY_LENGTH})`);
    }

    return new Uint8Array(privateKeyBytes);
}

// ============================================================================
// ARWEAVE GRAPHQL QUERIES
// ============================================================================

/**
 * Query Arweave GraphQL for all transactions with a specific UserId tag
 *
 * @param {string} userId - User identifier (UUID)
 * @returns {Promise<Array>} - Array of wallet objects with txId and metadata
 */
async function queryArweaveByUserId(userId) {
    const query = `
        query {
            transactions(
                tags: [
                    { name: "UserId", values: ["${userId}"] }
                ],
                first: ${MAX_GRAPHQL_RESULTS}
            ) {
                edges {
                    node {
                        id
                        tags {
                            name
                            value
                        }
                    }
                }
            }
        }
    `;

    try {
        const response = await axios.post(
            ARWEAVE_GRAPHQL,
            { query },
            {
                headers: { 'Content-Type': 'application/json' },
                timeout: HTTP_TIMEOUT_MS
            }
        );

        if (response.data.errors) {
            throw new Error(`GraphQL errors: ${JSON.stringify(response.data.errors)}`);
        }

        const edges = response.data.data.transactions.edges;

        // Fetch metadata for all transactions in parallel
        const walletPromises = edges.map(async (edge) => {
            const txId = edge.node.id;

            try {
                // Fetch transaction data to retrieve metadata
                const txData = await retrieveFromArweave(txId);
                const metadata = txData.metadata || null;

                return { txId, metadata };
            } catch (error) {
                // Add transaction without metadata if retrieval fails
                console.warn(`Warning: Could not fetch metadata for ${txId}: ${error.message}`);
                return { txId, metadata: null };
            }
        });

        const wallets = await Promise.all(walletPromises);
        return wallets;

    } catch (error) {
        if (error.response) {
            throw new Error(`Arweave GraphQL error: ${error.response.status} ${error.response.statusText}`);
        } else if (error.code === 'ECONNABORTED') {
            throw new Error('Request timed out. Please check your internet connection.');
        } else {
            throw new Error(`Failed to query Arweave: ${error.message}`);
        }
    }
}

// ============================================================================
// ARWEAVE DATA RETRIEVAL
// ============================================================================

/**
 * Retrieve encrypted wallet data from Arweave using transaction ID
 *
 * @param {string} txId - Arweave transaction ID
 * @returns {Promise<object>} - Encrypted wallet data (DualRecipientEncryptedData format)
 */
async function retrieveFromArweave(txId) {
    if (!txId || typeof txId !== 'string') {
        throw new Error('Invalid transaction ID');
    }

    txId = txId.trim();

    try {
        const url = `${ARWEAVE_GATEWAY}/${txId}`;
        const response = await axios.get(url, {
            timeout: HTTP_TIMEOUT_MS,
            headers: { 'Accept': 'application/json' }
        });

        if (!response.data) {
            throw new Error('No data returned from Arweave');
        }

        return response.data;

    } catch (error) {
        if (error.response) {
            if (error.response.status === 404) {
                throw new Error(`Transaction not found: ${txId}`);
            } else if (error.response.status === 429) {
                throw new Error('Rate limit exceeded. Please wait and try again.');
            } else {
                throw new Error(`Arweave error ${error.response.status}: ${error.response.statusText}`);
            }
        } else if (error.code === 'ECONNABORTED') {
            throw new Error('Request timed out. Check your connection and try again.');
        } else {
            throw new Error(`Failed to retrieve from Arweave: ${error.message}`);
        }
    }
}

// ============================================================================
// CRYPTOGRAPHIC UTILITIES
// ============================================================================

/**
 * HKDF key derivation (RFC 5869)
 *
 * @param {Buffer} ikm - Input keying material
 * @param {Buffer} salt - Salt value
 * @param {Buffer} info - Context/application specific info
 * @param {number} length - Desired output length in bytes
 * @returns {Buffer} - Derived key
 */
function hkdf(ikm, salt, info, length) {
    // HKDF-Extract: Create PRK using HMAC-SHA256
    const prk = crypto.createHmac('sha256', salt).update(ikm).digest();

    // HKDF-Expand: Expand PRK to desired length
    const okm = Buffer.alloc(length);
    let t = Buffer.alloc(0);
    let offset = 0;

    const iterations = Math.ceil(length / SHA256_OUTPUT_LENGTH);
    for (let i = 1; i <= iterations; i++) {
        const data = Buffer.concat([t, info, Buffer.from([i])]);
        t = crypto.createHmac('sha256', prk).update(data).digest();
        t.copy(okm, offset, 0, Math.min(SHA256_OUTPUT_LENGTH, length - offset));
        offset += SHA256_OUTPUT_LENGTH;
    }

    return okm;
}

/**
 * Decrypt the wrapped symmetric key using ML-KEM-768
 *
 * @param {Buffer} wrappedKey - Wrapped symmetric key (nonce + ciphertext + tag)
 * @param {Buffer} encapsulatedKey - ML-KEM encapsulated key
 * @param {object} recipient - Recipient metadata (must include salt, recV, kid, type)
 * @param {Uint8Array} privateKey - ML-KEM-768 private key
 * @returns {Buffer} - Decrypted symmetric key (32 bytes for AES-256)
 */
function decryptSymmetricKey(wrappedKey, encapsulatedKey, recipient, privateKey) {
    try {
        // Step 1: Decapsulate to get shared secret (quantum-safe KEM)
        const sharedSecret = ml_kem768.decapsulate(encapsulatedKey, privateKey);

        // Step 2: Derive encryption key using HKDF-SHA256
        // Format: "wrap|v=1|kid={kid}" (from QSCryptionManager.swift line 188)
        const info = Buffer.from(`wrap|v=1|kid=${recipient.kid}`, 'utf8');
        const salt = Buffer.from(recipient.salt, 'base64');
        const encryptionKey = hkdf(Buffer.from(sharedSecret), salt, info, 32);

        // Step 3: Extract nonce, tag, and ciphertext from wrapped key
        const nonce = wrappedKey.subarray(0, GCM_NONCE_LENGTH);
        const tag = wrappedKey.subarray(-GCM_TAG_LENGTH);
        const ciphertext = wrappedKey.subarray(GCM_NONCE_LENGTH, -GCM_TAG_LENGTH);

        // Step 4: Build AAD (Additional Authenticated Data)
        // Format: "recV={recV}|kid={kid}|type={type}|kem_hash={kemHash}|nonce={wrapNonce}"
        // (from QSCryptionManager.swift line 309)
        const kemHash = crypto.createHash('sha256').update(encapsulatedKey).digest();
        const kemHashB64 = kemHash.toString('base64');
        const wrapNonceB64 = nonce.toString('base64');
        const aad = Buffer.from(
            `recV=${recipient.recV}|kid=${recipient.kid}|type=${recipient.type}|kem_hash=${kemHashB64}|nonce=${wrapNonceB64}`,
            'utf8'
        );

        // Step 5: Decrypt using AES-256-GCM
        const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, nonce);
        decipher.setAuthTag(tag);
        decipher.setAAD(aad);

        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted;

    } catch (error) {
        throw new Error(`Failed to decrypt symmetric key: ${error.message}`);
    }
}

/**
 * Decrypt the wallet payload using the symmetric key
 *
 * @param {object} arweaveData - DualRecipientEncryptedData from Arweave
 * @param {Buffer} symmetricKey - Decrypted AES-256 symmetric key
 * @returns {Buffer} - Decrypted wallet data
 */
function decryptWalletPayload(arweaveData, symmetricKey) {
    try {
        const version = arweaveData.version;
        const recipientCount = arweaveData.recipients.length;

        // Build AAD for payload decryption
        // Format: "v={version}|recipients={recipients}"
        // (from QSCryptionManager.swift line 305)
        const payloadAAD = Buffer.from(
            `v=${version}|recipients=${recipientCount}`,
            'utf8'
        );

        const ciphertext = Buffer.from(arweaveData.ciphertext, 'base64');
        const nonce = Buffer.from(arweaveData.nonce, 'base64');
        const tag = Buffer.from(arweaveData.tag, 'base64');

        // Decrypt using AES-256-GCM
        const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, nonce);
        decipher.setAuthTag(tag);
        decipher.setAAD(payloadAAD);

        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted;

    } catch (error) {
        throw new Error(`Failed to decrypt wallet payload: ${error.message}`);
    }
}

/**
 * Check if wallet has ML-KEM-768 recipient (Pro version)
 *
 * @param {object} arweaveData - Data from Arweave
 * @returns {boolean} - True if wallet has ML-KEM-768 recipient
 */
function hasMLKEMRecipient(arweaveData) {
    if (!arweaveData.recipients || !Array.isArray(arweaveData.recipients)) {
        return false;
    }
    return arweaveData.recipients.some(r => r.type === 'ML-KEM-768');
}

/**
 * Complete decryption workflow for dual-recipient encrypted wallet
 *
 * @param {object} arweaveData - DualRecipientEncryptedData from Arweave
 * @param {Uint8Array} mlkemPrivateKey - ML-KEM-768 private key
 * @returns {Buffer} - Decrypted wallet data
 */
function decryptWallet(arweaveData, mlkemPrivateKey) {
    // Find ML-KEM-768 recipient
    const mlkemRecipient = arweaveData.recipients.find(r => r.type === 'ML-KEM-768');
    if (!mlkemRecipient) {
        throw new Error('No ML-KEM-768 recipient found. This wallet was created with Q-Ledger Standard (non-Pro) version and can only be decrypted in the Q-Ledger iOS app.');
    }

    // Decrypt the symmetric key
    const wrappedKey = Buffer.from(mlkemRecipient.wrappedK, 'base64');
    const encapsulatedKey = Buffer.from(mlkemRecipient.kem_ct, 'base64');

    const recipient = {
        recV: mlkemRecipient.recV,
        kid: mlkemRecipient.kid,
        type: mlkemRecipient.type,
        salt: mlkemRecipient.salt
    };

    const symmetricKey = decryptSymmetricKey(wrappedKey, encapsulatedKey, recipient, mlkemPrivateKey);

    // Decrypt the wallet payload
    const decryptedWallet = decryptWalletPayload(arweaveData, symmetricKey);

    return decryptedWallet;
}

// ============================================================================
// WALLET STATUS HELPERS
// ============================================================================

/**
 * Determine wallet status based on keyfile data
 *
 * @param {string} txId - Arweave transaction ID
 * @param {object} keyData - Parsed key file data
 * @returns {string} - 'active', 'revoked', or 'recovered'
 */
function getWalletStatus(txId, keyData) {
    if (!keyData.wallets) {
        return 'recovered';
    }

    const wallet = keyData.wallets.find(w => w.arweaveTransactionId === txId);

    if (!wallet) {
        return 'recovered';
    }

    return wallet.revoked ? 'revoked' : 'active';
}

/**
 * Get wallet metadata from Arweave or local keyfile
 *
 * @param {string} txId - Arweave transaction ID
 * @param {object} keyData - Parsed key file data
 * @param {object|null} arweaveMetadata - Metadata from Arweave (preferred source)
 * @returns {object|null} - Wallet metadata or null if not found
 */
function getWalletMetadata(txId, keyData, arweaveMetadata = null) {
    // Prefer Arweave metadata when available
    // This enables wallet recovery using only UUID and ML-KEM-768 keys
    if (arweaveMetadata) {
        return {
            walletName: arweaveMetadata.walletName || 'Unknown',
            keyFormat: arweaveMetadata.keyFormat || 'Unknown',
            dateCreated: arweaveMetadata.createdAt || null
        };
    }

    // Fall back to local keyfile if Arweave metadata is unavailable
    if (keyData.wallets) {
        const keyfileWallet = keyData.wallets.find(w => w.arweaveTransactionId === txId);
        if (keyfileWallet) {
            return keyfileWallet;
        }
    }

    return null;
}

// ============================================================================
// FILE UTILITIES
// ============================================================================

/**
 * Validate if Buffer contains valid UTF-8 encoded text
 * Equivalent to Swift's: String(data:encoding:.utf8) != nil
 *
 * @param {Buffer} data - Data to validate
 * @returns {boolean} - True if valid UTF-8 text, false if binary/invalid
 */
function isValidUTF8(data) {
    try {
        // Use TextDecoder with fatal flag to strictly validate UTF-8
        // This throws TypeError for invalid UTF-8 sequences (matches Swift behavior)
        const decoder = new TextDecoder('utf-8', { fatal: true });
        decoder.decode(data);
        return true;
    } catch (e) {
        // Invalid UTF-8 sequence detected - data is binary
        return false;
    }
}

/**
 * Detect if content is text or binary using strict UTF-8 validation
 * Matches Swift's String(data:encoding:) behavior
 *
 * @param {Buffer} data - Data to check
 * @returns {boolean} - True if text, false if binary
 */
function isLikelyText(data) {
    // Empty data is considered text
    if (data.length === 0) {
        return true;
    }

    // Check if data is valid UTF-8 (matches Swift's behavior)
    return isValidUTF8(data);
}

/**
 * Determine file extension based on wallet data and key format
 *
 * IMPORTANT: Only "Document" keyFormat can be binary (.bin) or text (.txt)
 * All other formats are ALWAYS text-based
 *
 * @param {Buffer} walletData - Decrypted wallet data
 * @param {string} keyFormat - Key format from metadata (e.g., "JSON Keystore File", "Document")
 * @returns {string} - File extension ('bin', 'json', or 'txt')
 */
function determineFileExtension(walletData, keyFormat) {
    // Step 1: Check if keyFormat is "Document" - only this format can be binary
    if (keyFormat === 'Document' || keyFormat === 'Auto Detect') {
        const isBinary = !isLikelyText(walletData);
        if (isBinary && walletData.length > 0) {
            return 'bin';
        }
        return 'txt';
    }

    // Step 2: Check key format for JSON types
    if (keyFormat === 'JSON Keystore File' || keyFormat === 'JSON JWK') {
        return 'json';
    }

    // Step 3: All other formats are text (BIP39, Raw Hex, WIF, BIP32, Q-Ledger Keys, etc.)
    return 'txt';
}

/**
 * Save decrypted wallet to file
 *
 * @param {Buffer} walletData - Decrypted wallet data
 * @param {string} walletName - Wallet name for filename
 * @param {string} keyFormat - Key format from metadata (optional)
 * @returns {Promise<string>} - Path where wallet was saved
 */
async function saveWallet(walletData, walletName, keyFormat) {
    // Determine file extension based on key format and content analysis
    const extension = determineFileExtension(walletData, keyFormat || 'Document');

    // Sanitize wallet name for filesystem
    const sanitizedName = walletName
        .replace(/[^a-zA-Z0-9-_\s]/g, '_')  // Replace invalid chars with underscore
        .replace(/\s+/g, '_')                // Replace spaces with underscore
        .substring(0, MAX_FILENAME_LENGTH);  // Limit length for filesystem compatibility

    const filename = `${sanitizedName}.${extension}`;
    const walletsDir = path.join(process.cwd(), 'wallets');
    const outputPath = path.join(walletsDir, filename);

    // Ensure directory exists
    await fs.mkdir(walletsDir, { recursive: true });

    // Write file
    await fs.writeFile(outputPath, walletData);

    console.log(`✓ Wallet saved to: ${outputPath}\n`);
    return outputPath;
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
    // Key management
    loadKeyFile,
    loadMLKEMKey,

    // Arweave
    queryArweaveByUserId,
    retrieveFromArweave,

    // Decryption
    hasMLKEMRecipient,
    decryptWallet,

    // Wallet status
    getWalletStatus,
    getWalletMetadata,

    // File utilities
    saveWallet,

    // Constants
    ARWEAVE_GATEWAY
};

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
// Gateways are tried in order; to add or prefer a gateway, edit this list
const ARWEAVE_GATEWAYS = [
    'https://arweave.net',
    'https://turbo-gateway.com',
    'https://ar-io.dev'
];
const APP_NAME = 'Q-Ledger';
const GRAPHQL_PAGE_SIZE = 100;
const HTTP_TIMEOUT_MS = 30000;
const FETCH_CONCURRENCY = 8;

// Cryptographic Constants
const ML_KEM_768_PRIVATE_KEY_LENGTH = 2400;
const ML_KEM_768_PUBLIC_KEY_OFFSET = 1152;
const ML_KEM_768_PUBLIC_KEY_LENGTH = 1184;
const ML_KEM_768_RECIPIENT_TYPE = 'ML-KEM-768';
const KEY_FINGERPRINT_LENGTH = 8;
const SHA256_OUTPUT_LENGTH = 32;
const GCM_NONCE_LENGTH = 12;
const GCM_TAG_LENGTH = 16;

// Envelope formats, newest first. On 2025-11-16 the iOS app appended
// "|alg=AES-256-GCM" to both the key-wrap HKDF info and the payload AAD;
// wallets stored before that date use the legacy strings.
const ENVELOPE_FORMATS = [
    {
        name: 'current',
        wrapInfo: (kid) => `wrap|v=1|kid=${kid}|alg=AES-256-GCM`,
        payloadAAD: (version, recipients) => `v=${version}|alg=AES-256-GCM|recipients=${recipients}`
    },
    {
        name: 'legacy',
        wrapInfo: (kid) => `wrap|v=1|kid=${kid}`,
        payloadAAD: (version, recipients) => `v=${version}|recipients=${recipients}`
    }
];

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
        if (!keyData.appName || keyData.appName !== APP_NAME) {
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

    // FIPS 203 private keys embed the public key followed by its SHA3-256 hash
    const embeddedHash = privateKeyBytes.subarray(
        ML_KEM_768_PUBLIC_KEY_OFFSET + ML_KEM_768_PUBLIC_KEY_LENGTH,
        ML_KEM_768_PUBLIC_KEY_OFFSET + ML_KEM_768_PUBLIC_KEY_LENGTH + SHA256_OUTPUT_LENGTH
    );
    const publicKeyHash = crypto.createHash('sha3-256').update(extractMLKEMPublicKey(privateKeyBytes)).digest();
    if (!publicKeyHash.equals(embeddedHash)) {
        throw new Error('Invalid ML-KEM-768 private key: integrity check failed (the key file is damaged)');
    }

    return new Uint8Array(privateKeyBytes);
}

/**
 * Extract the ML-KEM-768 public key embedded in a FIPS 203 private key
 *
 * @param {Uint8Array} privateKey - ML-KEM-768 private key (2400 bytes)
 * @returns {Buffer} - ML-KEM-768 public key (1184 bytes)
 */
function extractMLKEMPublicKey(privateKey) {
    return Buffer.from(privateKey).subarray(
        ML_KEM_768_PUBLIC_KEY_OFFSET,
        ML_KEM_768_PUBLIC_KEY_OFFSET + ML_KEM_768_PUBLIC_KEY_LENGTH
    );
}

/**
 * Compute the recipient key identifier ("kid") the app writes for an ML-KEM-768 key
 * Format: "ML-KEM-768:" + hex(first 8 bytes of SHA-256(public key))
 *
 * @param {Uint8Array} privateKey - ML-KEM-768 private key (2400 bytes)
 * @returns {string} - Key identifier
 */
function mlKemKeyId(privateKey) {
    const fingerprint = crypto.createHash('sha256').update(extractMLKEMPublicKey(privateKey)).digest();
    return `${ML_KEM_768_RECIPIENT_TYPE}:${fingerprint.subarray(0, KEY_FINGERPRINT_LENGTH).toString('hex')}`;
}

// ============================================================================
// ARWEAVE GRAPHQL QUERIES
// ============================================================================

const USER_TRANSACTIONS_QUERY = `
    query ($appName: String!, $userId: String!, $first: Int!, $after: String) {
        transactions(
            tags: [
                { name: "App-Name", values: [$appName] },
                { name: "UserId", values: [$userId] }
            ],
            first: $first,
            after: $after
        ) {
            pageInfo {
                hasNextPage
            }
            edges {
                cursor
                node {
                    id
                }
            }
        }
    }
`;

/**
 * List the IDs of all Q-Ledger transactions tagged with a UserId, across all result pages and gateways
 *
 * Gateway indexes can be incomplete: one may omit older transactions and still report no further pages.
 * Every gateway is therefore queried and the results are merged; only if all of them fail is an error thrown.
 * Tags can be set by anyone, so the result may include transactions that are not the user's;
 * use selectUserWallets() to keep only those encrypted to the user's key.
 *
 * @param {string} userId - User identifier (UUID)
 * @returns {Promise<string[]>} - Transaction IDs, in the first answering gateway's order (newest first)
 */
async function queryTransactionIdsByUserId(userId) {
    const results = await Promise.allSettled(
        ARWEAVE_GATEWAYS.map(gateway => queryGatewayTransactionIds(gateway, userId))
    );

    const failures = [];
    const txIds = [];
    const seen = new Set();

    results.forEach((result, index) => {
        if (result.status === 'rejected') {
            failures.push(`${ARWEAVE_GATEWAYS[index]}: ${describeRequestError(result.reason)}`);
            return;
        }
        for (const txId of result.value) {
            if (!seen.has(txId)) {
                seen.add(txId);
                txIds.push(txId);
            }
        }
    });

    if (failures.length === ARWEAVE_GATEWAYS.length) {
        throw new Error(`Failed to query Arweave on all gateways:\n  ${failures.join('\n  ')}`);
    }

    return txIds;
}

/**
 * List all matching transaction IDs from one gateway, following its pagination cursors
 *
 * @param {string} gateway - Gateway base URL
 * @param {string} userId - User identifier (UUID)
 * @returns {Promise<string[]>} - Transaction IDs
 */
async function queryGatewayTransactionIds(gateway, userId) {
    const txIds = [];
    let after = null;

    do {
        const response = await axios.post(
            `${gateway}/graphql`,
            {
                query: USER_TRANSACTIONS_QUERY,
                variables: { appName: APP_NAME, userId, first: GRAPHQL_PAGE_SIZE, after }
            },
            {
                headers: { 'Content-Type': 'application/json' },
                timeout: HTTP_TIMEOUT_MS
            }
        );

        if (response.data?.errors) {
            throw new Error(`GraphQL errors: ${JSON.stringify(response.data.errors)}`);
        }

        const transactions = response.data?.data?.transactions;
        if (!transactions) {
            throw new Error('Empty GraphQL response');
        }

        txIds.push(...transactions.edges.map(edge => edge.node.id));

        const lastEdge = transactions.edges[transactions.edges.length - 1];
        after = transactions.pageInfo?.hasNextPage && lastEdge ? lastEdge.cursor : null;
    } while (after);

    return txIds;
}

/**
 * Discover the user's wallets on Arweave
 *
 * @param {object} keyData - Parsed key file data
 * @param {Uint8Array} mlkemPrivateKey - ML-KEM-768 private key
 * @returns {Promise<{wallets: Array, ignoredCount: number, searchError: string|null}>} - The user's wallets, the number of
 *   unrelated transactions skipped, and why the search failed if only key-file wallets could be listed
 */
async function discoverWallets(keyData, mlkemPrivateKey) {
    // Wallets listed in the key file are fetched by ID even if no gateway's search returned them
    const keyFileTxIds = (keyData.wallets || []).map(w => w.arweaveTransactionId).filter(Boolean);

    let searchedTxIds = [];
    let searchError = null;
    try {
        searchedTxIds = await queryTransactionIdsByUserId(keyData.userIdentifier);
    } catch (error) {
        if (keyFileTxIds.length === 0) {
            throw error;
        }
        searchError = error.message;
    }

    const txIds = [...new Set([...searchedTxIds, ...keyFileTxIds])];

    const fetched = await mapWithConcurrency(txIds, FETCH_CONCURRENCY, async (txId) => {
        try {
            return { txId, envelope: await retrieveFromArweave(txId) };
        } catch (error) {
            return { txId, envelope: null, error: error.message };
        }
    });

    return { ...selectUserWallets(fetched, mlkemPrivateKey, keyData), searchError };
}

/**
 * Keep only the transactions that belong to the user
 *
 * Anyone can upload data carrying the user's UserId tag, and recipient key identifiers are public,
 * so a transaction absent from the key file is accepted only if it decrypts with the user's key.
 * Without the user's public key (which is never published) nobody else can produce such a backup.
 * Transactions that could not be fetched are kept so a gateway error never hides a wallet.
 *
 * @param {Array} fetched - Objects with txId, envelope (or null) and optional error
 * @param {Uint8Array} mlkemPrivateKey - ML-KEM-768 private key
 * @param {object} keyData - Parsed key file data
 * @returns {{wallets: Array, ignoredCount: number}}
 */
function selectUserWallets(fetched, mlkemPrivateKey, keyData) {
    const knownTxIds = new Set((keyData.wallets || []).map(w => w.arweaveTransactionId));
    const expectedKid = mlKemKeyId(mlkemPrivateKey);
    const wallets = [];
    let ignoredCount = 0;

    for (const { txId, envelope, error } of fetched) {
        if (!envelope) {
            wallets.push({ txId, metadata: null, envelope: null, fetchError: error || 'Unknown error' });
        } else if (knownTxIds.has(txId) || isEncryptedToKey(envelope, expectedKid, mlkemPrivateKey)) {
            const metadata = envelope.metadata && typeof envelope.metadata === 'object' ? envelope.metadata : null;
            wallets.push({ txId, metadata, envelope });
        } else {
            ignoredCount++;
        }
    }

    return { wallets, ignoredCount };
}

/**
 * Check that an envelope authenticates under the user's ML-KEM-768 key
 *
 * @param {object} envelope - Data from Arweave (untrusted)
 * @param {string} expectedKid - The user's ML-KEM-768 key identifier
 * @param {Uint8Array} mlkemPrivateKey - ML-KEM-768 private key
 * @returns {boolean} - True if the envelope decrypts with the key
 */
function isEncryptedToKey(envelope, expectedKid, mlkemPrivateKey) {
    if (!findMLKEMRecipient(envelope, expectedKid)) {
        return false;
    }

    try {
        decryptWallet(envelope, mlkemPrivateKey);
        return true;
    } catch (error) {
        return false;
    }
}

/**
 * Find the ML-KEM-768 recipient entry in an envelope
 *
 * @param {object} envelope - Data from Arweave (untrusted)
 * @param {string} [kid] - Only match a recipient with this key identifier
 * @returns {object|undefined} - Recipient entry
 */
function findMLKEMRecipient(envelope, kid) {
    if (!envelope || !Array.isArray(envelope.recipients)) {
        return undefined;
    }
    return envelope.recipients.find(r =>
        r && typeof r === 'object' && r.type === ML_KEM_768_RECIPIENT_TYPE && (kid === undefined || r.kid === kid)
    );
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
    const failures = [];

    for (const gateway of ARWEAVE_GATEWAYS) {
        try {
            const response = await axios.get(`${gateway}/${txId}`, {
                timeout: HTTP_TIMEOUT_MS,
                headers: { 'Accept': 'application/json' }
            });

            if (!response.data || typeof response.data !== 'object') {
                throw new Error('No data returned from Arweave');
            }

            return response.data;

        } catch (error) {
            failures.push(`${gateway}: ${describeRequestError(error)}`);
        }
    }

    throw new Error(`Failed to retrieve ${txId} from all gateways:\n  ${failures.join('\n  ')}`);
}

/**
 * Describe an HTTP request failure in user-facing terms
 *
 * @param {Error} error - Axios or other error
 * @returns {string} - Description
 */
function describeRequestError(error) {
    if (error.response) {
        if (error.response.status === 404) {
            return 'Transaction not found (it may not be indexed yet)';
        } else if (error.response.status === 429) {
            return 'Rate limit exceeded';
        }
        return `HTTP ${error.response.status} ${error.response.statusText}`;
    } else if (error.code === 'ECONNABORTED') {
        return 'Request timed out';
    }
    return error.message;
}

/**
 * Map over items with at most `limit` promises in flight, preserving order
 *
 * @param {Array} items - Items to process
 * @param {number} limit - Maximum concurrent operations
 * @param {Function} fn - Async mapping function
 * @returns {Promise<Array>} - Results in input order
 */
async function mapWithConcurrency(items, limit, fn) {
    const results = new Array(items.length);
    let next = 0;

    const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
        while (next < items.length) {
            const index = next++;
            results[index] = await fn(items[index]);
        }
    });

    await Promise.all(workers);
    return results;
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
 * @param {object} format - Entry of ENVELOPE_FORMATS
 * @returns {Buffer} - Decrypted symmetric key (32 bytes for AES-256)
 */
function decryptSymmetricKey(wrappedKey, encapsulatedKey, recipient, privateKey, format) {
    // Step 1: Decapsulate to get shared secret (quantum-safe KEM)
    const sharedSecret = ml_kem768.decapsulate(encapsulatedKey, privateKey);

    // Step 2: Derive encryption key using HKDF-SHA256
    const info = Buffer.from(format.wrapInfo(recipient.kid), 'utf8');
    const salt = Buffer.from(recipient.salt, 'base64');
    const encryptionKey = hkdf(Buffer.from(sharedSecret), salt, info, 32);

    // Step 3: Extract nonce, tag, and ciphertext from wrapped key
    const nonce = wrappedKey.subarray(0, GCM_NONCE_LENGTH);
    const tag = wrappedKey.subarray(-GCM_TAG_LENGTH);
    const ciphertext = wrappedKey.subarray(GCM_NONCE_LENGTH, -GCM_TAG_LENGTH);

    // Step 4: Build AAD (Additional Authenticated Data)
    // Format: "recV={recV}|kid={kid}|type={type}|kem_hash={kemHash}|nonce={wrapNonce}"
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
}

/**
 * Decrypt the wallet payload using the symmetric key
 *
 * @param {object} arweaveData - DualRecipientEncryptedData from Arweave
 * @param {Buffer} symmetricKey - Decrypted AES-256 symmetric key
 * @param {object} format - Entry of ENVELOPE_FORMATS
 * @returns {Buffer} - Decrypted wallet data
 */
function decryptWalletPayload(arweaveData, symmetricKey, format) {
    const payloadAAD = Buffer.from(
        format.payloadAAD(arweaveData.version, arweaveData.recipients.length),
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
}

/**
 * Check if wallet has ML-KEM-768 recipient (Pro version)
 *
 * @param {object} arweaveData - Data from Arweave
 * @returns {boolean} - True if wallet has ML-KEM-768 recipient
 */
function hasMLKEMRecipient(arweaveData) {
    return findMLKEMRecipient(arweaveData) !== undefined;
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
    const mlkemRecipient = findMLKEMRecipient(arweaveData);
    if (!mlkemRecipient) {
        throw new Error('No ML-KEM-768 recipient found. This wallet was created with Q-Ledger Standard (non-Pro) version and can only be decrypted in the Q-Ledger iOS app.');
    }

    const wrappedKey = Buffer.from(mlkemRecipient.wrappedK, 'base64');
    const encapsulatedKey = Buffer.from(mlkemRecipient.kem_ct, 'base64');

    const recipient = {
        recV: mlkemRecipient.recV,
        kid: mlkemRecipient.kid,
        type: mlkemRecipient.type,
        salt: mlkemRecipient.salt
    };

    // Authenticated decryption fails for every format except the one the wallet was written in
    for (const format of ENVELOPE_FORMATS) {
        let symmetricKey;
        try {
            symmetricKey = decryptSymmetricKey(wrappedKey, encapsulatedKey, recipient, mlkemPrivateKey, format);
        } catch (error) {
            continue;
        }

        try {
            return decryptWalletPayload(arweaveData, symmetricKey, format);
        } catch (error) {
            throw new Error(`Failed to decrypt wallet payload: the data is damaged (${error.message})`);
        }
    }

    throw new Error('Failed to decrypt wallet: it is not encrypted to the ML-KEM-768 key in this key file, or the data is damaged.');
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
 * The file is readable only by the current user and never overwrites an existing file;
 * wallets with the same name are saved as name-2, name-3, and so on.
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
        .substring(0, MAX_FILENAME_LENGTH)   // Limit length for filesystem compatibility
        || 'wallet';

    const walletsDir = path.join(process.cwd(), 'wallets');

    // Ensure directory exists
    await fs.mkdir(walletsDir, { recursive: true, mode: 0o700 });

    for (let copy = 1; ; copy++) {
        const filename = copy === 1 ? `${sanitizedName}.${extension}` : `${sanitizedName}-${copy}.${extension}`;
        const outputPath = path.join(walletsDir, filename);

        try {
            await fs.writeFile(outputPath, walletData, { flag: 'wx', mode: 0o600 });
        } catch (error) {
            if (error.code === 'EEXIST') {
                continue;
            }
            throw error;
        }

        console.log(`✓ Wallet saved to: ${outputPath}\n`);
        return outputPath;
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
    // Key management
    loadKeyFile,
    loadMLKEMKey,
    mlKemKeyId,

    // Arweave
    queryTransactionIdsByUserId,
    discoverWallets,
    selectUserWallets,
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
    ARWEAVE_GATEWAYS
};

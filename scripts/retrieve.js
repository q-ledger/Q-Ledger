#!/usr/bin/env node

/**
 * Q-Ledger Wallet Retrieval Script
 *
 * Retrieves and decrypts wallet backups from Arweave using ML-KEM-768 keys
 *
 * Usage:
 *   node retrieve.js
 *
 * Public domain - released under CC0-1.0
 */

const readline = require('readline');
const {
    loadKeyFile,
    loadMLKEMKey,
    queryArweaveByUserId,
    retrieveFromArweave,
    decryptWallet,
    getWalletStatus,
    getWalletMetadata,
    saveWallet
} = require('./utils');

// ============================================================================
// USER INPUT UTILITIES
// ============================================================================

/**
 * Create readline interface for user input
 */
function createReadlineInterface() {
    return readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
}

/**
 * Prompt user for input
 *
 * @param {object} rl - Readline interface
 * @param {string} question - Question to ask
 * @returns {Promise<string>} - User's answer
 */
function askQuestion(rl, question) {
    return new Promise(resolve => {
        rl.question(question, answer => {
            resolve(answer.trim());
        });
    });
}

// ============================================================================
// DISPLAY UTILITIES
// ============================================================================

/**
 * Display header
 */
function displayHeader() {
    console.log('\n===============================================');
    console.log('  Q-Ledger Wallet Retrieval Tool');
    console.log('  Decrypt wallet backups from Arweave');
    console.log('===============================================\n');
}

/**
 * Format wallet status for display
 *
 * @param {string} status - Wallet status ('active', 'revoked', or 'recovered')
 * @returns {string} - Formatted status string
 */
function formatWalletStatus(status) {
    if (status === 'active') {
        return '✓ Active';
    } else if (status === 'revoked') {
        return '✗ Revoked';
    } else {
        return '◆ Recovered';
    }
}

/**
 * Format creation date for display
 *
 * @param {string} dateCreated - ISO 8601 date string
 * @returns {string} - Formatted date string or empty string
 */
function formatCreationDate(dateCreated) {
    if (!dateCreated) {
        return '';
    }

    const date = new Date(dateCreated);
    const [datePart, timePart] = date.toISOString().split('T');
    return ` (${datePart} ${timePart.substring(0, 5)})`;
}

/**
 * Display wallet list in formatted table
 *
 * @param {Array} wallets - Array of wallet objects with txId and metadata
 * @param {object} keyData - Parsed key file data
 */
function displayWalletList(wallets, keyData) {
    console.log('WALLETS FOUND ON ARWEAVE');
    console.log('=========================\n');

    if (wallets.length === 0) {
        console.log('No wallets found on Arweave for this user identifier.\n');
        return;
    }

    console.log(`Total: ${wallets.length} wallet(s)\n`);

    // Display wallets
    wallets.forEach((wallet, index) => {
        const txId = wallet.txId;
        const status = getWalletStatus(txId, keyData);
        const metadata = getWalletMetadata(txId, keyData, wallet.metadata);
        const walletName = metadata?.walletName || 'Unknown';
        const keyFormat = metadata?.keyFormat || 'Unknown';

        const statusDisplay = formatWalletStatus(status);
        const dateDisplay = formatCreationDate(metadata?.dateCreated);
        const num = String(index + 1).padStart(2);

        console.log(`[${num}] ${statusDisplay.padEnd(12)} ${walletName} - ${keyFormat}${dateDisplay}`);
        console.log(`     ${txId}`);
        console.log('');
    });

    // Legend
    console.log('Status Legend:');
    console.log('  ✓ Active    - Wallet is active in your key file');
    console.log('  ✗ Revoked   - Wallet has been revoked');
    console.log('  ◆ Recovered - Wallet found on Arweave but not in your local key file\n');
}

/**
 * Parse wallet selection input
 *
 * @param {string} input - User input (transaction ID or number)
 * @param {Array} wallets - Array of wallet objects
 * @returns {object|null} - Selected wallet or null if invalid
 */
function parseWalletSelection(input, wallets) {
    // Check if input matches a transaction ID
    const matchingWallet = wallets.find(w => w.txId === input);
    if (matchingWallet) {
        return matchingWallet;
    }

    // Check if input is a valid wallet number
    const num = parseInt(input);
    if (!isNaN(num) && num >= 1 && num <= wallets.length) {
        return wallets[num - 1];
    }

    return null;
}

/**
 * Display wallet metadata before decryption
 *
 * @param {string} txId - Arweave transaction ID
 * @param {object} keyData - Parsed key file data
 * @param {object|null} arweaveMetadata - Metadata from Arweave (optional)
 */
function displayWalletInfo(txId, keyData, arweaveMetadata = null) {
    const metadata = getWalletMetadata(txId, keyData, arweaveMetadata);
    const status = getWalletStatus(txId, keyData);

    console.log('SELECTED WALLET');
    console.log('===============');
    console.log(`Transaction ID: ${txId}`);
    console.log(`Status: ${status}`);

    if (metadata) {
        console.log(`Name: ${metadata.walletName}`);
        console.log(`Format: ${metadata.keyFormat}`);
        console.log(`Created: ${new Date(metadata.dateCreated).toLocaleString()}`);
    }

    console.log('');
}

// ============================================================================
// MAIN RETRIEVAL WORKFLOW
// ============================================================================

/**
 * Main retrieval function
 */
async function main() {
    const rl = createReadlineInterface();

    try {
        displayHeader();

        // Load key file
        console.log('Loading Q-Ledger key file...\n');
        const keyData = await loadKeyFile();

        // Display user identifier
        console.log('User Identifier\n');
        console.log(`User ID: ${keyData.userIdentifier}\n`);

        // Query Arweave for wallets
        console.log('Querying Arweave for wallet backups...\n');
        const wallets = await queryArweaveByUserId(keyData.userIdentifier);
        console.log(`✓ Found ${wallets.length} wallet(s) on Arweave\n`);

        // Display wallet list
        console.log('Wallet List\n');
        displayWalletList(wallets, keyData);

        if (wallets.length === 0) {
            console.log('No wallets to retrieve. Exiting.\n');
            rl.close();
            return;
        }

        // Prompt user for transaction ID
        console.log('Select Wallet to Retrieve\n');

        let selectedWallet = null;
        let isValid = false;

        while (!isValid) {
            const answer = await askQuestion(
                rl,
                'Enter the Arweave transaction ID (or "q" to quit): '
            );

            if (answer.toLowerCase() === 'q') {
                console.log('\nExiting.\n');
                rl.close();
                return;
            }

            // Parse wallet selection
            selectedWallet = parseWalletSelection(answer, wallets);
            if (selectedWallet) {
                isValid = true;
            } else {
                console.log(`\n✗ Invalid input. Please enter a transaction ID from the list above, or a number (1-${wallets.length}).\n`);
            }
        }

        const selectedTxId = selectedWallet.txId;

        console.log('');
        displayWalletInfo(selectedTxId, keyData, selectedWallet.metadata);

        // Fetch and decrypt wallet
        console.log('Fetching and Decrypting Wallet\n');

        console.log('Fetching encrypted data from Arweave...');
        const arweaveData = await retrieveFromArweave(selectedTxId);
        console.log('✓ Data retrieved from Arweave\n');

        // Load ML-KEM key
        const mlkemPrivateKey = loadMLKEMKey(keyData);

        // Decrypt wallet
        console.log('Decrypting wallet...');
        console.log(`  Encryption version: ${arweaveData.version}`);
        console.log(`  Algorithm: ${arweaveData.algorithm}`);
        console.log(`  Recipients: ${arweaveData.recipients.length}`);
        const recipientTypes = arweaveData.recipients.map(r => r.type).join(', ');
        console.log(`  Recipient types: ${recipientTypes}\n`);

        const decryptedWallet = decryptWallet(arweaveData, mlkemPrivateKey);
        console.log('✓ Wallet decrypted successfully\n');

        // Extract wallet name and key format from metadata for file generation
        const metadata = getWalletMetadata(selectedTxId, keyData, selectedWallet.metadata);
        const walletName = metadata?.walletName || 'Unknown';
        const keyFormat = metadata?.keyFormat || 'Document';

        // Write decrypted wallet to file with appropriate extension
        const savedPath = await saveWallet(decryptedWallet, walletName, keyFormat);

        // Success message
        console.log('===============================================');
        console.log('✓ RETRIEVAL SUCCESSFUL');
        console.log('===============================================\n');
        console.log(`Wallet decrypted and saved to:\n${savedPath}\n`);
        console.log('⚠️  SECURITY WARNINGS:\n');
        console.log('1. The decrypted file contains sensitive data in plaintext');
        console.log('2. Import it into secure wallet software IMMEDIATELY');
        console.log('3. DELETE the decrypted file after importing');
        console.log('4. Never share the decrypted file with anyone\n');
        console.log('===============================================\n');

        rl.close();

    } catch (error) {
        console.error('\n✗ ERROR:\n');
        console.error(error.message);
        console.error('\n');
        rl.close();
        process.exit(1);
    }
}

// Run the script
if (require.main === module) {
    main().catch(error => {
        console.error('Unexpected error:', error);
        process.exit(1);
    });
}

module.exports = { main };

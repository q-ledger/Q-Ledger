/**
 * Tests for the Q-Ledger retrieval utilities
 *
 * Run with: npm test (Node.js 18 or later)
 *
 * Public domain - released under CC0-1.0
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const axios = require('axios');
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
const {
    loadMLKEMKey,
    mlKemKeyId,
    queryTransactionIdsByUserId,
    discoverWallets,
    selectUserWallets,
    decryptWallet,
    saveWallet,
    ARWEAVE_GATEWAYS
} = require('../scripts/utils');

const FIXTURES = path.join(__dirname, 'fixtures');
const readFixture = (name) => fs.readFileSync(path.join(FIXTURES, name), 'utf8');

const keyData = JSON.parse(readFixture('test-vector-keyfile.json'));
const currentEnvelope = JSON.parse(readFixture('envelope-current.json'));
const legacyEnvelope = JSON.parse(readFixture('envelope-legacy.json'));
const plaintext = readFixture('plaintext.txt');

test('decrypts a wallet in the current app format', () => {
    const decrypted = decryptWallet(currentEnvelope, loadMLKEMKey(keyData));
    assert.equal(decrypted.toString('utf8'), plaintext);
});

test('decrypts a wallet in the legacy app format', () => {
    const decrypted = decryptWallet(legacyEnvelope, loadMLKEMKey(keyData));
    assert.equal(decrypted.toString('utf8'), plaintext);
});

test('rejects a wallet when the key file holds a different key', () => {
    const { secretKey } = ml_kem768.keygen();
    assert.throws(() => decryptWallet(currentEnvelope, secretKey), /not encrypted to the ML-KEM-768 key/);
});

test('rejects a tampered payload', () => {
    const tampered = structuredClone(currentEnvelope);
    const ciphertext = Buffer.from(tampered.ciphertext, 'base64');
    ciphertext[0] ^= 0x01;
    tampered.ciphertext = ciphertext.toString('base64');
    assert.throws(() => decryptWallet(tampered, loadMLKEMKey(keyData)), /data is damaged/);
});

test('rejects a damaged ML-KEM key file', () => {
    const secretKey = Buffer.from(keyData.mlKemSecretKey, 'base64');
    secretKey[1500] ^= 0x01;
    assert.throws(
        () => loadMLKEMKey({ ...keyData, mlKemSecretKey: secretKey.toString('base64') }),
        /integrity check failed/
    );
});

test('computes the same key identifier the app writes', () => {
    const recipient = currentEnvelope.recipients.find(r => r.type === 'ML-KEM-768');
    assert.equal(mlKemKeyId(loadMLKEMKey(keyData)), recipient.kid);
});

test('keeps only transactions that belong to the user', () => {
    const mlkemPrivateKey = loadMLKEMKey(keyData);
    const genuineRecipient = currentEnvelope.recipients.find(r => r.type === 'ML-KEM-768');

    const otherKey = structuredClone(currentEnvelope);
    otherKey.recipients[1].kid = 'ML-KEM-768:0000000000000000';

    // The kid is public, so it can be copied into an envelope the user's key does not decrypt
    const copiedKid = {
        version: 1,
        ciphertext: 'AAAA',
        nonce: 'AAAAAAAAAAAAAAAA',
        tag: 'AAAAAAAAAAAAAAAAAAAAAA==',
        recipients: [{ recV: 1, type: 'ML-KEM-768', kid: genuineRecipient.kid, kem_ct: 'AAAA', salt: 'AAAA', wrappedK: 'AAAA' }]
    };

    // A genuine recipient entry copied next to a forged payload unwraps, but the payload does not authenticate
    const copiedRecipient = structuredClone(currentEnvelope);
    copiedRecipient.ciphertext = Buffer.from('forged payload').toString('base64');

    const malformed = { recipients: [null, 42, 'x'], metadata: 'not an object' };
    const standardOnly = { ...structuredClone(currentEnvelope), recipients: [currentEnvelope.recipients[0]] };

    const fetched = [
        { txId: 'other-key', envelope: otherKey },
        { txId: 'copied-kid', envelope: copiedKid },
        { txId: 'copied-recipient', envelope: copiedRecipient },
        { txId: 'malformed', envelope: malformed },
        { txId: 'mine', envelope: currentEnvelope },
        { txId: 'unrelated-standard', envelope: standardOnly },
        { txId: 'listed-standard', envelope: standardOnly },
        { txId: 'unreachable', envelope: null, error: 'Request timed out' }
    ];
    const listed = { ...keyData, wallets: [{ arweaveTransactionId: 'listed-standard' }] };

    const { wallets, ignoredCount } = selectUserWallets(fetched, mlkemPrivateKey, listed);

    assert.deepEqual(wallets.map(w => w.txId), ['mine', 'listed-standard', 'unreachable']);
    assert.equal(wallets[0].metadata.walletName, 'Test Vector Wallet');
    assert.equal(wallets[2].fetchError, 'Request timed out');
    assert.equal(ignoredCount, 5);
});

function graphqlResponse(edges, hasNextPage) {
    return { data: { data: { transactions: { edges, pageInfo: { hasNextPage } } } } };
}

const edge = (id, cursor = id) => ({ cursor, node: { id } });

test('merges transactions from all gateways when one index is incomplete', async (t) => {
    const [incomplete, complete, failing] = ARWEAVE_GATEWAYS;
    const requests = [];
    t.mock.method(axios, 'post', async (url, body) => {
        requests.push({ url, variables: body.variables });
        if (url.startsWith(incomplete)) {
            return graphqlResponse([edge('tx1'), edge('tx2')], false);
        }
        if (url.startsWith(complete)) {
            return body.variables.after === null
                ? graphqlResponse([edge('tx1'), edge('tx2')], true)
                : graphqlResponse([edge('tx3'), edge('tx4')], false);
        }
        if (url.startsWith(failing)) {
            return { data: '' };
        }
        throw new Error(`unexpected ${url}`);
    });

    const txIds = await queryTransactionIdsByUserId('user-1');

    assert.deepEqual(txIds, ['tx1', 'tx2', 'tx3', 'tx4']);
    const completeRequests = requests.filter(r => r.url === `${complete}/graphql`);
    assert.deepEqual(completeRequests.map(r => r.variables.after), [null, 'tx2']);
    assert.deepEqual(completeRequests[0].variables, { appName: 'Q-Ledger', userId: 'user-1', first: 100, after: null });
});

test('reports an error only when every gateway fails', async (t) => {
    t.mock.method(axios, 'post', async () => ({ data: '' }));

    await assert.rejects(() => queryTransactionIdsByUserId('user-1'), /Failed to query Arweave on all gateways/);
});

test('includes key-file wallets that no gateway search returned', async (t) => {
    t.mock.method(axios, 'post', async () => graphqlResponse([], false));
    t.mock.method(axios, 'get', async (url) => {
        assert.ok(url.endsWith('/listed-tx'), url);
        return { data: currentEnvelope };
    });
    const listed = { ...keyData, wallets: [{ arweaveTransactionId: 'listed-tx' }] };

    const { wallets, searchError } = await discoverWallets(listed, loadMLKEMKey(keyData));

    assert.deepEqual(wallets.map(w => w.txId), ['listed-tx']);
    assert.equal(searchError, null);
});

test('falls back to key-file wallets when every search fails', async (t) => {
    t.mock.method(axios, 'post', async () => ({ data: '' }));
    t.mock.method(axios, 'get', async () => ({ data: currentEnvelope }));
    const listed = { ...keyData, wallets: [{ arweaveTransactionId: 'listed-tx' }] };

    const { wallets, searchError } = await discoverWallets(listed, loadMLKEMKey(keyData));

    assert.deepEqual(wallets.map(w => w.txId), ['listed-tx']);
    assert.match(searchError, /Failed to query Arweave on all gateways/);
});

test('fails discovery when every search fails and the key file lists no wallets', async (t) => {
    t.mock.method(axios, 'post', async () => ({ data: '' }));

    await assert.rejects(() => discoverWallets({ ...keyData, wallets: [] }, loadMLKEMKey(keyData)), /all gateways/);
});

test('saves wallets readable only by the user without overwriting', async (t) => {
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qledger-test-'));
    const originalCwd = process.cwd();
    process.chdir(workDir);
    t.after(() => {
        process.chdir(originalCwd);
        fs.rmSync(workDir, { recursive: true, force: true });
    });
    t.mock.method(console, 'log', () => {});

    const first = await saveWallet(Buffer.from('first'), 'My Wallet', 'BIP39 Seed Phrase');
    const second = await saveWallet(Buffer.from('second'), 'My Wallet', 'BIP39 Seed Phrase');

    assert.equal(path.basename(first), 'My_Wallet.txt');
    assert.equal(path.basename(second), 'My_Wallet-2.txt');
    assert.equal(fs.readFileSync(first, 'utf8'), 'first');
    assert.equal(fs.readFileSync(second, 'utf8'), 'second');
    if (process.platform !== 'win32') {
        assert.equal(fs.statSync(first).mode & 0o777, 0o600);
    }
});

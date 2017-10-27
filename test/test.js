let getRandomValues;
let now;
if (typeof(window) === 'undefined') {
    // we are in node
    const crypto = require('crypto');
    getRandomValues = crypto.randomFillSync.bind(crypto);
    now = () => {
        const [seconds, nanos] = process.hrtime();
        return seconds * 1000 + nanos / 1000000;
    };

    ED25519_DIST_PATH = './dist/';
    ED25519 = require('../ed25519.js');
} else {
    getRandomValues = window.crypto.getRandomValues.bind(window.crypto);
    now = performance.now.bind(performance);
}

async function test() {
    console.log(`Test with${typeof(WebAssembly)!=='undefined'?'':'out'} WebAssembly support.`);

    const public_key = new Uint8Array(32),
        private_key = new Uint8Array(64),
        seed = new Uint8Array(32),
        scalar = new Uint8Array(32),
        other_public_key = new Uint8Array(32),
        other_private_key = new Uint8Array(64),
        shared_secret = new Uint8Array(32),
        other_shared_secret = new Uint8Array(32),
        signature = new Uint8Array(64);
    let start, end, i;
    const message = Uint8Array.from('Hello world.'.split('').map(c => c.charCodeAt(0)));
    const message_len = message.byteLength;

    /* create a random seed, and a keypair out of that seed */
    getRandomValues(seed);
    await ED25519.createKeyPair(public_key, private_key, seed);

    /* create signature on the message with the keypair */
    await ED25519.sign(signature, message, message_len, public_key, private_key);

    /* verify the signature */
    if (await ED25519.verify(signature, message, message_len, public_key)) {
        console.log("valid signature");
    } else {
        throw Error("invalid signature");
    }

    /* create scalar and add it to the keypair */
    getRandomValues(scalar);
    await ED25519.addScalar(public_key, private_key, scalar);

    /* create signature with the new keypair */
    await ED25519.sign(signature, message, message_len, public_key, private_key);

    /* verify the signature with the new keypair */
    if (await ED25519.verify(signature, message, message_len, public_key)) {
        console.log("valid signature\n");
    } else {
        throw Error("invalid signature\n");
    }

    /* make a slight adjustment and verify again */
    signature[44] ^= 0x10;
    if (await ED25519.verify(signature, message, message_len, public_key)) {
        throw Error("did not detect signature change\n");
    } else {
        console.log("correctly detected signature change\n");
    }

    /* generate two keypairs for testing key exchange */
    getRandomValues(seed);
    await ED25519.createKeyPair(public_key, private_key, seed);
    getRandomValues(seed);
    await ED25519.createKeyPair(other_public_key, other_private_key, seed);

    /* create two shared secrets - from both perspectives - and check if they're equal */
    await ED25519.keyExchange(shared_secret, other_public_key, private_key);
    await ED25519.keyExchange(other_shared_secret, public_key, other_private_key);

    for (i = 0; i < 32; ++i) {
        if (shared_secret[i] != other_shared_secret[i]) {
            throw Error("key exchange was incorrect\n");
        }
    }
    console.log("key exchange was correct\n");


    /* test performance */
    console.log('Performance tests (times in micro seconds):')
    console.log("testing seed generation performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        getRandomValues(seed);
    }
    end = now();
    console.log("per seed:", (end - start) * 1000 / i);

    console.log("testing key generation performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        await ED25519.createKeyPair(public_key, private_key, seed);
    }
    end = now();
    console.log("per keypair", (end - start) * 1000 / i);

    console.log("testing sign performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        await ED25519.sign(signature, message, message_len, public_key, private_key);
    }
    end = now();
    console.log("per signature", (end - start) * 1000 / i);

    console.log("testing verify performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        await ED25519.verify(signature, message, message_len, public_key);
    }
    end = now();
    console.log("per verification", (end - start) * 1000 / i);

    console.log("testing keypair scalar addition performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        await ED25519.addScalar(public_key, private_key, scalar);
    }
    end = now();
    console.log("per scalar addition", (end - start) * 1000 / i);

    console.log("testing public key scalar addition performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        await ED25519.addScalar(public_key, null, scalar);
    }
    end = now();
    console.log("per public key scalar addition", (end - start) * 1000 / i);

    console.log("testing key exchange performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        await ED25519.keyExchange(shared_secret, other_public_key, private_key);
    }
    end = now();
    console.log("per shared secret", (end - start) * 1000 / i);

    console.log("testing overhead by copy to the webassembly memory");
    start = now();
    for (i = 0; i < 10000; ++i) {
        ED25519._pubKeyBuffer.set(public_key);
        ED25519._privKeyBuffer.set(private_key);
        ED25519._signatureBuffer.set(signature);
    }
    end = now();
    console.log("per copy of publicKey + privateKey + signature", (end - start) * 1000 / i);

    /*
    console.log("testing overhead for stackSave + stackAlloc + stackRestore");
    start = now();
    for (i = 0; i < 10000; ++i) {
        const stack = ED25519._handler.stackSave();
        ED25519._handler.stackAlloc(128);
        ED25519._handler.stackRestore(stack);
    }
    end = now();
    console.log("per stackSave + stackAlloc + stackRestore", (end - start) * 1000 / i);

    const testBuffer = new Uint8Array(256);
    console.log("testing overhead for typed array creation");
    start = now();
    for (i = 0; i < 10000; ++i) {
        const priv = new Uint8Array(testBuffer.buffer, 17, 64);
        const pub = new Uint8Array(testBuffer.buffer, 83, 32);
        const sign = new Uint8Array(testBuffer.buffer, 115, 64);
    }
    end = now();
    console.log("per buffer creation for priv + pub + signature", (end - start) * 1000 / i);  
    */
}

const timeout = setTimeout(() => {}, 10 * 60 * 1000); // timeout to keep node.js alive
test()
.then(() => {
    console.log('tests finished.');
    clearTimeout(timeout);
})
.catch(() => {
    console.error('an exception was thrown.');
    clearTimeout(timeout);
});
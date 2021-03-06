'use strict';

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
    global.ED25519 = require('../ed25519.js');
    ED25519.setPath('./dist/');
} else {
    getRandomValues = window.crypto.getRandomValues.bind(window.crypto);
    now = performance.now.bind(performance);
    ED25519.setPath('../dist/');
}

async function test() {
    console.log(`Test with${typeof(WebAssembly)!=='undefined'?'':'out'} WebAssembly support.`);

    const public_key = new Uint8Array(32),
        private_key = new Uint8Array(32),
        scalar = new Uint8Array(32),
        other_public_key = new Uint8Array(32),
        other_private_key = new Uint8Array(64),
        shared_secret = new Uint8Array(32),
        other_shared_secret = new Uint8Array(32),
        signature = new Uint8Array(64);
    let start, end, time, i;
    const message = Uint8Array.from('Hello world.'.split('').map(c => c.charCodeAt(0)));

    /* create a random private key and derive the public key */
    getRandomValues(private_key);
    await ED25519.derivePublicKey(public_key, private_key);

    /* create signature on the message with the keypair */
    await ED25519.sign(signature, message, public_key, private_key);

    /* verify the signature */
    if (await ED25519.verify(signature, message, public_key)) {
        console.log("valid signature");
    } else {
        throw Error("invalid signature");
    }

    /* make a slight adjustment and verify again */
    signature[44] ^= 0x10;
    if (await ED25519.verify(signature, message, public_key)) {
        throw Error("did not detect signature change\n");
    } else {
        console.log("correctly detected signature change\n");
    }


    /* test performance */

    console.log('Performance tests (times in micro seconds):')
    console.log("testing private key generation performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        getRandomValues(private_key);
    }
    end = now();
    time = (end - start) * 1000 / i;
    console.log("per private key:", time, '- executions per second:', Math.floor(1000000 / time));

    console.log("testing public key derivation performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        await ED25519.derivePublicKey(public_key, private_key);
    }
    end = now();
    time = (end - start) * 1000 / i;
    console.log("per derivation", time, '- executions per second:', Math.floor(1000000 / time));

    console.log("testing sign performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        await ED25519.sign(signature, message, public_key, private_key);
    }
    end = now();
    time = (end - start) * 1000 / i
    console.log("per signature", time, '- executions per second:', Math.floor(1000000 / time));

    console.log("testing verify performance: ");
    start = now();
    for (i = 0; i < 10000; ++i) {
        await ED25519.verify(signature, message, public_key);
    }
    end = now();
    time = (end - start) * 1000 / i;
    console.log("per verification", time, '- executions per second:', Math.floor(1000000 / time));

    console.log("testing overhead by copy to the webassembly memory");
    start = now();
    for (i = 0; i < 10000; ++i) {
        ED25519._properties.pubKeyBuffer.set(public_key);
        ED25519._properties.privKeyBuffer.set(private_key);
        ED25519._properties.signatureBuffer.set(signature);
    }
    end = now();
    time = (end - start) * 1000 / i;
    console.log("per copy of publicKey + privateKey + signature", time, '- executions per second:', Math.floor(1000000 / time));

   /* 
    console.log("testing overhead for stackSave + stackAlloc + stackRestore");
    start = now();
    for (i = 0; i < 10000; ++i) {
        const stack = ED25519._handler.stackSave();
        ED25519._handler.stackAlloc(128);
        ED25519._handler.stackRestore(stack);
    }
    end = now();
    time = (end - start) * 1000 / i;
    console.log("per stackSave + stackAlloc + stackRestore", time, '- executions per second:', Math.floor(1000000 / time));

    const testBuffer = new Uint8Array(256);
    console.log("testing overhead for typed array creation");
    start = now();
    for (i = 0; i < 10000; ++i) {
        const priv = new Uint8Array(testBuffer.buffer, 17, 64);
        const pub = new Uint8Array(testBuffer.buffer, 83, 32);
        const sign = new Uint8Array(testBuffer.buffer, 115, 64);
    }
    end = now();
    time = (end - start) * 1000 / i;
    console.log("per buffer creation for priv + pub + signature", time, '- executions per second:', Math.floor(1000000 / time));
    */
}

if (typeof window === 'undefined') {
    // in nodejs trigger the tests directly from the js file
    const timeout = setTimeout(() => {}, 10 * 60 * 1000); // timeout to keep node.js alive
    test()
    .then(() => {
        console.log('tests finished.');
        clearTimeout(timeout);
    })
    .catch(e => {
        console.error('an exception was thrown.', e);
        clearTimeout(timeout);
    });
}

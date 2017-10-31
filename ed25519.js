class ED25519 {
    static async _awaitHandler() {
        if (!ED25519._handlerPromise) {
            ED25519._handlerPromise = new Promise((resolve, reject) => {
                // load the handler
                if (typeof(document) !== 'undefined') {
                    // we are in the browser
                    var script = document.createElement('script');
                    script.onload = resolve;
                    script.onerror = reject;
                    script.src = ED25519.DIST_PATH + (typeof(WebAssembly)!=='undefined'? 'ed25519-wasm.js' : 'ed25519-asm.js');
                    document.body.appendChild(script);
                } else {
                    // we are in node
                    global.ED25519_HANDLER = require(ED25519.DIST_PATH + (typeof(WebAssembly)!=='undefined'? 'ed25519-wasm.js' : 'ed25519-asm.js'));
                    resolve();
                }
            })
            .then(() => new Promise((resolve, reject) => {
                ED25519._handler = ED25519_HANDLER({
                    wasmBinaryFile: '../' + ED25519.DIST_PATH + 'ed25519-wasm.wasm',
                    memoryInitializerPrefixURL: '../' + ED25519.DIST_PATH
                });
                // wait until the handler is ready
                ED25519._handler.onRuntimeInitialized = resolve;
            }))
            .then(() => {
                console.log('got the handler');
                const memoryStart = ED25519._handler._get_static_memory_start();
                const memorySize = ED25519._handler._get_static_memory_size();
                if (memorySize < ED25519.SEED_SIZE + ED25519.PUBLIC_KEY_SIZE + ED25519.PRIVATE_KEY_SIZE
                    + ED25519.SIGNATURE_SIZE + ED25519.SCALAR_SIZE + ED25519.SECRET_SIZE) {
                    throw Error('Static memory too small');
                }
                let byteOffset = memoryStart;
                ED25519._seedPointer = byteOffset;
                ED25519._seedBuffer = new Uint8Array(ED25519._handler.HEAP8.buffer, byteOffset, ED25519.SEED_SIZE);
                byteOffset += ED25519.SEED_SIZE;
                ED25519._pubKeyPointer = byteOffset;
                ED25519._pubKeyBuffer = new Uint8Array(ED25519._handler.HEAP8.buffer, byteOffset, ED25519.PUBLIC_KEY_SIZE);
                byteOffset += ED25519.PUBLIC_KEY_SIZE;
                ED25519._privKeyPointer = byteOffset;
                ED25519._privKeyBuffer = new Uint8Array(ED25519._handler.HEAP8.buffer, byteOffset, ED25519.PRIVATE_KEY_SIZE);
                byteOffset += ED25519.PRIVATE_KEY_SIZE;
                ED25519._signaturePointer = byteOffset;
                ED25519._signatureBuffer = new Uint8Array(ED25519._handler.HEAP8.buffer, byteOffset, ED25519.SIGNATURE_SIZE);
                byteOffset += ED25519.SIGNATURE_SIZE;
                ED25519._scalarPointer = byteOffset;
                ED25519._scalarBuffer = new Uint8Array(ED25519._handler.HEAP8.buffer, byteOffset, ED25519.SCALAR_SIZE);
                byteOffset += ED25519.SCALAR_SIZE;
                ED25519._secretPointer = byteOffset;
                ED25519._secretBuffer = new Uint8Array(ED25519._handler.HEAP8.buffer, byteOffset, ED25519.SECRET_SIZE);
                byteOffset += ED25519.SECRET_SIZE;
                ED25519._messagePointer = byteOffset;
                ED25519._messageBuffer = new Uint8Array(ED25519._handler.HEAP8.buffer, byteOffset, (memoryStart + memorySize) - byteOffset);
            });
        }
        return await ED25519._handlerPromise;
    }


    /**
     * Creates a new key pair from the given seed. public_key must be a writable 32 byte buffer, private key must be
     * a writable 64 byte buffer and seed must be a 32 byte buffer.
     * IMPORTANT: The private key gets deterministically computed from the seed, thus the seed is as confidential
     * as the private key.
     */
    static async createKeyPair(out_publicKey, out_privateKey, key_seed) {
        await ED25519._awaitHandler();
        if (key_seed.byteLength !== ED25519.SEED_SIZE
            || out_publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE
            || out_privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        ED25519._seedBuffer.set(key_seed);
        ED25519._handler._ed25519_create_keypair(ED25519._pubKeyPointer, ED25519._privKeyPointer, ED25519._seedPointer);
        out_publicKey.set(ED25519._pubKeyBuffer);
        out_privateKey.set(ED25519._privKeyBuffer);
        ED25519._seedBuffer.fill(0);
        ED25519._privKeyBuffer.fill(0);
    }


    /**
     * Calculate the public key for a given private key.
     */
    static async derivePublicKey(out_publicKey, privateKey) {
        await ED25519._awaitHandler();
        if (out_publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE
            || privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        ED25519._privKeyBuffer.set(privateKey);
        ED25519._handler._ed25519_public_key_derive(ED25519._pubKeyPointer, ED25519._privKeyPointer);
        out_publicKey.set(ED25519._pubKeyBuffer);
        ED25519._privKeyBuffer.fill(0);
    }


    /**
     * Creates a signature of the given message with the given key pair. signature must be a writable 64 byte buffer.
     * message must have at least message_len bytes to be read and must fit into ED25519._messageBuffer.
     */
    static async sign(out_signature, message, publicKey, privateKey) {
        await ED25519._awaitHandler();
        const messageLength = message.byteLength;
        if (out_signature.byteLength !== ED25519.SIGNATURE_SIZE
            || messageLength > ED25519._messageBuffer.byteLength
            || publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE
            || privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        ED25519._messageBuffer.set(message);
        ED25519._pubKeyBuffer.set(publicKey);
        ED25519._privKeyBuffer.set(privateKey);
        ED25519._handler._ed25519_sign(ED25519._signaturePointer, ED25519._messagePointer, messageLength,
            ED25519._pubKeyPointer, ED25519._privKeyPointer);
        out_signature.set(ED25519._signatureBuffer);
        ED25519._privKeyBuffer.fill(0);
    }


    /**
     * Verifies the signature on the given message using public_key. signature must be a readable 64 byte buffer.
     * message must have at least message_len bytes to be read and must fit ED25519._messageBuffer.
     * Returns 1 if the signature matches, 0 otherwise.
     */
    static async verify(signature, message, publicKey) {
        await ED25519._awaitHandler();
        const messageLength = message.byteLength;
        if (signature.byteLength !== ED25519.SIGNATURE_SIZE
            || message.byteLength > ED25519._messageBuffer.byteLength
            || publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        ED25519._signatureBuffer.set(signature);
        ED25519._messageBuffer.set(message);
        ED25519._pubKeyBuffer.set(publicKey);
        return ED25519._handler._ed25519_verify(ED25519._signaturePointer, ED25519._messagePointer, messageLength,
            ED25519._pubKeyPointer);
    }


    /**
     * Adds scalar to the given key pair where scalar is a 32 byte buffer (possibly generated with createSeed),
     * generating a new key pair. You can calculate the public key sum without knowing the private key and vice versa
     * by passing in null for the key you don't know. ED25519 is useful for enforcing randomness on a key pair by a third
     * party while only knowing the public key, among other things. Warning: the last bit of the scalar is ignored - if
     * comparing scalars make sure to clear it with scalar[31] &= 127.
     */
    static async addScalar(publicKey, privateKey, scalar) {
        await ED25519._awaitHandler();
        if ((publicKey === null && privateKey === null)
            || (publicKey !== null && publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE)
            || (privateKey !== null && privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE)
            || scalar.byteLength !== ED25519.SCALAR_SIZE) {
            throw Error('Illegal arguments.');
        }
        if (publicKey) {
            ED25519._pubKeyBuffer.set(publicKey);
        }
        if (privateKey) {
            ED25519._privKeyBuffer.set(privateKey);
        }
        ED25519._handler._ed25519_add_scalar(
            publicKey? ED25519._pubKeyPointer : 0 /* NULL pointer */,
            privateKey? ED25519._privKeyPointer : 0 /* NULL pointer */,
            ED25519._scalarPointer);
        if (publicKey) {
            publicKey.set(ED25519._pubKeyBuffer);
        }
        if (privateKey) {
            privateKey.set(ED25519._privKeyBuffer);
            ED25519._privKeyBuffer.fill(0);
        }
    }


    /**
     * Performs a key exchange on the given public key and private key, producing a shared secret. It is recommended to
     * hash the shared secret before using it. sharedSecret must be a 32 byte writable buffer where the shared secret
     * will be stored.
     */
    static async keyExchange(out_sharedSecret, publicKey, privateKey) {
        await ED25519._awaitHandler();
        if (out_sharedSecret.byteLength !== ED25519.SECRET_SIZE
            || publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE
            || privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        ED25519._pubKeyBuffer.set(publicKey);
        ED25519._privKeyBuffer.set(privateKey);
        ED25519._handler._ed25519_key_exchange(ED25519._secretPointer, ED25519._pubKeyPointer, ED25519._privKeyPointer);
        out_sharedSecret.set(ED25519._secretBuffer);
        ED25519._privKeyBuffer.fill(0);
    }
}

ED25519.DIST_PATH = typeof(ED25519_DIST_PATH)!=='undefined'? ED25519_DIST_PATH : 'dist/';
ED25519.SEED_SIZE = 32;
ED25519.PUBLIC_KEY_SIZE = 32;
ED25519.PRIVATE_KEY_SIZE = 64;
ED25519.SIGNATURE_SIZE = 64;
ED25519.SCALAR_SIZE = 32;
ED25519.SECRET_SIZE = 32;

ED25519._seedBuffer = null;
ED25519._pubKeyBuffer = null;
ED25519._privKeyBuffer = null;
ED25519._signatureBuffer = null;
ED25519._scalarBuffer = null;
ED25519._secretBuffer = null;
ED25519._messageBuffer = null;

ED25519._seedPointer = null;
ED25519._pubKeyPointer = null;
ED25519._privKeyPointer = null;
ED25519._signaturePointer = null;
ED25519._scalarPointer = null;
ED25519._secretPointer = null;
ED25519._messagePointer = null;

ED25519._handler = null;
ED25519._handlerPromise = null;

if (typeof(Class) !== 'undefined') {
    // support for nimiqs class system
    Class.register(ED25519);
} else if (typeof(module) !== 'undefined') {
    module.exports = ED25519;
}
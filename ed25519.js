class ED25519 {
    static _awaitHandler() {
        if (!ED25519._properties.handlerPromise) {
            ED25519._properties.handlerPromise = new Promise((resolve, reject) => {
                // load the handler
                if (typeof(document) !== 'undefined') {
                    // we are in the browser
                    var script = document.createElement('script');
                    script.onload = resolve;
                    script.onerror = reject;
                    script.src = ED25519._properties.path + (typeof(WebAssembly)!=='undefined'? 'ed25519-wasm.js' : 'ed25519-asm.js');
                    document.body.appendChild(script);
                } else {
                    // we are in node
                    if (typeof(WebAssembly)==='undefined') {
                        throw Error('Please use a node version with WebAssembly support.');
                    }
                    global.ED25519_HANDLER = require(ED25519._properties.path + 'ed25519-wasm.js');
                    resolve();
                }
            })
            .then(() => new Promise((resolve, reject) => {
                ED25519._properties.handler = ED25519_HANDLER({
                    wasmBinaryFile: ED25519._properties.dependenciesPath + 'ed25519-wasm.wasm',
                    memoryInitializerPrefixURL: ED25519._properties.dependenciesPath,
                    onRuntimeInitialized: resolve,
                });
            }))
            .then(() => {
                const memoryStart = ED25519._properties.handler._get_static_memory_start();
                const memorySize = ED25519._properties.handler._get_static_memory_size();
                if (memorySize < ED25519.PUBLIC_KEY_SIZE + ED25519.PRIVATE_KEY_SIZE + ED25519.SIGNATURE_SIZE) {
                    throw Error('Static memory too small');
                }
                let byteOffset = memoryStart;
                ED25519._properties.pubKeyPointer = byteOffset;
                ED25519._properties.pubKeyBuffer = new Uint8Array(ED25519._properties.handler.HEAP8.buffer, byteOffset, ED25519.PUBLIC_KEY_SIZE);
                byteOffset += ED25519.PUBLIC_KEY_SIZE;
                ED25519._properties.privKeyPointer = byteOffset;
                ED25519._properties.privKeyBuffer = new Uint8Array(ED25519._properties.handler.HEAP8.buffer, byteOffset, ED25519.PRIVATE_KEY_SIZE);
                byteOffset += ED25519.PRIVATE_KEY_SIZE;
                ED25519._properties.signaturePointer = byteOffset;
                ED25519._properties.signatureBuffer = new Uint8Array(ED25519._properties.handler.HEAP8.buffer, byteOffset, ED25519.SIGNATURE_SIZE);
                byteOffset += ED25519.SIGNATURE_SIZE;
                ED25519._properties.messagePointer = byteOffset;
                ED25519._properties.messageBuffer = new Uint8Array(ED25519._properties.handler.HEAP8.buffer, byteOffset, (memoryStart + memorySize) - byteOffset);

                if (ED25519._properties.removePrivKeyTraces) {
                    // stack to be able to overwrite any traces of private key data on the stack (note that the ed25519
                    // implementation does not malloc at any time so we don't have to mind that).
                    // We overwrite the private key data as the HEAP8 with all data is easily accessible for an attacker.
                    ED25519._properties.stack = ED25519._properties.handler._getStack();
                    Object.defineProperty(ED25519._properties.stack, 'fill', {
                        value: Uint8Array.prototype.fill.bind(ED25519._properties.stack)
                    });
                }

                // freeze methods (see comment about freeze below)
                Object.freeze(ED25519._properties);
                Object.freeze(ED25519._properties.handler);
                Object.defineProperty(ED25519._properties.privKeyBuffer, 'fill', {
                    value: Uint8Array.prototype.fill.bind(ED25519._properties.privKeyBuffer)
                });
                Object.defineProperty(ED25519._properties.privKeyBuffer, 'set', {
                    value: Uint8Array.prototype.set.bind(ED25519._properties.privKeyBuffer)
                });
            });
        }
        return ED25519._properties.handlerPromise;
    }


    static setPath(path, dependenciesPath = path) {
        if (ED25519._properties.handlerPromise) {
            throw Error('must be set before first call of any method');
        }
        ED25519._properties.path = path;
        ED25519._properties.dependenciesPath = dependenciesPath;
    }


    static disablePrivateKeyTraceRemoval() {
        if (ED25519._properties.handlerPromise) {
            throw Error('must be set before first call of any method');
        }
        ED25519._properties.removePrivKeyTraces = false;
    }


    /**
     * Calculate the public key for a given private key.
     * The private and public key are 32 byte. The private key can be any random data, however ensure to
     * use random data generated by a cryptographically secure random generator, e.g. window.crypto.getRandomValues.
     */
    static async derivePublicKey(out_publicKey, privateKey) {
        await ED25519._awaitHandler();
        if (out_publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE
            || privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        ED25519._properties.privKeyBuffer.set(privateKey);
        ED25519._properties.handler._ed25519_public_key_derive(ED25519._properties.pubKeyPointer, ED25519._properties.privKeyPointer);
        if (ED25519._properties.removePrivKeyTraces) {
            ED25519._properties.privKeyBuffer.fill(0);
            ED25519._properties.stack.fill(0);
        }
        out_publicKey.set(ED25519._properties.pubKeyBuffer);
    }


    /**
     * Creates a signature of the given message with the given key pair. signature must be a writable 64 byte buffer.
     * message must have at least message_len bytes to be read and must fit into ED25519._properties.messageBuffer.
     */
    static async sign(out_signature, message, publicKey, privateKey) {
        await ED25519._awaitHandler();
        const messageLength = message.byteLength;
        if (out_signature.byteLength !== ED25519.SIGNATURE_SIZE
            || messageLength > ED25519._properties.messageBuffer.byteLength
            || publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE
            || privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        ED25519._properties.messageBuffer.set(message);
        ED25519._properties.pubKeyBuffer.set(publicKey);
        ED25519._properties.privKeyBuffer.set(privateKey);
        ED25519._properties.handler._ed25519_sign(ED25519._properties.signaturePointer, ED25519._properties.messagePointer, messageLength,
            ED25519._properties.pubKeyPointer, ED25519._properties.privKeyPointer);
        if (ED25519._properties.removePrivKeyTraces) {
            ED25519._properties.privKeyBuffer.fill(0);
            ED25519._properties.stack.fill(0);
        }
        out_signature.set(ED25519._properties.signatureBuffer);
    }


    /**
     * Verifies the signature on the given message using public_key. signature must be a readable 64 byte buffer.
     * message must have at least message_len bytes to be read and must fit ED25519._properties.messageBuffer.
     * Returns true if the signature matches, false otherwise.
     */
    static async verify(signature, message, publicKey) {
        await ED25519._awaitHandler();
        const messageLength = message.byteLength;
        if (signature.byteLength !== ED25519.SIGNATURE_SIZE
            || message.byteLength > ED25519._properties.messageBuffer.byteLength
            || publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        ED25519._properties.signatureBuffer.set(signature);
        ED25519._properties.messageBuffer.set(message);
        ED25519._properties.pubKeyBuffer.set(publicKey);
        return !!ED25519._properties.handler._ed25519_verify(ED25519._properties.signaturePointer, ED25519._properties.messagePointer, messageLength,
            ED25519._properties.pubKeyPointer);
    }
}

ED25519.PUBLIC_KEY_SIZE = 32;
ED25519.PRIVATE_KEY_SIZE = 32;
ED25519.SIGNATURE_SIZE = 64;

ED25519._properties = {
    pubKeyBuffer: null,
    privKeyBuffer: null,
    signatureBuffer: null,
    messageBuffer: null,

    pubKeyPointer: null,
    privKeyPointer: null,
    signaturePointer: null,
    messagePointer: null,

    stack: null,

    path: '../node_modules/ed25519/dist/',
    dependenciesPath: '../node_modules/ed25519/dist/',
    handler: null,
    handlerPromise: null,

    removePrivKeyTraces: true
};

// Freeze the object to avoid that an attacker can replace the methods and steal the private key,
// e.g. by asking the user to post something in the developer tools under false claims or xss.
// Note however that the attacker can change the _properties (including the handlerPromise) before
// _awaitHandler has finished. So you might want to manually call that method at start up.
Object.freeze(ED25519);

if (typeof(module) !== 'undefined') {
    module.exports = ED25519;
}
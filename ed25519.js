const ED25519 = {
    DIST_PATH: window.ED25519_DIST_PATH || 'dist/',

    SEED_SIZE: 32,
    PUBLIC_KEY_SIZE: 32,
    PRIVATE_KEY_SIZE: 64,
    SIGNATURE_SIZE: 64,
    SCALAR_SIZE: 32,
    SECRET_SIZE: 32,
    
    _instancePromise: null,
    _handler: null,

    _seedBuffer: null,
    _pubKeyBuffer: null,
    _privKeyBuffer: null,
    _signatureBuffer: null,
    _scalarBuffer: null,
    _secretBuffer: null,
    _messageBuffer: null,

    _seedPointer: null,
    _pubKeyPointer: null,
    _privKeyPointer: null,
    _signaturePointer: null,
    _scalarPointer: null,
    _secretPointer: null,
    _messagePointer: null,

    _handler: null,
    _handlerPromise: null,
    _awaitHandler: function() {
        if (!this._handlerPromise) {
            this._handlerPromise = new Promise((resolve, reject) => {
                // load the handler
                var script = document.createElement('script');
                script.onload = resolve;
                script.onerror = reject;
                script.src = ED25519.DIST_PATH + (window.WebAssembly? 'ed25519-wasm.js' : 'ed25519-asm.js');
                document.body.appendChild(script);
            })
            .then(() => new Promise((resolve, reject) => {
                this._handler = ED25519_HANDLER({
                    wasmBinaryFile: ED25519.DIST_PATH + 'ed25519-wasm.wasm',
                    memoryInitializerPrefixURL: ED25519.DIST_PATH
                });
                // wait until the handler is ready
                this._handler.onRuntimeInitialized = resolve;
            }))
            .then(() => {
                console.log('got the handler');
                const memoryStart = this._handler._get_static_memory_start();
                const memorySize = this._handler._get_static_memory_size();
                if (memorySize < ED25519.SEED_SIZE + ED25519.PUBLIC_KEY_SIZE + ED25519.PRIVATE_KEY_SIZE
                    + ED25519.SIGNATURE_SIZE + ED25519.SCALAR_SIZE + ED25519.SECRET_SIZE) {
                    throw Error('Static memory too small');
                }
                let byteOffset = memoryStart;
                this._seedPointer = byteOffset;
                this._seedBuffer = new Uint8Array(this._handler.HEAP8.buffer, byteOffset, ED25519.SEED_SIZE);
                byteOffset += ED25519.SEED_SIZE;
                this._pubKeyPointer = byteOffset;
                this._pubKeyBuffer = new Uint8Array(this._handler.HEAP8.buffer, byteOffset, ED25519.PUBLIC_KEY_SIZE);
                byteOffset += ED25519.PUBLIC_KEY_SIZE;
                this._privKeyPointer = byteOffset;
                this._privKeyBuffer = new Uint8Array(this._handler.HEAP8.buffer, byteOffset, ED25519.PRIVATE_KEY_SIZE);
                byteOffset += ED25519.PRIVATE_KEY_SIZE;
                this._signaturePointer = byteOffset;
                this._signatureBuffer = new Uint8Array(this._handler.HEAP8.buffer, byteOffset, ED25519.SIGNATURE_SIZE);
                byteOffset += ED25519.SIGNATURE_SIZE;
                this._scalarPointer = byteOffset;
                this._scalarBuffer = new Uint8Array(this._handler.HEAP8.buffer, byteOffset, ED25519.SCALAR_SIZE);
                byteOffset += ED25519.SCALAR_SIZE;
                this._secretPointer = byteOffset;
                this._secretBuffer = new Uint8Array(this._handler.HEAP8.buffer, byteOffset, ED25519.SECRET_SIZE);
                byteOffset += ED25519.SECRET_SIZE;
                this._messagePointer = byteOffset;
                this._messageBuffer = new Uint8Array(this._handler.HEAP8.buffer, byteOffset, (memoryStart + memorySize) - byteOffset);
            });
        }
        return this._handlerPromise;
    },


    /**
     * Creates a new key pair from the given seed. public_key must be a writable 32 byte buffer, private_key must be
     * a writable 64 byte buffer and seed must be a 32 byte buffer.
     */
    createKeyPair: async function(out_publicKey, out_privateKey, seed) {
        await this._awaitHandler();
        if (seed.byteLength !== ED25519.SEED_SIZE
            || out_publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE
            || out_privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        this._seedBuffer.set(seed);
        this._handler._ed25519_create_keypair(this._pubKeyPointer, this._privKeyPointer, this._seedPointer);
        out_publicKey.set(this._pubKeyBuffer);
        out_privateKey.set(this._privKeyBuffer);
        this._privKeyBuffer.fill(0);
    },


    /**
     * Creates a signature of the given message with the given key pair. signature must be a writable 64 byte buffer.
     * message must have at least message_len bytes to be read and must fit into this._messageBuffer.
     */
    sign: async function(out_signature, message, messageLength, publicKey, privateKey) {
        await this._awaitHandler();
        if (out_signature.byteLength !== ED25519.SIGNATURE_SIZE
            || message.byteLength < messageLength || message.byteLength > this._messageBuffer.byteLength
            || publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE
            || privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        this._messageBuffer.set(message);
        this._pubKeyBuffer.set(publicKey);
        this._privKeyBuffer.set(privateKey);
        this._handler._ed25519_sign(this._signaturePointer, this._messagePointer, messageLength,
            this._pubKeyPointer, this._privKeyPointer);
        out_signature.set(this._signatureBuffer);
        this._privKeyBuffer.fill(0);
    },


    /**
     * Verifies the signature on the given message using public_key. signature must be a readable 64 byte buffer.
     * message must have at least message_len bytes to be read and must fit this._messageBuffer.
     * Returns 1 if the signature matches, 0 otherwise.
     */
    verify: async function(signature, message, messageLength, publicKey) {
        await this._awaitHandler();
        if (signature.byteLength !== ED25519.SIGNATURE_SIZE
            || message.byteLength < messageLength || message.byteLength > this._messageBuffer.byteLength
            || publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        this._signatureBuffer.set(signature);
        this._messageBuffer.set(message);
        this._pubKeyBuffer.set(publicKey);
        return this._handler._ed25519_verify(this._signaturePointer, this._messagePointer, messageLength,
            this._pubKeyPointer);
    },


    /**
     * Adds scalar to the given key pair where scalar is a 32 byte buffer (possibly generated with createSeed),
     * generating a new key pair. You can calculate the public key sum without knowing the private key and vice versa
     * by passing in null for the key you don't know. This is useful for enforcing randomness on a key pair by a third
     * party while only knowing the public key, among other things. Warning: the last bit of the scalar is ignored - if
     * comparing scalars make sure to clear it with scalar[31] &= 127.
     */
    addScalar: async function(publicKey, privateKey, scalar) {
        await this._awaitHandler();
        if ((publicKey === null && privateKey === null)
            || (publicKey !== null && publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE)
            || (privateKey !== null && privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE)
            || scalar.byteLength !== ED25519.SCALAR_SIZE) {
            throw Error('Illegal arguments.');
        }
        if (publicKey) {
            this._pubKeyBuffer.set(publicKey);
        }
        if (privateKey) {
            this._privKeyBuffer.set(privateKey);
        }
        this._handler._ed25519_add_scalar(
            publicKey? this._pubKeyPointer : 0 /* NULL pointer */,
            privateKey? this._privKeyPointer : 0 /* NULL pointer */,
            this._scalarPointer);
        if (publicKey) {
            publicKey.set(this._pubKeyBuffer);
        }
        if (privateKey) {
            privateKey.set(this._privKeyBuffer);
            this._privKeyBuffer.fill(0);
        }
    },


    /**
     * Performs a key exchange on the given public key and private key, producing a shared secret. It is recommended to
     * hash the shared secret before using it. sharedSecret must be a 32 byte writable buffer where the shared secret
     * will be stored.
     */
    keyExchange: async function(out_sharedSecret, publicKey, privateKey) {
        await this._awaitHandler();
        if (out_sharedSecret.byteLength !== ED25519.SECRET_SIZE
            || publicKey.byteLength !== ED25519.PUBLIC_KEY_SIZE
            || privateKey.byteLength !== ED25519.PRIVATE_KEY_SIZE) {
            throw Error('Wrong buffer size.');
        }
        this._pubKeyBuffer.set(publicKey);
        this._privKeyBuffer.set(privateKey);
        this._handler._ed25519_key_exchange(this._secretPointer, this._pubKeyPointer, this._privKeyPointer);
        out_sharedSecret.set(this._secretBuffer);
        this._privKeyBuffer.fill(0);
    }
}
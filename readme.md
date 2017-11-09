Ed25519
=======

This is a portable implementation of [Ed25519](http://ed25519.cr.yp.to/) based
on the SUPERCOP "ref10" implementation. All code is licensed under the permissive
zlib license.

The code is pure ANSI C without any dependencies. The code has been compiled
to WebAssembly with an asm.js fallback and wrapped into a Javascript API.


Performance
-----------

WebAssembly in browser performance:

    Private Key generation: 1.2us (827472 per second)
    Public Key derivation: 86.4us (11568 per second)
    Public Key derivation (with private key trace removal): 238.8us (4187 per second)
    Message signing (short message): 87.7us (11401 per second)
    Message signing (short message, with private key trace removal): 236.3us (4231 per second)
    Message verifying (short message): 180.0us (5553 per second)

asm.js fallback in browser performance:

    Private Key generation: 1.2us (827472 per second)
    Public key derivation: 3107.9us (321 per second)
    Message signing (short message): 3252.7us (307 per second)
    Message verifying (short message): 11778.9us (84 per second)

WebAssembly in node.js performance:

    Private Key generation: 4.8us (207429 per second)
    Public key derivation: 81.9us (12202 per second)
    Message signing (short message): 84.0us (11898 per second)
    Message verifying (short message): 171.4us (5831 per second)

Comparison to native binary compiled from C:

    Private Key generation: 23.7us (42039 per second)
    Public key derivation: 43.0us (23227 per second)
    Message signing (short message): 44.0us (22696 per second)
    Message verifying (short message): 118.2us (8455 per second)

Comparison to the WebCrypto API (window.crypto.subtle):

    Private Key generation: 119.7us (8349 per second)
    Message signing (short message): 115.0us (8690 per second)
    Message verification (short message): 213.6us (4681 per second)



Usage
-----

There are no defined types for private keys, public keys or signatures.
Instead simple Uint8Arrays are used with the following sizes:
 
signature: 64, 
public key: 32, 
private key: 32

Private keys are symply cryptographically secure random data, generated
for example by window.crypto.getRandomValues() in the browser or
require('crypto').randomFillSync in node.

See test.js for usage examples.


License
-------
All code is released under the zlib license. See license.txt for details.

Ed25519
=======

This is a portable implementation of [Ed25519](http://ed25519.cr.yp.to/) based
on the SUPERCOP "ref10" implementation. Additionally there is key exchanging
and scalar addition included to further aid building a PKI using Ed25519. All
code is licensed under the permissive zlib license.

The code is pure ANSI C without any dependencies. The code has been compiled
to WebAssembly with an asm.js fallback and wrapped into a Javascript API.


Performance
-----------

WebAssembly performance:

    Key generation: 105us (9508 per second)
    Message signing (short message): 106us (9458 per second)
    Message verifying (short message): 192us (5211 per second)
    Scalar addition: 102us (9791 per second)
    Key exchange: 198us (5055 per second)

asm.js fallback performance:

    Key generation: 3031us (330 per second)
    Message signing (short message): 3195us (313 per second)
    Message verifying (short message): 11800us (85 per second)
    Scalar addition: 3403us (294 per second)
    Key exchange: 10484us (95 per second)

Comparison to native binary compiled from C:

    Key generation: 43us (23255 per second)
    Message signing (short message): 44us (22727 per second)
    Message verifying (short message): 113us (8849 per second)
    Scalar addition: 43us (23255 per second)
    Key exchange: 109us (9174 per second)    

Comparison to the WebCrypto API (window.crypto.subtle):

    Key generation: 139us (7194 per second)
    Message signing (short message): 145us (6877 per second)
    Message verification (short message): 276us (3617 per second)



Usage
-----

There are no defined types for seeds, private keys, public keys, shared secrets
or signatures. Instead simple buffers are used with the following sizes:

seed : 32
signature : 64
public key : 32
private key : 64
scalar : 32
shared secret : 32



License
-------
All code is released under the zlib license. See license.txt for details.

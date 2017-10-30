#include "ed25519.h"
#include "sha512.h"
#include "ge.h"

void ed25519_public_key_derive(unsigned char *out_public_key, const unsigned char *private_key) {
    ge_p3 A;
    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(out_public_key, &A);
}

// The implementation that this fork is based on, removed the compression / decompression used in the supercop
// implementation where the private key consists of 32 random bytes which get "decompressed" by
//
// randombytes(sk,32); // sk is our signing key / private key, 32 random bytes
// crypto_hash_sha512(az,sk,32);
// az[0] &= 248;
// az[31] &= 63;
// az[31] |= 64;
// 
// The result is a 64 byte buffer. The current implementation uses those 64 bytes as private key to avoid decompressing
// the private key on every sign which gives a performance boost of ~8%.
// See https://github.com/orlp/ed25519/commit/b0de745a0c1d92d2e5ec8bd2169d149056aeac1f#diff-8c43ca84c50aa9091e4d041082f4790e
void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) { 
    sha512(seed, 32, private_key);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ed25519_public_key_derive(public_key, private_key);
}



/*
 * Declarations for the libsodium constants and functions invoked in
 * the main Python module for this library via a cffi wrapper module.
 */

int sodium_memcmp(const void * const b1_, const void * const b2_, size_t len);
int sodium_init();

// crypto_box
size_t crypto_box_publickeybytes();
size_t crypto_box_sealbytes();

int crypto_box_seal(unsigned char *c, const unsigned char *m,
                    unsigned long long mlen, const unsigned char *pk);

int crypto_box_seal_open(unsigned char *m, const unsigned char *c,
                         unsigned long long clen,
                         const unsigned char *pk, const unsigned char *sk);

// crypto_secretbox
size_t crypto_secretbox_keybytes();
size_t crypto_secretbox_noncebytes();
size_t crypto_secretbox_zerobytes();
size_t crypto_secretbox_boxzerobytes();
size_t crypto_secretbox_messagebytes_max();

int crypto_secretbox(unsigned char *c,        const unsigned char *m,
                     unsigned long long mlen, const unsigned char *n,
               const unsigned char *k);

int crypto_secretbox_open(unsigned char *m,        const unsigned char *c,
                          unsigned long long clen, const unsigned char *n,
                    const unsigned char *k);

// crypto_scalarmult
size_t crypto_scalarmult_bytes();
size_t crypto_scalarmult_scalarbytes();

int crypto_scalarmult_base(unsigned char *q, const unsigned char *n);
int crypto_scalarmult(unsigned char *q, const unsigned char *n, const unsigned char *p);

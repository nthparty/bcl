"""Basic cryptographic library.
Python library that provides a simple interface for symmetric (i.e.,
secret-key) and asymmetric (i.e., public-key) encryption/decryption
primitives.
"""

import doctest
import nacl.utils
import nacl.encoding
import nacl.secret
import nacl.public

class symmetric():
    """
    Symmetric (i.e., secret-key) encryption/decryption primitives.

    >>> x = nacl.utils.random(1024)
    >>> s = symmetric.secret()
    >>> c = symmetric.encrypt(s, x)
    >>> symmetric.decrypt(s, c) == x
    True
    """
    @staticmethod
    def secret() -> bytes:
        """
        Create a secret key.
        """
        return nacl.utils.random()

    @staticmethod
    def encrypt(secret, plaintext):
        """
        Encrypt a plaintext (a bytes-like object) using the supplied secret key.
        """
        return bytes(nacl.secret.SecretBox(secret).encrypt(plaintext))

    @staticmethod
    def decrypt(secret, ciphertext):
        """
        Decrypt a ciphertext (a bytes-like object) using the supplied secret key.
        """
        return nacl.secret.SecretBox(secret).decrypt(ciphertext)

class asymmetric():
    """
    Asymmetric (i.e., public-key) encryption/decryption primitives.

    >>> x = nacl.utils.random(1024)
    >>> s = asymmetric.secret()
    >>> p = asymmetric.public(s)
    >>> c = asymmetric.encrypt(p, x)
    >>> asymmetric.decrypt(s, c) == x
    True
    """
    @staticmethod
    def secret() -> bytes:
        """
        Create a secret key.
        """
        return nacl.utils.random()

    @staticmethod
    def public(secret):
        """
        Create a public key using a secret key (a bytes-like object of length 32).
        """
        return nacl.public\
            .PrivateKey(secret).public_key\
            .encode(encoder=nacl.encoding.Base64Encoder)\
            .decode()

    @staticmethod
    def encrypt(public, plaintext):
        """
        Encrypt a plaintext (a bytes-like object) using the supplied public key.
        """
        public_key = nacl.public.PublicKey(
            public, encoder=nacl.encoding.Base64Encoder
        )
        return bytes(nacl.public.SealedBox(public_key).encrypt(plaintext))

    @staticmethod
    def decrypt(secret, ciphertext):
        """
        Decrypt a ciphertext (a bytes-like object) using the supplied secret key.
        """
        return nacl.public\
            .SealedBox(nacl.public.PrivateKey(secret))\
            .decrypt(ciphertext)

if __name__ == "__main__":
    doctest.testmod()

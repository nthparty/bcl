"""Basic cryptographic library.

Python library that provides a simple interface for symmetric (i.e.,
secret-key) and asymmetric (i.e., public-key) encryption/decryption
primitives.
"""

from __future__ import annotations
import doctest
import base64
import bcl.utils
import bcl.secret
import bcl.public

class raw(bytes):
    """
    Wrapper class for a raw bytes-like object that represents a key,
    plaintext, or ciphertext.
    """
    @classmethod
    def from_base64(cls, s: str) -> raw:
        """Convert Base64 UTF-8 string representation of a raw value."""
        return bytes.__new__(cls, base64.standard_b64decode(s))

    def to_base64(self: raw) -> str:
        """Convert to equivalent Base64 UTF-8 string representation."""
        return base64.standard_b64encode(self).decode('utf-8')

class key(raw):
    """
    Wrapper class for a bytes-like object that represents a key.
    """

class secret(key):
    """
    Wrapper class for a bytes-like object that represents a secret key.
    """

class public(key):
    """
    Wrapper class for a bytes-like object that represents a public key.
    """

class plain(raw):
    """
    Wrapper class for a bytes-like object that represents a plaintext.
    """

class cipher(raw):
    """
    Wrapper class for a bytes-like object that represents a ciphertext.
    """

class symmetric:
    """
    Symmetric (i.e., secret-key) encryption/decryption primitives.

    >>> x = plain(bcl.utils.random(1024))
    >>> isinstance(x, raw)
    True
    >>> isinstance(x, plain)
    True
    >>> s = symmetric.secret()
    >>> isinstance(s, key)
    True
    >>> isinstance(s, secret)
    True
    >>> s == secret.from_base64(s.to_base64())
    True
    >>> c = symmetric.encrypt(s, x)
    >>> isinstance(c, raw)
    True
    >>> isinstance(c, cipher)
    True
    >>> c == secret.from_base64(c.to_base64())
    True
    >>> symmetric.decrypt(s, c) == x
    True
    >>> isinstance(symmetric.decrypt(s, c), plain)
    True
    """
    @staticmethod
    def secret() -> secret:
        """
        Create a secret key.
        """
        return secret(bcl.utils.random())

    @staticmethod
    def encrypt(secret_key: secret, plaintext: plain) -> cipher:
        """
        Encrypt a plaintext (a bytes-like object) using the supplied secret key.
        """
        return cipher(bcl.secret.SecretBox(secret_key).encrypt(plaintext))

    @staticmethod
    def decrypt(secret_key: secret, ciphertext: cipher) -> plain:
        """
        Decrypt a ciphertext (a bytes-like object) using the supplied secret key.
        """
        return plain(bcl.secret.SecretBox(secret_key).decrypt(ciphertext))

class asymmetric:
    """
    Asymmetric (i.e., public-key) encryption/decryption primitives.

    >>> x = plain(bcl.utils.random(1024))
    >>> x == plain.from_base64(x.to_base64())
    True
    >>> s = asymmetric.secret()
    >>> p = asymmetric.public(s)
    >>> isinstance(p, key)
    True
    >>> isinstance(p, public)
    True
    >>> p == public.from_base64(p.to_base64())
    True
    >>> c = asymmetric.encrypt(p, x)
    >>> asymmetric.decrypt(s, c) == x
    True
    """
    @staticmethod
    def secret() -> secret:
        """
        Create a secret key.
        """
        return secret(bcl.utils.random())

    @staticmethod
    def public(secret_key: secret) -> public:
        """
        Create a public key using a secret key (a bytes-like object of length 32).
        """
        return public(bcl.public.PrivateKey(secret_key).public_key)

    @staticmethod
    def encrypt(public_key: public, plaintext: plain) -> cipher:
        """
        Encrypt a plaintext (a bytes-like object) using the supplied public key.
        """
        return cipher(
            bcl.public\
                .SealedBox(bcl.public.PublicKey(public_key)).encrypt(plaintext)
        )

    @staticmethod
    def decrypt(secret_key: secret, ciphertext: cipher) -> plain:
        """
        Decrypt a ciphertext (a bytes-like object) using the supplied secret key.
        """
        return plain(
            bcl.public\
                .SealedBox(bcl.public.PrivateKey(secret_key)).decrypt(ciphertext)
        )

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover

"""
Python library that provides a simple interface for symmetric (i.e.,
secret-key) and asymmetric (i.e., public-key) encryption/decryption
primitives.
"""
from __future__ import annotations
from typing import Optional, Union
import doctest
import os
import base64

try:
    from bcl import _sodium
except: # pylint: disable=W0702 # pragma: no cover
    # Support for direct invocation in order to execute doctests.
    import _sodium

crypto_secretbox_KEYBYTES = _sodium.lib.crypto_secretbox_keybytes()
crypto_secretbox_NONCEBYTES = _sodium.lib.crypto_secretbox_noncebytes()
crypto_secretbox_ZEROBYTES = _sodium.lib.crypto_secretbox_zerobytes()
crypto_secretbox_BOXZEROBYTES = _sodium.lib.crypto_secretbox_boxzerobytes()
crypto_secretbox_MESSAGEBYTES_MAX = _sodium.lib.crypto_secretbox_messagebytes_max()
crypto_box_PUBLICKEYBYTES = _sodium.lib.crypto_box_publickeybytes()
crypto_box_SEALBYTES = _sodium.lib.crypto_box_sealbytes()

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

class nonce(raw):
    """
    Wrapper class for a bytes-like object that represents a nonce.

    >>> isinstance(nonce(), bytes)
    True
    >>> noncetext = nonce()
    >>> noncetext == nonce(noncetext)
    True
    >>> try:
    ...     nonce(bytes([1, 2, 3]))
    ... except ValueError as e:
    ...     length = crypto_secretbox_NONCEBYTES
    ...     str(e) == "nonce must have exactly "  + str(length) + " bytes"
    True
    """
    def __new__(cls, noncetext: Optional[nonce] = None) -> nonce:
        """
        Create a nonce object.
        """
        if noncetext is None:
            noncetext = os.urandom(crypto_secretbox_NONCEBYTES)
        elif len(noncetext) != crypto_secretbox_NONCEBYTES:
            raise ValueError(
                "nonce must have exactly " + \
                str(crypto_secretbox_NONCEBYTES) + " bytes"
            )

        return bytes.__new__(cls, noncetext)

class key(raw):
    """
    Wrapper class for a bytes-like object that represents a key.
    """
    def __hash__(self):
        """
        Return hash of this key object that takes into account
        the subclass of the object.

        >>> len({key(bytes([0])), key(bytes([1]))})
        2
        """
        return hash((bytes(self), type(self)))

    def __eq__(self: key, other: key) -> bool:
        """
        Compare two keys (including their subclass). The portion of
        the method that compares byte values runs in constant time.

        >>> key(bytes([0] * 32)) == key(bytes([1] * 32))
        False
        >>> key(bytes([1] * 32)) == key(bytes([1] * 32))
        True
        >>> secret(bytes([0] * 32)) == public(bytes([0] * 32))
        False
        """
        # Keys of different derived classes are not equal
        # because they serve different roles.
        if not isinstance(other, self.__class__):
            return False

        (k_0, k_1) = (bytes(self), bytes(other))
        length = max(len(k_0), len(k_1))

        k_0_buffer = _sodium.ffi.new("char []", length)
        k_1_buffer = _sodium.ffi.new("char []", length)
        _sodium.ffi.memmove(k_0_buffer, k_0, len(k_0))
        _sodium.ffi.memmove(k_1_buffer, k_1, len(k_1))

        return (
            len(k_0) == len(k_1) and \
            _sodium.lib.sodium_memcmp(k_0_buffer, k_1_buffer, length) == 0
        )

    def __ne__(self, other):
        """
        Compare two keys (including their subclass). The portion of
        the method that compares byte values runs in constant time.

        >>> key(bytes([0] * 32)) != key(bytes([1] * 32))
        True
        >>> key(bytes([1] * 32)) != key(bytes([1] * 32))
        False
        >>> secret(bytes([0] * 32)) != public(bytes([0] * 32))
        True
        """
        return not self == other

class secret(key):
    """
    Wrapper class for a bytes-like object that represents a secret key.
    The constructor for this class can be used to generate an instance
    of a secret key or to convert a bytes-like object into a secret key.

    >>> sk = secret()
    >>> sk = secret(bytes(sk))

    The constructor for this class checks that the supplied bytes-like
    object is a valid key.

    >>> secret(123)
    Traceback (most recent call last):
      ...
    TypeError: secret key must be a bytes-like object
    >>> try:
    ...     secret(bytes([1, 2, 3]))
    ... except ValueError as e:
    ...     length = crypto_secretbox_KEYBYTES
    ...     str(e) == "secret key must have exactly "  + str(length) + " bytes"
    True
    """
    def __new__(cls, secret_key: Optional[secret] = None) -> secret:
        """
        Create a secret key object.
        """
        if secret_key is None:
            secret_key = secret(os.urandom(crypto_secretbox_KEYBYTES))
        elif not isinstance(secret_key, (bytes, bytearray)):
            raise TypeError("secret key must be a bytes-like object")
        elif len(secret_key) != crypto_secretbox_KEYBYTES:
            raise ValueError(
                "secret key must have exactly " + \
                str(crypto_secretbox_KEYBYTES) + " bytes"
            )

        return bytes.__new__(cls, secret_key)

class public(key):
    """
    Wrapper class for a bytes-like object that represents a public key.
    The constructor for this class can be used to generate an instance
    of a public key or to convert a bytes-like object into a public key.

    >>> pk = public()
    >>> pk = public(bytes(pk))

    The constructor for this class checks that the supplied bytes-like
    object is a valid key.

    >>> public(123)
    Traceback (most recent call last):
      ...
    TypeError: public key must be a bytes-like object
    >>> try:
    ...     public(bytes([1, 2, 3]))
    ... except ValueError as e:
    ...     length = crypto_box_PUBLICKEYBYTES
    ...     str(e) == "public key must have exactly "  + str(length) + " bytes"
    True
    """
    def __new__(cls, public_key: Optional[public] = None) -> public:
        """
        Create a public key object.
        """
        if public_key is None:
            public_key = public(os.urandom(crypto_box_PUBLICKEYBYTES))
        elif not isinstance(public_key, (bytes, bytearray)):
            raise TypeError("public key must be a bytes-like object")
        elif len(public_key) != crypto_box_PUBLICKEYBYTES:
            raise ValueError(
                "public key must have exactly " + \
                str(crypto_box_PUBLICKEYBYTES) + " bytes"
            )

        return bytes.__new__(cls, public_key)

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

    >>> x = plain(os.urandom(1024))
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
    >>> c == cipher.from_base64(c.to_base64())
    True
    >>> symmetric.decrypt(s, c) == x
    True
    >>> isinstance(symmetric.decrypt(s, c), plain)
    True

    When no nonce object is supplied, encryption is non-deterministic.
    Deterministic encryption is possible by supplying a nonce object.

    >>> symmetric.encrypt(s, x) == symmetric.encrypt(s, x)
    False
    >>> n = nonce()
    >>> symmetric.encrypt(s, x, n) == symmetric.encrypt(s, x, n)
    True
    """
    @staticmethod
    def secret() -> secret:
        """
        Create a secret key.
        """
        return secret()

    @staticmethod
    def encrypt(
            secret_key: secret, plaintext: Union[plain, bytes, bytearray],
            noncetext: Optional[nonce] = None
        ) -> cipher:
        """
        Encrypt a plaintext (a bytes-like object) using the supplied secret key
        (and a nonce, if it is supplied).

        >>> m = plain(bytes([1, 2, 3]))
        >>> s = symmetric.secret()
        >>> c = symmetric.encrypt(s, m)
        >>> m == symmetric.decrypt(s, c)
        True

        All parameters supplied to this method must have appropriate types.

        >>> c = symmetric.encrypt(bytes([0, 0, 0]), m)
        Traceback (most recent call last):
          ...
        TypeError: can only encrypt using a symmetric secret key
        >>> c = symmetric.encrypt(s, "abc")
        Traceback (most recent call last):
          ...
        TypeError: can only encrypt a plaintext object or bytes-like object
        >>> c = symmetric.encrypt(s, m, bytes([0, 0, 0]))
        Traceback (most recent call last):
          ...
        TypeError: nonce parameter must be a nonce object
        """
        if not isinstance(secret_key, secret):
            raise TypeError("can only encrypt using a symmetric secret key")

        if not isinstance(plaintext, (plain, bytes, bytearray)):
            raise TypeError("can only encrypt a plaintext object or bytes-like object")
        if len(plaintext) > crypto_secretbox_MESSAGEBYTES_MAX:
            raise ValueError( # pragma: no cover
                "message length can be at most " + \
                str(crypto_secretbox_MESSAGEBYTES_MAX) + " bytes"
            )

        if noncetext is None:
            noncetext = nonce()
        elif not isinstance(noncetext, nonce):
            raise TypeError("nonce parameter must be a nonce object")

        padded_plaintext = (b"\x00" * crypto_secretbox_ZEROBYTES) + plaintext
        ciphertext = _sodium.ffi.new("unsigned char[]", len(padded_plaintext))
        if _sodium.lib.crypto_secretbox(
            ciphertext, padded_plaintext, len(padded_plaintext), noncetext, secret_key
        ) != 0:
            raise RuntimeError("libsodium error during encryption") # pragma: no cover

        return cipher(
            noncetext + \
            _sodium.ffi.buffer(
                ciphertext,
                len(padded_plaintext)
            )[crypto_secretbox_BOXZEROBYTES:]
        )

    @staticmethod
    def decrypt(secret_key: secret, ciphertext: cipher) -> plain:
        """
        Decrypt a ciphertext (a bytes-like object) using the supplied secret key.

        >>> m = plain(bytes([1, 2, 3]))
        >>> s = symmetric.secret()
        >>> c = symmetric.encrypt(s, m)
        >>> m == symmetric.decrypt(s, c)
        True

        All parameters supplied to this method must have appropriate types.

        >>> c = symmetric.decrypt(bytes([0, 0, 0]), m)
        Traceback (most recent call last):
          ...
        TypeError: can only decrypt using a symmetric secret key
        >>> c = symmetric.decrypt(s, "abc")
        Traceback (most recent call last):
          ...
        TypeError: can only decrypt a ciphertext
        >>> symmetric.decrypt(s, cipher(c + bytes([0, 0, 0])))
        Traceback (most recent call last):
          ...
        RuntimeError: ciphertext failed verification
        """
        if not isinstance(secret_key, secret):
            raise TypeError("can only decrypt using a symmetric secret key")

        if not isinstance(ciphertext, cipher):
            raise TypeError("can only decrypt a ciphertext")

        padded_ciphertext = (
            (b"\x00" * crypto_secretbox_BOXZEROBYTES) + \
            ciphertext[crypto_secretbox_NONCEBYTES:]
        )
        plaintext = _sodium.ffi.new("unsigned char[]", len(padded_ciphertext))
        if _sodium.lib.crypto_secretbox_open(
            plaintext, padded_ciphertext, len(padded_ciphertext),
            ciphertext[:crypto_secretbox_NONCEBYTES],
            secret_key
        ) != 0:
            raise RuntimeError("ciphertext failed verification")

        return plain(
            _sodium.ffi.buffer(plaintext, len(padded_ciphertext)) \
            [crypto_secretbox_ZEROBYTES:]
        )

class asymmetric:
    """
    Asymmetric (i.e., public-key) encryption/decryption primitives.

    >>> x = plain(os.urandom(1024))
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
        return secret()

    @staticmethod
    def public(secret_key: secret) -> public:
        """
        Create a public key using a secret key (a bytes-like object of length 32).
        """
        q = _sodium.ffi.new("unsigned char[]", _sodium.lib.crypto_scalarmult_bytes())
        if _sodium.lib.crypto_scalarmult_base(q, secret_key) != 0:
            raise RuntimeError("libsodium error during decryption") # pragma: no cover

        return public(_sodium.ffi.buffer(q, _sodium.lib.crypto_scalarmult_scalarbytes())[:])

    @staticmethod
    def encrypt(public_key: public, plaintext: Union[plain, bytes, bytearray]) -> cipher:
        """
        Encrypt a plaintext (a bytes-like object) using the supplied public key.

        >>> m = plain(bytes([1, 2, 3]))
        >>> s = asymmetric.secret()
        >>> p = asymmetric.public(s)
        >>> c = asymmetric.encrypt(p, m)
        >>> m == asymmetric.decrypt(s, c)
        True

        All parameters supplied to this method must have appropriate types.

        >>> c = asymmetric.encrypt(s, m)
        Traceback (most recent call last):
          ...
        TypeError: can only encrypt using a public key
        >>> c = asymmetric.encrypt(p, "abc")
        Traceback (most recent call last):
          ...
        TypeError: can only encrypt a plaintext object or bytes-like object
        """
        if not isinstance(public_key, public):
            raise TypeError("can only encrypt using a public key")

        if not isinstance(plaintext, (plain, bytes, bytearray)):
            raise TypeError("can only encrypt a plaintext object or bytes-like object")

        plaintext_length = len(plaintext)
        ciphertext_length = crypto_box_SEALBYTES + plaintext_length
        ciphertext = _sodium.ffi.new("unsigned char[]", ciphertext_length)
        if _sodium.lib.crypto_box_seal(
            ciphertext, plaintext, plaintext_length, public_key
        ) != 0:
            raise RuntimeError("libsodium error during encryption") # pragma: no cover

        return cipher(_sodium.ffi.buffer(ciphertext, ciphertext_length)[:])

    @staticmethod
    def decrypt(secret_key: secret, ciphertext: cipher) -> plain:
        """
        Decrypt a ciphertext (a bytes-like object) using the supplied secret key.

        >>> m = plain(bytes([1, 2, 3]))
        >>> s = asymmetric.secret()
        >>> p = asymmetric.public(s)
        >>> c = asymmetric.encrypt(p, m)
        >>> m == asymmetric.decrypt(s, c)
        True

        All parameters supplied to this method must have appropriate types.

        >>> c = asymmetric.decrypt(p, m)
        Traceback (most recent call last):
          ...
        TypeError: can only decrypt using an asymmetric secret key
        >>> c = asymmetric.decrypt(s, "abc")
        Traceback (most recent call last):
          ...
        TypeError: can only decrypt a ciphertext
        >>> try:
        ...     asymmetric.decrypt(s, cipher(bytes([0])))
        ... except ValueError as e:
        ...     length = crypto_box_SEALBYTES
        ...     str(e) == "asymmetric ciphertext must have at least "  + str(length) + " bytes"
        True
        """
        if not isinstance(secret_key, secret):
            raise TypeError("can only decrypt using an asymmetric secret key")

        if not isinstance(ciphertext, cipher):
            raise TypeError("can only decrypt a ciphertext")

        q = _sodium.ffi.new("unsigned char[]", _sodium.lib.crypto_scalarmult_bytes())
        if _sodium.lib.crypto_scalarmult_base(q, secret_key) != 0:
            raise RuntimeError("libsodium error during decryption") # pragma: no cover
        public_key = public(
            _sodium.ffi.buffer(q, _sodium.lib.crypto_scalarmult_scalarbytes())[:]
        )

        ciphertext_length = len(ciphertext)
        if not ciphertext_length >= crypto_box_SEALBYTES:
            raise ValueError(
                "asymmetric ciphertext must have at least " + \
                str(crypto_box_SEALBYTES) + " bytes"
            )

        plaintext_length = ciphertext_length - crypto_box_SEALBYTES
        plaintext = _sodium.ffi.new("unsigned char[]", max(1, plaintext_length))
        if _sodium.lib.crypto_box_seal_open(
            plaintext, ciphertext, ciphertext_length, public_key, secret_key
        ) != 0:
            raise RuntimeError("libsodium error during decryption") # pragma: no cover

        return plain(_sodium.ffi.buffer(plaintext, plaintext_length)[:])

# Initializes sodium, picking the best implementations available for this
# machine.
def _sodium_init():
    if _sodium.lib.sodium_init() == -1:
        raise RuntimeError("libsodium error during initialization") # pragma: no cover

_sodium.ffi.init_once(_sodium_init, "libsodium")

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover

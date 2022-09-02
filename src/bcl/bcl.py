"""
Python library that provides a simple interface for symmetric (*i.e.*,
secret-key) and asymmetric (*i.e.*, public-key) encryption/decryption
primitives.

This library exports a number of classes (derived from :obj:`bytes`) for
representing keys, nonces, plaintexts, and ciphertexts. It also exports
two classes :obj:`symmetric` and :obj:`asymmetric` that have only static
methods (for key generation and encryption/decryption).
"""
from __future__ import annotations
from typing import Optional, Union
import doctest
import os
import base64

try:
    # Import shared/dynamic library (libsodium subset).
    from bcl import _sodium # pylint: disable=cyclic-import
except: # pylint: disable=bare-except # pragma: no cover
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
    nonce, plaintext, or ciphertext. The derived classes :obj:`secret`,
    :obj:`public`, :obj:`nonce`, :obj:`plain`, and :obj:`cipher`
    all inherit the methods defined in this class.

    >>> s = secret.from_base64('1P3mjNnadofjTUkzTmipYl+xdo9z/EaGLbWcJ8MAPBQ=')
    >>> s.hex()
    'd4fde68cd9da7687e34d49334e68a9625fb1768f73fc46862db59c27c3003c14'
    >>> n = nonce.from_base64('JVN9IKBLZi3lEq/eDgkV+y6n4v7x2edI')
    >>> c = symmetric.encrypt(s, 'abc'.encode(), n)
    >>> c.to_base64()
    'JVN9IKBLZi3lEq/eDgkV+y6n4v7x2edI9dvFXD+om1dHB6UUCt1y4BqrBw=='
    """
    @classmethod
    def from_base64(cls, s: str) -> raw:
        """
        Convert Base64 UTF-8 string representation of a raw value.
        """
        return bytes.__new__(cls, base64.standard_b64decode(s))

    def to_base64(self: raw) -> str:
        """
        Convert to equivalent Base64 UTF-8 string representation.
        """
        return base64.standard_b64encode(self).decode('utf-8')

class nonce(raw):
    """
    Wrapper class for a bytes-like object that represents a nonce.

    >>> n = nonce()
    >>> n = nonce(bytes(n))
    >>> isinstance(n, nonce) and isinstance(n, bytes)
    True

    While the constructor works like the constructor for bytes-like
    objects in also accepting an integer argument, an instance can
    only have the exact length permitted for a nonce.

    >>> nonce(nonce.length).hex()
    '000000000000000000000000000000000000000000000000'

    The constructor for this class checks that the supplied bytes-like
    object or integer argument satisfy the conditions for a valid nonce.

    >>> nonce('abc')
    Traceback (most recent call last):
      ...
    TypeError: nonce constructor argument must be a bytes-like object or an integer
    >>> try:
    ...     nonce(bytes([1, 2, 3]))
    ... except ValueError as e:
    ...     str(e) == 'nonce must have exactly '  + str(nonce.length) + ' bytes'
    True
    >>> try:
    ...     nonce(123)
    ... except ValueError as e:
    ...     str(e) == 'nonce must have exactly '  + str(nonce.length) + ' bytes'
    True
    """

    length: int = crypto_secretbox_NONCEBYTES
    """Length (in number of bytes) of nonce instances."""

    def __new__(cls, argument: Optional[Union[bytes, bytearray, int]] = None) -> nonce:
        """
        Create a nonce object.
        """
        if argument is None:
            return bytes.__new__(cls, os.urandom(crypto_secretbox_NONCEBYTES))

        if isinstance(argument, (bytes, bytearray)):
            if len(argument) != crypto_secretbox_NONCEBYTES:
                raise ValueError(
                    'nonce must have exactly ' +
                    str(crypto_secretbox_NONCEBYTES) + ' bytes'
                )
            return bytes.__new__(cls, argument)

        if isinstance(argument, int):
            if argument != crypto_secretbox_NONCEBYTES:
                raise ValueError(
                    'nonce must have exactly ' +
                    str(crypto_secretbox_NONCEBYTES) + ' bytes'
                )
            return bytes.__new__(cls, argument)

        raise TypeError(
            'nonce constructor argument must be a bytes-like ' +
            'object or an integer'
        )

class key(raw):
    """
    Wrapper class for a bytes-like object that represents a key. The
    derived classes :obj:`secret` and :obj:`public` inherit the methods
    defined in this class.

    Any :obj:`key` objects (including instances of classes derived from
    :obj:`key`) have a few features and behaviors that distinguish them
    from bytes-like objects.

    * Comparison of keys (using the built-in ``==`` and ``!=`` operators
      via the :obj:`__eq__` and :obj:`__ne__` methods) is performed in
      constant time.

    * Keys of different types are not equivalent even if their binary
      representation is identical.

      >>> b = 'd6vGTIjbxZyMolCW+/p1QFF5hjsYC5Q4x07s+RIMKK8='
      >>> secret.from_base64(b) == public.from_base64(b)
      False
      >>> secret.from_base64(b) != public.from_base64(b)
      True

    * Consistent with the above property, keys having different classes
      are distinct when used as keys or items within containers.

      >>> b = 'd6vGTIjbxZyMolCW+/p1QFF5hjsYC5Q4x07s+RIMKK8='
      >>> len({secret.from_base64(b), public.from_base64(b)})
      2
    """
    def __hash__(self: key) -> int:
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

        k_0_buffer = _sodium.ffi.new('char []', length)
        k_1_buffer = _sodium.ffi.new('char []', length)
        _sodium.ffi.memmove(k_0_buffer, k_0, len(k_0))
        _sodium.ffi.memmove(k_1_buffer, k_1, len(k_1))

        return (
            len(k_0) == len(k_1) and
            _sodium.lib.sodium_memcmp(k_0_buffer, k_1_buffer, length) == 0
        )

    def __ne__(self: key, other: key) -> bool:
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

    >>> s = secret()
    >>> s = secret(bytes(s))
    >>> isinstance(s, secret) and isinstance(s, key)and isinstance(s, bytes)
    True

    While the constructor works like the constructor for bytes-like
    objects in also accepting an integer argument, an instance can only
    have the exact length permitted for a secret key.

    >>> secret(secret.length).hex()
    '0000000000000000000000000000000000000000000000000000000000000000'

    The constructor for this class checks that the supplied bytes-like
    object or integer argument satisfy the conditions for a valid secret
    key.

    >>> secret('abc')
    Traceback (most recent call last):
      ...
    TypeError: secret key constructor argument must be a bytes-like object or an integer
    >>> try:
    ...     secret(bytes([1, 2, 3]))
    ... except ValueError as e:
    ...     str(e) == 'secret key must have exactly '  + str(secret.length) + ' bytes'
    True
    >>> try:
    ...     secret(123)
    ... except ValueError as e:
    ...     str(e) == 'secret key must have exactly '  + str(secret.length) + ' bytes'
    True

    The methods :obj:`symmetric.encrypt`, :obj:`symmetric.decrypt`, and
    :obj:`asymmetric.decrypt` only accept key parameters that are objects
    of this class.
    """

    length: int = crypto_secretbox_KEYBYTES
    """Length (in number of bytes) of secret key instances."""

    def __new__(cls, argument: Optional[Union[bytes, bytearray, int]] = None) -> secret:
        """
        Create a secret key object.
        """
        if argument is None:
            return bytes.__new__(cls, secret(os.urandom(crypto_secretbox_KEYBYTES)))

        if isinstance(argument, (bytes, bytearray)):
            if len(argument) != crypto_secretbox_KEYBYTES:
                raise ValueError(
                    'secret key must have exactly ' +
                    str(crypto_secretbox_KEYBYTES) + ' bytes'
                )
            return bytes.__new__(cls, argument)

        if isinstance(argument, int):
            if argument != crypto_secretbox_KEYBYTES:
                raise ValueError(
                    'secret key must have exactly ' +
                    str(crypto_secretbox_KEYBYTES) + ' bytes'
                )
            return bytes.__new__(cls, argument)

        raise TypeError(
            'secret key constructor argument must be a bytes-like ' +
            'object or an integer'
        )

class public(key):
    """
    Wrapper class for a bytes-like object that represents a public key.
    The constructor for this class can be used to generate an instance
    of a public key or to convert a bytes-like object into a public key.

    >>> p = public()
    >>> p = public(bytes(p))
    >>> isinstance(p, public) and isinstance(p, key)and isinstance(p, bytes)
    True

    While the constructor works like the constructor for bytes-like
    objects in also accepting an integer argument, an instance can only
    have the exact length permitted for a public key.

    >>> public(public.length).hex()
    '0000000000000000000000000000000000000000000000000000000000000000'

    The constructor for this class checks that the supplied bytes-like
    object or integer argument satisfy the conditions for a valid public
    key.

    >>> public('abc')
    Traceback (most recent call last):
      ...
    TypeError: public key constructor argument must be a bytes-like object or an integer
    >>> try:
    ...     public(bytes([1, 2, 3]))
    ... except ValueError as e:
    ...     length = crypto_box_PUBLICKEYBYTES
    ...     str(e) == 'public key must have exactly '  + str(length) + ' bytes'
    True
    >>> try:
    ...     public(123)
    ... except ValueError as e:
    ...     length = crypto_box_PUBLICKEYBYTES
    ...     str(e) == 'public key must have exactly '  + str(length) + ' bytes'
    True

    The method :obj:`asymmetric.encrypt` only accepts key parameters that
    are objects of this class.
    """

    length: int = crypto_box_PUBLICKEYBYTES
    """Length (in number of bytes) of public key instances."""

    def __new__(cls, argument: Optional[Union[bytes, bytearray, int]] = None) -> public:
        """
        Create a public key object.
        """
        if argument is None:
            return bytes.__new__(cls, secret(os.urandom(crypto_box_PUBLICKEYBYTES)))

        if isinstance(argument, (bytes, bytearray)):
            if len(argument) != crypto_box_PUBLICKEYBYTES:
                raise ValueError(
                    'public key must have exactly ' +
                    str(crypto_box_PUBLICKEYBYTES) + ' bytes'
                )
            return bytes.__new__(cls, argument)

        if isinstance(argument, int):
            if argument != crypto_box_PUBLICKEYBYTES:
                raise ValueError(
                    'public key must have exactly ' +
                    str(crypto_box_PUBLICKEYBYTES) + ' bytes'
                )
            return bytes.__new__(cls, argument)

        raise TypeError(
            'public key constructor argument must be a bytes-like ' +
            'object or an integer'
        )

class plain(raw):
    """
    Wrapper class for a bytes-like object that represents a plaintext.

    >>> x = plain(os.urandom(1024))
    >>> x == plain.from_base64(x.to_base64())
    True

    The methods :obj:`symmetric.decrypt` and :obj:`asymmetric.decrypt`
    return objects of this class.
    """

class cipher(raw):
    """
    Wrapper class for a bytes-like object that represents a ciphertext.

    >>> c = cipher(os.urandom(1024))
    >>> c == cipher.from_base64(c.to_base64())
    True

    The methods :obj:`symmetric.encrypt` and :obj:`asymmetric.encrypt`
    return objects of this class, and the methods :obj:`symmetric.decrypt`
    and :obj:`asymmetric.decrypt` can only be applied to objects of this
    class.
    """

class symmetric:
    """
    Symmetric (*i.e.*, secret-key) encryption/decryption primitives.
    This class encapsulates only static methods and should not be
    instantiated.

    >>> x = 'abc'.encode()
    >>> s = symmetric.secret()
    >>> isinstance(s, key) and isinstance(s, secret)
    True
    >>> s == secret.from_base64(s.to_base64())
    True
    >>> c = symmetric.encrypt(s, x)
    >>> isinstance(c, raw) and isinstance(c, cipher)
    True
    >>> c == cipher.from_base64(c.to_base64())
    True
    >>> symmetric.decrypt(s, c) == x
    True
    >>> isinstance(symmetric.decrypt(s, c), plain)
    True

    Encryption is non-deterministic if no :obj:`nonce` parameter is
    supplied.

    >>> symmetric.encrypt(s, x) == symmetric.encrypt(s, x)
    False

    Deterministic encryption is possible by supplying a :obj:`nonce`
    parameter.

    >>> n = nonce()
    >>> symmetric.encrypt(s, x, n) == symmetric.encrypt(s, x, n)
    True
    """
    @staticmethod
    def secret() -> secret:
        """
        Generate a :obj:`secret` key.
        """
        return secret()

    @staticmethod
    def encrypt(
            secret_key: secret, plaintext: Union[plain, bytes, bytearray],
            noncetext: Optional[nonce] = None
        ) -> cipher:
        """
        Encrypt a plaintext (a bytes-like object) using the supplied
        :obj:`secret` key (and an optional :obj:`nonce`, if applicable).

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
        >>> c = symmetric.encrypt(s, 'abc')
        Traceback (most recent call last):
          ...
        TypeError: can only encrypt a plaintext object or bytes-like object
        >>> c = symmetric.encrypt(s, m, bytes([0, 0, 0]))
        Traceback (most recent call last):
          ...
        TypeError: nonce parameter must be a nonce object
        """
        if not isinstance(secret_key, secret):
            raise TypeError('can only encrypt using a symmetric secret key')

        if not isinstance(plaintext, (plain, bytes, bytearray)):
            raise TypeError('can only encrypt a plaintext object or bytes-like object')
        if len(plaintext) > crypto_secretbox_MESSAGEBYTES_MAX:
            raise ValueError( # pragma: no cover
                'message length can be at most ' +
                str(crypto_secretbox_MESSAGEBYTES_MAX) + ' bytes'
            )

        if noncetext is None:
            noncetext = nonce()
        elif not isinstance(noncetext, nonce):
            raise TypeError('nonce parameter must be a nonce object')

        padded_plaintext = (b'\x00' * crypto_secretbox_ZEROBYTES) + plaintext
        ciphertext = _sodium.ffi.new('unsigned char[]', len(padded_plaintext))
        if _sodium.lib.crypto_secretbox(
            ciphertext, padded_plaintext, len(padded_plaintext), noncetext, secret_key
        ) != 0:
            raise RuntimeError('libsodium error during encryption') # pragma: no cover

        return cipher(
            noncetext +
            _sodium.ffi.buffer(
                ciphertext,
                len(padded_plaintext)
            )[crypto_secretbox_BOXZEROBYTES:]
        )

    @staticmethod
    def decrypt(secret_key: secret, ciphertext: cipher) -> plain:
        """
        Decrypt a ciphertext (an instance of :obj:`cipher`) using the supplied
        :obj:`secret` key.

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
        >>> c = symmetric.decrypt(s, 'abc')
        Traceback (most recent call last):
          ...
        TypeError: can only decrypt a ciphertext
        >>> symmetric.decrypt(s, cipher(c + bytes([0, 0, 0])))
        Traceback (most recent call last):
          ...
        RuntimeError: ciphertext failed verification
        """
        if not isinstance(secret_key, secret):
            raise TypeError('can only decrypt using a symmetric secret key')

        if not isinstance(ciphertext, cipher):
            raise TypeError('can only decrypt a ciphertext')

        padded_ciphertext = (
            (b'\x00' * crypto_secretbox_BOXZEROBYTES) +
            ciphertext[crypto_secretbox_NONCEBYTES:]
        )
        plaintext = _sodium.ffi.new('unsigned char[]', len(padded_ciphertext))
        if _sodium.lib.crypto_secretbox_open(
            plaintext, padded_ciphertext, len(padded_ciphertext),
            ciphertext[:crypto_secretbox_NONCEBYTES],
            secret_key
        ) != 0:
            raise RuntimeError('ciphertext failed verification')

        return plain(
            _sodium.ffi.buffer(plaintext, len(padded_ciphertext)) \
            [crypto_secretbox_ZEROBYTES:]
        )

class asymmetric:
    """
    Asymmetric (*i.e.*, public-key) encryption/decryption primitives.
    This class encapsulates only static methods and should not be
    instantiated.

    >>> x = 'abc'.encode()
    >>> s = asymmetric.secret()
    >>> isinstance(s, key) and isinstance(s, secret)
    True
    >>> p = asymmetric.public(s)
    >>> isinstance(p, key) and isinstance(p, public)
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
        Generate a :obj:`secret` key.

        >>> s = symmetric.secret()
        >>> isinstance(s, key) and isinstance(s, secret)
        True
        """
        return secret()

    @staticmethod
    def public(secret_key: secret) -> public:
        """
        Generate a :obj:`public` key using a :obj:`secret` key.

        >>> s = asymmetric.secret()
        >>> p = asymmetric.public(s)
        >>> isinstance(p, key) and isinstance(p, public)
        True
        """
        q = _sodium.ffi.new('unsigned char[]', _sodium.lib.crypto_scalarmult_bytes())
        if _sodium.lib.crypto_scalarmult_base(q, secret_key) != 0:
            raise RuntimeError('libsodium error during decryption') # pragma: no cover

        return public(
            _sodium.ffi.buffer(q, _sodium.lib.crypto_scalarmult_scalarbytes())[:]
        )

    @staticmethod
    def encrypt(public_key: public, plaintext: Union[plain, bytes, bytearray]) -> cipher:
        """
        Encrypt a plaintext (any bytes-like object) using the supplied
        :obj:`public` key.

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
        >>> c = asymmetric.encrypt(p, 'abc')
        Traceback (most recent call last):
          ...
        TypeError: can only encrypt a plaintext object or bytes-like object
        """
        if not isinstance(public_key, public):
            raise TypeError('can only encrypt using a public key')

        if not isinstance(plaintext, (plain, bytes, bytearray)):
            raise TypeError('can only encrypt a plaintext object or bytes-like object')

        plaintext_length = len(plaintext)
        ciphertext_length = crypto_box_SEALBYTES + plaintext_length
        ciphertext = _sodium.ffi.new('unsigned char[]', ciphertext_length)
        if _sodium.lib.crypto_box_seal(
            ciphertext, plaintext, plaintext_length, public_key
        ) != 0:
            raise RuntimeError('libsodium error during encryption') # pragma: no cover

        return cipher(_sodium.ffi.buffer(ciphertext, ciphertext_length)[:])

    @staticmethod
    def decrypt(secret_key: secret, ciphertext: cipher) -> plain:
        """
        Decrypt a ciphertext (an instance of :obj:`cipher`) using the supplied
        :obj:`secret` key.

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
        >>> c = asymmetric.decrypt(s, 'abc')
        Traceback (most recent call last):
          ...
        TypeError: can only decrypt a ciphertext
        >>> try:
        ...     asymmetric.decrypt(s, cipher(bytes([0])))
        ... except ValueError as e:
        ...     length = crypto_box_SEALBYTES
        ...     str(e) == 'asymmetric ciphertext must have at least '  + str(length) + ' bytes'
        True
        """
        if not isinstance(secret_key, secret):
            raise TypeError('can only decrypt using an asymmetric secret key')

        if not isinstance(ciphertext, cipher):
            raise TypeError('can only decrypt a ciphertext')

        q = _sodium.ffi.new('unsigned char[]', _sodium.lib.crypto_scalarmult_bytes())
        if _sodium.lib.crypto_scalarmult_base(q, secret_key) != 0:
            raise RuntimeError('libsodium error during decryption') # pragma: no cover
        public_key = public(
            _sodium.ffi.buffer(q, _sodium.lib.crypto_scalarmult_scalarbytes())[:]
        )

        ciphertext_length = len(ciphertext)
        if not ciphertext_length >= crypto_box_SEALBYTES:
            raise ValueError(
                'asymmetric ciphertext must have at least ' +
                str(crypto_box_SEALBYTES) + ' bytes'
            )

        plaintext_length = ciphertext_length - crypto_box_SEALBYTES
        plaintext = _sodium.ffi.new('unsigned char[]', max(1, plaintext_length))
        if _sodium.lib.crypto_box_seal_open(
            plaintext, ciphertext, ciphertext_length, public_key, secret_key
        ) != 0:
            raise RuntimeError('libsodium error during decryption') # pragma: no cover

        return plain(_sodium.ffi.buffer(plaintext, plaintext_length)[:])

# Initializes sodium, picking the best implementations available for this
# machine.
def _sodium_init():
    if _sodium.lib.sodium_init() == -1:
        raise RuntimeError('libsodium error during initialization') # pragma: no cover

_sodium.ffi.init_once(_sodium_init, 'libsodium')

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover

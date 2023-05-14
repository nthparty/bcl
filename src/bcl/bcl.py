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
from typing import Union, Optional, Callable
import doctest
import ctypes
import os
import base64

try:
    # Support for direct invocation in order to execute doctests.
    from _sodium import _sodium
except:  # pylint: disable=bare-except # pragma: no cover
    from bcl._sodium import _sodium

# Private global constants and functions (defined within
# ``_sodium_init`` after libsodium is ready).
_CRYPTO_SECRETBOX_ZEROBYTES = None
"""Length of padding for plaintext."""

_CRYPTO_SECRETBOX_BOXZEROBYTES = None
"""Length of padding for plaintext."""

_CRYPTO_SECRETBOX_NONCEBYTES = None
"""Length of padding for ciphertext."""

_CRYPTO_SECRETBOX_MESSAGEBYTES_MAX = None
"""Maximum message length for symmetric encryption."""

_CRYPTO_SECRETBOX_KEYBYTES = None
"""Length of symmetric encryption/decryption key."""

_CRYPTO_BOX_SEALBYTES = None
"""Minimum length of asymmetric encryption ciphertext."""

_CRYPTO_BOX_PUBLICKEYBYTES = None
"""Length of asymmetric public encryption key."""

_CRYPTO_SCALARMULTBYTES = None
"""Length of element used as an asymmetric public encryption key."""

_crypto_scalarmult_bytes_new: Callable[[], bytes] = (
    lambda: None # pylint: disable=unnecessary-lambda-assignment
)
_buffer_create: Callable[[int], bytes] = (
    lambda size: (ctypes.c_char * size)() # pylint: disable=unnecessary-lambda-assignment
)

# pylint: disable=invalid-name  # snake_case and PascalCase for bcl classes and class methods.
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

    length: int = None
    """Length (in number of bytes) of nonce instances."""

    def __new__(cls, argument: Optional[Union[bytes, bytearray, int]] = None) -> nonce:
        """
        Create a nonce object.
        """
        if argument is None:
            return bytes.__new__(cls, os.urandom(_CRYPTO_SECRETBOX_NONCEBYTES))

        if isinstance(argument, (bytes, bytearray)):
            if len(argument) != _CRYPTO_SECRETBOX_NONCEBYTES:
                raise ValueError(
                    'nonce must have exactly ' +
                    str(_CRYPTO_SECRETBOX_NONCEBYTES) + ' bytes'
                )
            return bytes.__new__(cls, argument)

        if isinstance(argument, int):
            if argument != _CRYPTO_SECRETBOX_NONCEBYTES:
                raise ValueError(
                    'nonce must have exactly ' +
                    str(_CRYPTO_SECRETBOX_NONCEBYTES) + ' bytes'
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

        return (
            len(k_0) == len(k_1) and
            _sodium.sodium_memcmp(k_0, k_1, length) == 0
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

    length: int = None
    """Length (in number of bytes) of secret key instances."""

    def __new__(cls, argument: Optional[Union[bytes, bytearray, int]] = None) -> secret:
        """
        Create a secret key object.
        """
        if argument is None:
            return bytes.__new__(cls, secret(os.urandom(_CRYPTO_SECRETBOX_KEYBYTES)))

        if isinstance(argument, (bytes, bytearray)):
            if len(argument) != _CRYPTO_SECRETBOX_KEYBYTES:
                raise ValueError(
                    'secret key must have exactly ' +
                    str(_CRYPTO_SECRETBOX_KEYBYTES) + ' bytes'
                )
            return bytes.__new__(cls, argument)

        if isinstance(argument, int):
            if argument != _CRYPTO_SECRETBOX_KEYBYTES:
                raise ValueError(
                    'secret key must have exactly ' +
                    str(_CRYPTO_SECRETBOX_KEYBYTES) + ' bytes'
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
    ...     length = _CRYPTO_BOX_PUBLICKEYBYTES
    ...     str(e) == 'public key must have exactly '  + str(length) + ' bytes'
    True
    >>> try:
    ...     public(123)
    ... except ValueError as e:
    ...     length = _CRYPTO_BOX_PUBLICKEYBYTES
    ...     str(e) == 'public key must have exactly '  + str(length) + ' bytes'
    True

    The method :obj:`asymmetric.encrypt` only accepts key parameters that
    are objects of this class.
    """

    length: int = None
    """Length (in number of bytes) of public key instances."""

    def __new__(cls, argument: Optional[Union[bytes, bytearray, int]] = None) -> public:
        """
        Create a public key object.
        """
        if argument is None:
            return bytes.__new__(cls, secret(os.urandom(_CRYPTO_BOX_PUBLICKEYBYTES)))

        if isinstance(argument, (bytes, bytearray)):
            if len(argument) != _CRYPTO_BOX_PUBLICKEYBYTES:
                raise ValueError(
                    'public key must have exactly ' +
                    str(_CRYPTO_BOX_PUBLICKEYBYTES) + ' bytes'
                )
            return bytes.__new__(cls, argument)

        if isinstance(argument, int):
            if argument != _CRYPTO_BOX_PUBLICKEYBYTES:
                raise ValueError(
                    'public key must have exactly ' +
                    str(_CRYPTO_BOX_PUBLICKEYBYTES) + ' bytes'
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
        if len(plaintext) > _CRYPTO_SECRETBOX_MESSAGEBYTES_MAX:
            raise ValueError( # pragma: no cover
                'message length can be at most ' +
                str(_CRYPTO_SECRETBOX_MESSAGEBYTES_MAX) + ' bytes'
            )

        if noncetext is None:
            noncetext = nonce()
        elif not isinstance(noncetext, nonce):
            raise TypeError('nonce parameter must be a nonce object')

        padded_plaintext = bytes(_CRYPTO_SECRETBOX_ZEROBYTES) + plaintext
        ciphertext = _buffer_create(len(padded_plaintext))
        if _sodium.crypto_secretbox(
            ciphertext, padded_plaintext, len(padded_plaintext), noncetext, secret_key
        ) != 0:
            raise RuntimeError('libsodium error during encryption') # pragma: no cover

        return cipher(noncetext + ciphertext.raw[_CRYPTO_SECRETBOX_BOXZEROBYTES:])

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
            bytes(_CRYPTO_SECRETBOX_BOXZEROBYTES) +
            ciphertext[_CRYPTO_SECRETBOX_NONCEBYTES:]
        )
        plaintext = _buffer_create(len(padded_ciphertext))
        if _sodium.crypto_secretbox_open(
            plaintext, padded_ciphertext, len(padded_ciphertext),
            ciphertext[:_CRYPTO_SECRETBOX_NONCEBYTES],
            secret_key
        ) != 0:
            raise RuntimeError('ciphertext failed verification')

        return plain(plaintext.raw[_CRYPTO_SECRETBOX_ZEROBYTES:])

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
        q = _crypto_scalarmult_bytes_new()
        if _sodium.crypto_scalarmult_base(q, secret_key) != 0:
            raise RuntimeError('libsodium error during decryption') # pragma: no cover

        return public(q.raw)

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
        ciphertext_length = _CRYPTO_BOX_SEALBYTES + plaintext_length
        ciphertext = _buffer_create(ciphertext_length)
        if _sodium.crypto_box_seal(
            ciphertext, plaintext, plaintext_length, public_key
        ) != 0:
            raise RuntimeError('libsodium error during encryption') # pragma: no cover

        return cipher(ciphertext.raw)

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
        ...     length = _CRYPTO_BOX_SEALBYTES
        ...     str(e) == 'asymmetric ciphertext must have at least '  + str(length) + ' bytes'
        True
        """
        if not isinstance(secret_key, secret):
            raise TypeError('can only decrypt using an asymmetric secret key')

        if not isinstance(ciphertext, cipher):
            raise TypeError('can only decrypt a ciphertext')

        q = _crypto_scalarmult_bytes_new()
        if _sodium.crypto_scalarmult_base(q, secret_key) != 0:
            raise RuntimeError('libsodium error during decryption') # pragma: no cover
        public_key = public(q.raw)

        ciphertext_length = len(ciphertext)
        if not ciphertext_length >= _CRYPTO_BOX_SEALBYTES:
            raise ValueError(
                'asymmetric ciphertext must have at least ' +
                str(_CRYPTO_BOX_SEALBYTES) + ' bytes'
            )

        plaintext_length = ciphertext_length - _CRYPTO_BOX_SEALBYTES
        plaintext = _buffer_create(max(1, plaintext_length))
        if _sodium.crypto_box_seal_open(
            plaintext, ciphertext, ciphertext_length, public_key, secret_key
        ) != 0:
            raise RuntimeError('libsodium error during decryption') # pragma: no cover

        return plain(plaintext.raw)

def _sodium_init():
    """
    Checks that libsodium is not already initialized, initializes it,
    and defines globals whose definitions depend on functions exported
    by libsodium.
    """
    if _sodium.sodium_init() == 1:
        raise RuntimeError('libsodium is already initialized') # pragma: no cover

    if not _sodium.sodium_init() == 1:
        raise RuntimeError('libsodium error during initialization') # pragma: no cover

    _sodium.ready = True

    # Define values of public and private globals.
    context = globals()

    # We cast to 64-bit integer manually below (otherwise, we would add the type
    # signature information to each function.
    context['_CRYPTO_SECRETBOX_ZEROBYTES'] = \
        _sodium.crypto_secretbox_zerobytes() % pow(2, 64)
    context['_CRYPTO_SECRETBOX_BOXZEROBYTES'] = \
        _sodium.crypto_secretbox_boxzerobytes() % pow(2, 64)
    context['_CRYPTO_SECRETBOX_NONCEBYTES'] = \
        _sodium.crypto_secretbox_noncebytes() % pow(2, 64)
    context['_CRYPTO_SECRETBOX_MESSAGEBYTES_MAX'] = \
        _sodium.crypto_secretbox_messagebytes_max() % pow(2, 64)
    context['_CRYPTO_SECRETBOX_KEYBYTES'] = \
            _sodium.crypto_secretbox_keybytes() % pow(2, 64)
    context['_CRYPTO_BOX_SEALBYTES'] = \
        _sodium.crypto_box_sealbytes() % pow(2, 64)
    context['_CRYPTO_BOX_PUBLICKEYBYTES'] = \
        _sodium.crypto_box_publickeybytes() % pow(2, 64)
    context['_CRYPTO_SCALARMULTBYTES'] = \
        _sodium.crypto_scalarmult_bytes() % pow(2, 64)

    assert _CRYPTO_BOX_PUBLICKEYBYTES == _CRYPTO_SCALARMULTBYTES

    context['_crypto_scalarmult_bytes_new'] = \
        ctypes.c_char * _CRYPTO_SCALARMULTBYTES

    # Define static class attributes.
    nonce.length = context['_CRYPTO_SECRETBOX_NONCEBYTES']
    secret.length = context['_CRYPTO_SECRETBOX_KEYBYTES']
    public.length = context['_CRYPTO_BOX_PUBLICKEYBYTES']

# Check that libsodium is not already initialized and initialize it
# (unless documentation is being automatically generated).
if not os.environ.get('BCL_SPHINX_AUTODOC_BUILD', None) == '1':
    _sodium_init()

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover

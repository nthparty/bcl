===
bcl
===

Python library that provides a simple interface for symmetric (i.e., secret-key) and asymmetric (i.e., public-key) encryption/decryption primitives.

|pypi|

.. |pypi| image:: https://badge.fury.io/py/bcl.svg
   :target: https://badge.fury.io/py/bcl
   :alt: PyPI version and link.

Purpose
-------
This library provides simple and straightforward methods for symmetric (i.e., secret-key) and asymmetric (i.e., public-key) cryptographic encryption and decryption capabilities. The library's interface is designed for ease of use and therefore hides from users some of the flexibilities and performance trade-offs that can be leveraged via direct use of the underlying libraries.

The library's name is a reference to `Boron trichloride <https://en.wikipedia.org/wiki/Boron_trichloride>`, as it is a wrapper for a limited set of capabilities found in `PyNaCl <https://pypi.org/project/PyNaCl/>` (which is itself a wrapper library for `libsodium <https://doc.libsodium.org/>`). However, it can also be an acronym for "basic cryptographic library".

Package Installation and Usage
------------------------------
The package is available on PyPI::

    python -m pip install bcl

The library can be imported in the usual ways::

    import bcl
    from bcl import *

Testing and Conventions
-----------------------
All unit tests are executed and their coverage is measured when using `nose <https://nose.readthedocs.io/>`_ (see ``setup.cfg`` for configution details)::

    nosetests

Alternatively, all unit tests are included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`_::

    python bcl/bcl.py -v

Style conventions are enforced using `Pylint <https://www.pylint.org/>`_::

    pylint bcl

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the GitHub page for this library.

Versioning
----------
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.

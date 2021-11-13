===
bcl
===

Python library that provides a simple interface for symmetric (*i.e.*, secret-key) and asymmetric (*i.e.*, public-key) encryption/decryption primitives.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/bcl.svg
   :target: https://badge.fury.io/py/bcl
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/bcl/badge/?version=latest
   :target: https://bcl.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nthparty/bcl/workflows/lint-test-build-upload/badge.svg
   :target: https://github.com/nthparty/bcl/actions
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/nthparty/bcl/badge.svg?branch=main
   :target: https://coveralls.io/github/nthparty/bcl?branch=main
   :alt: Coveralls test coverage summary.

Purpose
-------
This library provides simple and straightforward methods for symmetric (*i.e.*, secret-key) and asymmetric (*i.e.*, public-key) cryptographic encryption and decryption capabilities. The library's interface is designed for ease of use and therefore hides from users some of the flexibilities and performance trade-offs that can be leveraged via direct use of the underlying cryptographic libraries.

The library's name is a reference to `boron trichloride <https://en.wikipedia.org/wiki/Boron_trichloride>`_, as it is a wrapper and binding for a limited set of capabilities found in `libsodium <https://doc.libsodium.org/>`_. However, it can also be an acronym for *basic cryptographic library*.

Package Installation and Usage
------------------------------
The package is available on `PyPI <https://pypi.org/project/bcl/>`_::

    python -m pip install bcl

The library can be imported in the usual ways::

    import bcl
    from bcl import *

Examples
^^^^^^^^
This library provides concise methods for implementing symmetric encryption workflows::

    >>> from bcl import symmetric
    >>> s = symmetric.secret() # Generate a secret key.
    >>> c = symmetric.encrypt(s, 'abc'.encode())
    >>> symmetric.decrypt(s, c).decode('utf-8')
    'abc'

Asymmetric encryption workflows are also supported::

    >>> from bcl import asymmetric
    >>> s = asymmetric.secret() # Generate a secret key.
    >>> p = asymmetric.public(s) # Generate a corresponding public key.
    >>> c = asymmetric.encrypt(p, 'abc'.encode())
    >>> asymmetric.decrypt(s, c).decode('utf-8')
    'abc'

The library also provides a number of classes for representing keys (secret and public), nonces, plaintexts, and ciphertexts. All methods expect and return instances of the appropriate classes::

    >>> from bcl import secret, public, cipher
    >>> s = asymmetric.secret()
    >>> isinstance(s, secret)
    True
    >>> p = asymmetric.public(s)
    >>> isinstance(p, public)
    True
    >>> c = symmetric.encrypt(s, 'abc'.encode())
    >>> type(c)
    <class 'bcl.bcl.cipher'>
    >>> symmetric.decrypt(bytes(s), c)
    Traceback (most recent call last):
      ...
    TypeError: can only decrypt using a symmetric secret key
    >>> symmetric.decrypt(s, bytes(c))
    Traceback (most recent call last):
      ...
    TypeError: can only decrypt a ciphertext

Furthermore, the above classes are derived from ``bytes``, so `all methods and other operators <https://docs.python.org/3/library/stdtypes.html#bytes>`_ supported by ``bytes`` objects are supported::

    >>> p.hex()
    '0be9cece7fee92809908bd14666eab96b77deebb488c738445d842a6613b7b48'

In addition, Base64 conversion methods are included for all of the above classes to support concise encoding and decoding of objects::

    >>> p.to_base64()
    'C+nOzn/ukoCZCL0UZm6rlrd97rtIjHOERdhCpmE7e0g='
    >>> b = 'C+nOzn/ukoCZCL0UZm6rlrd97rtIjHOERdhCpmE7e0g='
    >>> type(public.from_base64(b))
    <class 'bcl.bcl.public'>

Development, Build, and Manual Installation Instructions
--------------------------------------------------------
Developing the library further in a local environment and/or building the library from source requires retrieving and compiling `libsodium <https://doc.libsodium.org/>`_.

Building from Source
^^^^^^^^^^^^^^^^^^^^
The library can be built manually from source **within Linux and macOS** using the sequence of commands below::

    python -m pip install setuptools wheel cffi
    python setup.py bdist_wheel

The step ``python setup.py bdist_wheel`` in the above attempts to automatically locate a copy of the libsodium source archive ``bcl/libsodium.tar.gz``. If the archive corresponding to the operating system is not found, the build process attempts to download it. To support building offline, it is necessary to first download the appropriate libsodium archive to its designated location::

    wget -O bcl/libsodium.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz

The process for building manually from source within a Windows environment is not currently documented, but an example of one sequence of steps can be found in the Windows job entry within the GitHub Actions workflow defined in the file ``.github/workflows/lint-test-build-upload.yml``.

Preparation for Local Development
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Before `documentation can be generated <#documentation>`_ or `tests can be executed <#testing-and-conventions>`_, it is necessary to `run the build process <#building-from-source>`_ and then to use the command below to move the compiled libsodium shared/dynamic library file into its designated location (so that the module file ``bcl/bcl.py`` is able to import it)::

    cp build/lib*/bcl/_sodium*.* bcl

Manual Installation
^^^^^^^^^^^^^^^^^^^
Once the package is `built <#building-from-source>`_, it can be installed manually using the command below::

    python -m pip install -f dist --no-index bcl --upgrade

Documentation
-------------
.. include:: toc.rst

Once the libsodium shared library file is compiled and moved into its designated location (as described in `the relevant subsection above <#preparation-for-local-development>`_), the documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org/>`_::

    cd docs
    python -m pip install -r requirements.txt
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. ../setup.py ../bcl/sodium_ffi.py && make html

Testing and Conventions
-----------------------
Before unit tests can be executed, it is first necessary to prepare for local development by compiling and moving into its designated location the libsodium shared library file (as described in `the relevant subsection above <#preparation-for-local-development>`_).

All unit tests are executed and their coverage is measured when using `nose <https://nose.readthedocs.io/>`_ (see ``setup.cfg`` for configution details)::

    python -m pip install nose coverage
    nosetests --cover-erase

Alternatively, all unit tests are included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`_::

    python bcl/bcl.py -v

Style conventions are enforced using `Pylint <https://www.pylint.org/>`_::

    python -m pip install pylint
    pylint bcl

Publishing (for Maintainers Only)
---------------------------------
The package can be published on PyPI by a package maintainer. First, remove any old build/distribution files and package the source distribution::

    rm -rf dist && rm -rf bcl.egg-info
    python setup.py sdist

Next, navigate to the appropriate GitHub Actions run of the workflow defined in ``lint-test-build-upload.yml``. Click on the workflow and scroll down to the **Artifacts** panel.  Download the archive files to the ``dist`` directory. Unzip all the archive files so that only the ``*.whl`` files remain::

    cd dist && for i in `ls *.zip`; do unzip $i; done && rm *.zip && cd ..

Finally, upload the package distribution archive to PyPI::

    python -m pip install twine
    twine upload dist/*

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/bcl>`_ for this library.

Versioning
----------
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.

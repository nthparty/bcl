===
bcl
===

Python library that provides a simple interface for symmetric (*i.e.*, secret-key) and asymmetric (*i.e.*, public-key) encryption/decryption primitives.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/bcl.svg#
   :target: https://badge.fury.io/py/bcl
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/bcl/badge/?version=latest
   :target: https://bcl.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nthparty/bcl/workflows/build-lint-test-cover-docs-upload/badge.svg#
   :target: https://github.com/nthparty/bcl/actions
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/nthparty/bcl/badge.svg?branch=main
   :target: https://coveralls.io/github/nthparty/bcl?branch=main
   :alt: Coveralls test coverage summary.

Purpose
-------
This library provides simple and straightforward methods for symmetric (*i.e.*, secret-key) and asymmetric (*i.e.*, public-key) cryptographic encryption and decryption capabilities. The library's interface is designed for ease of use and therefore hides from users some of the flexibilities and performance trade-offs that can be leveraged via direct use of the underlying cryptographic libraries.

The library's name is a reference to `boron trichloride <https://en.wikipedia.org/wiki/Boron_trichloride>`__, as it is a wrapper and binding for a limited set of capabilities found in `libsodium <https://doc.libsodium.org>`__. However, it can also be an acronym for *basic cryptographic library*.

Installation and Usage
----------------------
This library is available as a `package on PyPI <https://pypi.org/project/bcl>`__:

.. code-block:: bash

    python -m pip install bcl

The library can be imported in the usual manner:

.. code-block:: python

    import bcl
    from bcl import *

Examples
^^^^^^^^

.. |symmetric| replace:: symmetric
.. _symmetric: https://bcl.readthedocs.io/en/3.0.0/_source/bcl.html#bcl.bcl.symmetric

This library provides concise methods for implementing |symmetric|_ encryption workflows:

.. code-block:: python

    >>> from bcl import symmetric
    >>> s = symmetric.secret() # Generate a secret key.
    >>> c = symmetric.encrypt(s, 'abc'.encode())
    >>> symmetric.decrypt(s, c).decode('utf-8')
    'abc'

.. |Asymmetric| replace:: Asymmetric
.. _Asymmetric: https://bcl.readthedocs.io/en/3.0.0/_source/bcl.html#bcl.bcl.asymmetric

|Asymmetric|_ encryption workflows are also supported:

.. code-block:: python

    >>> from bcl import asymmetric
    >>> s = asymmetric.secret() # Generate a secret key.
    >>> p = asymmetric.public(s) # Generate a corresponding public key.
    >>> c = asymmetric.encrypt(p, 'abc'.encode())
    >>> asymmetric.decrypt(s, c).decode('utf-8')
    'abc'

.. |keys| replace:: keys
.. _keys: https://bcl.readthedocs.io/en/3.0.0/_source/bcl.html#bcl.bcl.key

.. |secret| replace:: secret
.. _secret: https://bcl.readthedocs.io/en/3.0.0/_source/bcl.html#bcl.bcl.secret

.. |public| replace:: public
.. _public: https://bcl.readthedocs.io/en/3.0.0/_source/bcl.html#bcl.bcl.public

.. |nonces| replace:: nonces
.. _nonces: https://bcl.readthedocs.io/en/3.0.0/_source/bcl.html#bcl.bcl.nonce

.. |plaintexts| replace:: plaintexts
.. _plaintexts: https://bcl.readthedocs.io/en/3.0.0/_source/bcl.html#bcl.bcl.plain

.. |ciphertexts| replace:: ciphertexts
.. _ciphertexts: https://bcl.readthedocs.io/en/3.0.0/_source/bcl.html#bcl.bcl.cipher

This library also provides a number of classes for representing |keys|_ (|secret|_ and |public|_), |nonces|_, |plaintexts|_, and |ciphertexts|_. All methods expect and return instances of the appropriate classes:

.. code-block:: python

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

.. |bytes| replace:: ``bytes``
.. _bytes: https://docs.python.org/3/library/stdtypes.html#bytes

Furthermore, the above classes are derived from |bytes|_, so `all methods and other operators <https://docs.python.org/3/library/stdtypes.html#bytes>`__ supported by |bytes|_ objects are supported:

.. code-block:: python

    >>> p.hex()
    '0be9cece7fee92809908bd14666eab96b77deebb488c738445d842a6613b7b48'

In addition, Base64 conversion methods are included for all of the above classes to support concise encoding and decoding of objects:

.. code-block:: python

    >>> p.to_base64()
    'C+nOzn/ukoCZCL0UZm6rlrd97rtIjHOERdhCpmE7e0g='
    >>> b = 'C+nOzn/ukoCZCL0UZm6rlrd97rtIjHOERdhCpmE7e0g='
    >>> type(public.from_base64(b))
    <class 'bcl.bcl.public'>

Development, Build, and Manual Installation Instructions
--------------------------------------------------------
All development and installation dependencies are managed using `setuptools <https://pypi.org/project/setuptools>`__ and are fully specified in ``setup.cfg``. The ``extras_require`` option is used to `specify optional requirements <https://setuptools.pypa.io/en/latest/userguide/dependency_management.html#optional-dependencies>`__ for various development tasks. This makes it possible to specify additional options (such as ``docs``, ``lint``, and so on) when performing installation using `pip <https://pypi.org/project/pip>`__ (assuming that the library has already been built successfully):

.. code-block:: bash

    python -m pip install ".[docs,lint]"

Building from Source
^^^^^^^^^^^^^^^^^^^^
The library can be built manually from source **within Linux and macOS** using the sequence of commands below:

.. code-block:: bash

    python -m pip install ".[build]"
    python -m build --sdist --wheel .

Developing the library further in a local environment and/or building the library from source requires `libsodium <https://doc.libsodium.org>`__. The step ``python -m build --sdist --wheel .`` in the above attempts to automatically locate a copy of the libsodium source archive ``src/bcl/libsodium.tar.gz``. If the archive corresponding to the operating system is not found, the build process attempts to download it. To support building offline, it is necessary to first download the appropriate libsodium archive to its designated location:

.. code-block:: bash

    wget -O src/bcl/libsodium.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz

The process for building manually from source within a Windows environment is not currently documented, but an example of one sequence of steps can be found in the Windows job entry within the GitHub Actions workflow defined in the file ``.github/workflows/build-lint-test-cover-docs-upload.yml``.

Preparation for Local Development
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Before `documentation can be generated <#documentation>`_ or `tests can be executed <#testing-and-conventions>`_, it is necessary to `run the build process <#building-from-source>`_ and then to use the command below to move the compiled libsodium shared/dynamic library file into its designated location (so that the module file ``src/bcl/bcl.py`` is able to import it):

.. code-block:: bash

    cp build/lib*/bcl/_sodium.py src/bcl

Manual Installation
^^^^^^^^^^^^^^^^^^^
Once the package is `built <#building-from-source>`_, it can be installed manually using the command below:

.. code-block:: bash

    python -m pip install -f dist . --upgrade

Documentation
^^^^^^^^^^^^^
Once the libsodium shared library file is compiled and moved into its designated location (as described in `the relevant subsection above <#preparation-for-local-development>`_), the documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org>`__:

.. code-block:: bash

    python -m pip install ".[docs]"
    cd docs
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. ../src/bcl/_sodium_build.py && make html

Testing and Conventions
^^^^^^^^^^^^^^^^^^^^^^^
Before unit tests can be executed, it is first necessary to prepare for local development by compiling and moving into its designated location the libsodium shared library file (as described in `the relevant subsection above <#preparation-for-local-development>`__).

All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org>`__ (see ``pyproject.toml`` for configuration details):

.. code-block:: bash

    python -m pip install ".[test]"
    python -m pytest

Alternatively, all unit tests are included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`__:

.. code-block:: bash

    python src/bcl/bcl.py -v

Style conventions are enforced using `Pylint <https://pylint.readthedocs.io>`__:

.. code-block:: bash

    python -m pip install ".[lint]"
    python -m pylint src/bcl src/bcl/_sodium.tmpl src/bcl/_sodium_build.py --disable=duplicate-code

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/bcl>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/bcl>`__ via the GitHub Actions workflow found in ``.github/workflows/build-publish-sign-release.yml`` that follows the `recommendations found in the Python Packaging User Guide <https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/>`__.

Ensure that the correct version number appears in ``setup.cfg``, and that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions.

To publish the package, create and push a tag for the version being published (replacing ``?.?.?`` with the version number):

.. code-block:: bash

    git tag ?.?.?
    git push origin ?.?.?

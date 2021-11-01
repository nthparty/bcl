===
bcl
===

Python library that provides a simple interface for symmetric (*i.e.*, secret-key) and asymmetric (*i.e.*, public-key) encryption/decryption primitives.

|pypi| |readthedocs|

.. |pypi| image:: https://badge.fury.io/py/bcl.svg
   :target: https://badge.fury.io/py/bcl
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/bcl/badge/?version=latest
   :target: https://bcl.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

Purpose
-------
This library provides simple and straightforward methods for symmetric (*i.e.*, secret-key) and asymmetric (*i.e.*, public-key) cryptographic encryption and decryption capabilities. The library's interface is designed for ease of use and therefore hides from users some of the flexibilities and performance trade-offs that can be leveraged via direct use of the underlying libraries.

The library's name is a reference to `boron trichloride <https://en.wikipedia.org/wiki/Boron_trichloride>`_, as it is a wrapper and binding for a limited set of capabilities found in `libsodium <https://doc.libsodium.org/>`_. However, it can also be an acronym for *basic cryptographic library*.

Package Installation and Usage
------------------------------
The package is available on `PyPI <https://pypi.org/project/bcl/>`_::

    python -m pip install bcl

The library can be imported in the usual ways::

    import bcl
    from bcl import *

Manual Installation (via Building from Source)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The package can be installed manually using the below sequence of commands::

    python -m pip install wheel
    python setup.py bdist_wheel
    python -m pip install -f dist --no-index bcl --upgrade

Preparation for Local Development
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Before documentation can be generated or tests can be executed, it is necessary to build the module and retrieve the compiled libsodium shared/dynamic library file so that the module file in the source tree has access to it::

    python setup.py bdist_wheel && cp build/lib*/bcl/_sodium*.* bcl

Documentation
-------------
.. include:: toc.rst

Once the libsodium shared library file is compiled and moved into its designated location (as described in `the relevant subsection above <#preparation-for-local-development>`_), the documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org/>`_::

    cd docs
    python -m pip install -r requirements.txt
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. ../setup.py && make html

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
The package can be published on PyPI by a package maintainer. First, package the source distribution::

    python setup.py sdist

Next, run ``wheel-builder.yml`` and save/download the built artifacts locally, (*e.g.*, in ``./dist``). Finally, upload the package distribution archive to PyPI (replacing ``?.?.?`` with the appropriate version number)::

    twine upload dist/bcl-?.?.?*

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/bcl>`_ for this library.

Versioning
----------
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.

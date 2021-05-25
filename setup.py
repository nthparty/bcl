from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name="bcl",
    version="1.0.0",
    packages=["bcl",],
    install_requires=["pynacl",],
    license="MIT",
    url="https://github.com/nthparty/bcl",
    author="Andrei Lapets",
    author_email="a@lapets.io",
    description="Python library that provides a simple interface "+\
                "for symmetric (i.e., secret-key) and asymmetric "+\
                "(i.e., public-key) encryption/decryption primitives.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    test_suite="nose.collector",
    tests_require=["nose"],
)

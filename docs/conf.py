# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
sys.path.insert(0, os.path.abspath('../src')) # Prioritize local module copy.

# Set environment variable so that module can detect that documentation is
# being generated.
os.environ['BCL_SPHINX_AUTODOC_BUILD'] = '1'

# -- Project information -----------------------------------------------------

# The name and version are retrieved from ``setup.cfg`` in the root directory.
from configparser import ConfigParser
setup_config = ConfigParser()
setup_config.read('../setup.cfg')
project = setup_config['metadata']['name']
version = setup_config['metadata']['version']
release = version

# The copyright year and holder information is retrieved from the
# ``LICENSE`` file.
import re
with open('../LICENSE', 'r') as license_file:
    license_string = license_file.read().split('Copyright (c) ')[1]
year = license_string[:4]
author = license_string[5:].split('\n')[0]
copyright = year + ', ' + re.sub(r"\.$", "", author) # Period already in HTML.


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.napoleon',
    'sphinx.ext.intersphinx',
    'sphinx.ext.viewcode'
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build']

# Options to configure autodoc extension behavior.
autodoc_member_order = 'bysource'
autodoc_default_options = {
    'special-members': True,
    'exclude-members': ','.join([
        '__init__',
        '__weakref__',
        '__module__',
        '__hash__',
        '__dict__',
        '__annotations__'
    ])
}
autodoc_preserve_defaults = True
autodoc_mock_imports = ['_sodium']

# Allow references/links to definitions found in the Python documentation
# and in the documentation for this package's dependencies.

def rtd_url_for_installed_version(name):
    prefix = 'https://' + name + '.readthedocs.io/en/'

    if sys.version_info.major == 3 and sys.version_info.minor == 7:
        import pkg_resources
        return prefix + pkg_resources.get_distribution(name).version

    import importlib.metadata
    return prefix + importlib.metadata.version(name)

intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'barriers': (rtd_url_for_installed_version('barriers'), None)
}


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Theme options for Read the Docs.
html_theme_options = {
    'collapse_navigation': True,
    'navigation_depth': 1,
    'titles_only': True
}

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import sys
from pathlib import Path
# sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path('..', '..', 'src').resolve()))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Asgard'
copyright = '2025, Sereysethy Touch'
author = 'Sereysethy Touch'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.duration',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.napoleon',
]

# autoclass_content = "both"  # merge class and __init__ docstrings
autodoc_typehints = "both"  # show types from signature
autodoc_default_options = {
    "member-order": "bysource",
    "members": True,
    "special-members": True,
}

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']


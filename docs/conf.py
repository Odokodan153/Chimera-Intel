# docs/conf.py


import os
import sys

# Add the project's source directory to the path so Sphinx can find the modules

sys.path.insert(0, os.path.abspath("../src"))

# -- Project information -----------------------------------------------------

project = "Chimera Intel"
copyright = "2025, Ignacio Iliev"
author = "Ignacio Iliev"
release = "6.0.0"

# -- General configuration ---------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",  # Main extension to pull documentation from docstrings
    "sphinx.ext.napoleon",  # To understand Google-style docstrings
    "sphinx.ext.viewcode",  # To add links to the source code in the docs
    "sphinx.ext.todo",  # To show "todo" notes
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"  # A professional, modern theme like ReadTheDocs
html_static_path = ["_static"]

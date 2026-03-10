"""Sphinx configuration for the apatchy documentation."""

import sys
from pathlib import Path

# Path setup
# Add the package source tree so autodoc can import the modules.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "framework" / "src"))

# Project information
project = "apatchy"
copyright = "2025, faulty *ptrrr"
author = "@0xbigshaq"
release = "0.1.0"

# General configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx_autodoc_typehints",
    "myst_parser",
    "sphinxcontrib.mermaid",
    "sphinx_design",
    "sphinx_rtd_dark_mode",
    "sphinxcontrib.doxylink",
]

# Recognise both RST and Markdown source files
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

exclude_patterns = ["_build", "api/_build"]

# Napoleon settings (Google & NumPy style docstrings)
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True

# Autodoc settings
autodoc_member_order = "bysource"
autodoc_typehints = "description"

# Intersphinx mapping to Python stdlib docs
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# MyST-Parser settings 
# Map ```mermaid fenced blocks to the sphinxcontrib-mermaid directive
myst_fence_as_directive = ["mermaid"]
myst_enable_extensions = ["colon_fence"]
myst_heading_anchors = 3

# Doxylink settings (Apache HTTPD API cross-references) 
_docs_dir = Path(__file__).resolve().parent
doxylink = {
    "httpd": (
        str(_docs_dir / "_doxygen" / "httpd.tag"),
        "doxygen/",
    ),
}
doxylink_parse_error_ignore_regexes = [
    r"AP_DECLARE_HOOK",
    r"APR_DECLARE",
    r"APR_IMPLEMENT",
    r"__attribute__",
    r"STACK_OF",
    r"IDCONST",
]

# Mermaid settings 
mermaid_output_format = "raw"
mermaid_init_config = {"startOnLoad": False}

# Options for HTML output 
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_js_files = ["mermaid-panzoom.js"]
html_theme = "sphinx_rtd_theme"
html_logo = "./apatchy-logo-transparent.png"
html_favicon = "./apatchy-logo-transparent.png"
html_theme_options = {
    "collapse_navigation": True,
    "sticky_navigation": True,
    "navigation_depth": -1,
    "includehidden": True,
    "titles_only": False,
    "logo_only": False,
}

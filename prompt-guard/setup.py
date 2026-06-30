# Compatibility shim. All real metadata lives in pyproject.toml ([project] table).
# This lets `pip install -e .` work on older pip (< 21.3) that predates PEP 660
# editable installs, as long as setuptools >= 61 is present.
from setuptools import setup

setup()

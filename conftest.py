"""
Puts src/ on sys.path so tests can import the modules the same flat way
app.py does (``from analysis import ...``). Keeps ``python src\app.py``
working unchanged while making the package importable under pytest.
"""

import os
import sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")

if SRC not in sys.path:
    sys.path.insert(0, SRC)

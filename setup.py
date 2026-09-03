#!/usr/bin/env python3

"""c65of setup script"""

import sys

from setuptools import setup

if sys.version_info < (3, 11):
    print(
        "c65of requires python 3.11 or newer, not {py}".format(
            py=".".join([str(v) for v in sys.version_info[:3]])
        ),
        file=sys.stderr,
    )
    sys.exit(1)

setup(
    name="c65of",
    setup_requires=["pbr>=1.9", "setuptools>=17.1"],
    python_requires=">=3.11",
    pbr=True,
)

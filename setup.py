#!/usr/bin/env python3
import ast
import os

import setuptools


setup_path = os.path.dirname(__file__)

# Get __version__ from the module without importing it
with open(os.path.join(setup_path, "aia.py")) as dinit:
    assignment_node = next(
        el for el in ast.parse(dinit.read()).body
        if isinstance(el, ast.Assign) and el.targets[0].id == "__version__"
    )
    version = ast.literal_eval(assignment_node.value)

with open(os.path.join(setup_path, "README.md")) as readme:
    long_description = readme.read()


setuptools.setup(
    name="aia",
    version=version,
    author="Danilo de Jesus da Silva Bellini",
    author_email="danilo.bellini@gmail.com",
    url="https://github.com/danilobellini/aia",
    description="AIA chasing through OpenSSL for TLS certificate chain "
                "building and verifying",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="2-clause BSD",
    py_modules=["aia"],
    include_package_data=True,
    python_requires=">=3.6",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",  # Assuming OpenSSL is available
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking",
    ],
)

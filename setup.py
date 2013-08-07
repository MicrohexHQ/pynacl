#!/usr/bin/env python
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand
from distutils.command.build import build as _build

import nacl

try:
    import nacl.nacl
except ImportError:
    # installing - there is no cffi yet
    ext_modules = []
else:
    # building bdist - cffi is here!
    ext_modules = [nacl.nacl.ffi.verifier.get_extension()]

class Build(_build):
    def run(self):
        _build.run(self)
        # after building the python code, build libsodium and install it into
        # the build directory
        print "HERE"

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


setup(
    name=nacl.__title__,
    version=nacl.__version__,

    description=nacl.__summary__,
    long_description=open("README.rst").read(),
    url=nacl.__uri__,
    license=nacl.__license__,

    author=nacl.__author__,
    author_email=nacl.__email__,

    install_requires=[
        "cffi",
    ],
    extras_require={
        "tests": ["pytest"],
    },
    tests_require=["pytest"],

    packages=[
        "nacl",
        "nacl.invoke",
    ],

    ext_package="nacl",
    ext_modules=ext_modules,

    zip_safe=False,
    cmdclass={"test": PyTest, "build": Build},

    classifiers=[
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
    ]
)

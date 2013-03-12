#!/usr/bin/python
from distutils.core import setup, Extension

VERSION = "1.1"

setup(name="python-mcrypt",
      version = VERSION,
      description = "Python interface to mcrypt library",
      author = "Gustavo Niemeyer",
      author_email = "niemeyer@conectiva.com",
      license = "LGPL",
      long_description = \
"""
Python interface to mcrypt library.
""",
      ext_modules = [Extension("mcrypt",
      			       ["mcrypt.c"],
			       libraries=["mcrypt"],
			       define_macros=[("VERSION", '"%s"'%VERSION)])],
      )

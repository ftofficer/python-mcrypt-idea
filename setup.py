#!/usr/bin/python

import os.path
from subprocess import check_call
import shutil

try:
    from setuptools import setup, Extension
    from setuptools.command.build_ext import build_ext
except ImportError:
    from distutils.core import setup, Extension
    from distutils.command.build_ext import build_ext
    
from distutils import log

VERSION = "1.1"
LIBMCRYPT_MODULE = 'libmcrypt-2.5.8'

libmcrypt_base = os.path.join(os.path.dirname(__file__), LIBMCRYPT_MODULE)
libmcrypt_lib_dir = os.path.join(libmcrypt_base, 'lib', '.libs')
libmcrypt_include = os.path.join(libmcrypt_base, 'include')

mcrypt_module = Extension("_mcrypt",
                          ["_mcrypt.c"],
                          libraries=['mcrypt'],
                          library_dirs=[libmcrypt_lib_dir],
                          include_dirs=[libmcrypt_include],
                          define_macros=[("VERSION", '"%s"'%VERSION)])

class build_ext_with_libmcrypt(build_ext):
    def run(self):
        self._build_libmcrypt()
        self._collect_libmcrypt_modules('algorithms')
        self._collect_libmcrypt_modules('modes')
        build_ext.run(self)

    def _build_libmcrypt(self):
        # Build libmcrypt
        check_call(['sh', 'configure', '--enable-shared', '--enable-static'],
                   cwd=libmcrypt_base)
        check_call(['make'], cwd=libmcrypt_base)

    def _collect_libmcrypt_modules(self, name):
        source_dir = os.path.join(libmcrypt_base, 'modules', name, '.libs')
        target_dir = os.path.join(os.path.join('mcrypt', 'modules', name))

        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        for module in os.listdir(source_dir):
            if module.endswith('.so'):
                source = os.path.join(source_dir, module)
                target = os.path.join(target_dir, module)
                log.info('Collect libmcrypt module: %s => %s', source, target)
                shutil.copyfile(source, target)
                

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
      packages = ['mcrypt'],
      
      ext_modules = [mcrypt_module],
      cmdclass = {'build_ext': build_ext_with_libmcrypt},
      )

#!/usr/bin/python

import os.path
from subprocess import check_call, call
import shutil

try:
    from setuptools import setup, Extension
    from setuptools.command.build_ext import build_ext
    from setuptools.cmd import Command
except ImportError:
    from distutils.core import setup, Extension
    from distutils.command.build_ext import build_ext
    from distutils.cmd import Command
    
from distutils import log

VERSION = "1.2.2"
LIBMCRYPT_MODULE = 'libmcrypt-2.5.8'

libmcrypt_base = os.path.join(os.path.dirname(__file__), LIBMCRYPT_MODULE)

libmcrypt_dist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'libmcrypt'))
libmcrypt_include = os.path.join(libmcrypt_dist_dir, 'include')
libmcrypt_lib_dir = os.path.join(libmcrypt_dist_dir, 'lib')

mcrypt_module = Extension("mcrypt",
                          ["mcrypt.c"],
                          extra_objects=[os.path.join(libmcrypt_lib_dir, 'libmcrypt.a')],
                          include_dirs=[libmcrypt_include],
                          define_macros=[("VERSION", '"%s"'%VERSION)])

class build_ext_with_libmcrypt(build_ext):
    def run(self):
        log.info('Build libmcrypt...')
        self._build_libmcrypt()
        
        build_ext.run(self)

    def _build_libmcrypt(self):
        # Build libmcrypt
        call(['make', 'distclean'], cwd=libmcrypt_base)
        check_call(['sh', 'configure', '--prefix=%s' % libmcrypt_dist_dir,
                    '--enable-shared', '--enable-static',
                    '--with-pic'],
                   cwd=libmcrypt_base)
        check_call(['make'], cwd=libmcrypt_base)
        check_call(['make', 'install'], cwd=libmcrypt_base)
        

    def _collect_libmcrypt_modules(self, name):
        source_dir = os.path.join(libmcrypt_dist_dir, )
        target_dir = os.path.join(os.path.join('mcrypt', 'modules', name))
        log.info('Collect libmcrypt modules from %s to %s...', source_dir, target_dir)

        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        for module in os.listdir(source_dir):
            if module.endswith('.so'):
                source = os.path.join(source_dir, module)
                target = os.path.join(target_dir, module)
                log.info('Collect libmcrypt module: %s => %s', source, target)
                shutil.copyfile(source, target)
        

setup(name="python-mcrypt-idea",
      version = VERSION,
      description = "Python interface to mcrypt library, with IDEA compile in",
      author = "Cong Zhang",
      author_email = "ftofficer@ftofficer.com",
      license = "LGPL",
      long_description = \
"""
Python interface to mcrypt library, derived from http://labix.org/python-mcrypt and added IDEA.
""",
      include_package_data = True,
      ext_modules = [mcrypt_module],
      cmdclass = {'build_ext': build_ext_with_libmcrypt},
    )

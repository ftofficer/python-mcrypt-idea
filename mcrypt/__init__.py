"""Module proxy for c module _mcrypt, setting default algorithms and modes directory."""

import _mcrypt
import os.path

_MODULES_DIR = os.path.join(os.path.dirname(__file__), 'modules')

_mcrypt.set_algorithm_dir(os.path.join(_MODULES_DIR, 'algorithms'))
_mcrypt.set_mode_dir(os.path.join(_MODULES_DIR, 'modes'))

MCRYPT = _mcrypt.MCRYPT
MCRYPTError = _mcrypt.MCRYPTError

__all__ = ('MCRYPT', 'MCRYPTError')


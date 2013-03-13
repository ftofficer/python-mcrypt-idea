"""Module proxy for c module _mcrypt, setting default algorithms and modes directory."""

import _mcrypt
import os.path

_mcrypt.set_algorithm_dir(

#!/usr/bin/env python3
"""
DEPRECATED: Use the new 'apttrail' package instead.

This script is kept for backward compatibility and will be removed in future versions.
Please update your workflows to use: python -m apttrail
"""

import sys
import warnings
from apttrail.cli import main

if __name__ == "__main__":
    warnings.warn(
        "This script is deprecated. Please use 'python -m apttrail' instead.",
        DeprecationWarning,
        stacklevel=2
    )
    sys.exit(main())
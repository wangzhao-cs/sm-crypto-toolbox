"""``python -m smcrypto`` 入口（等价于 ``smctl``）。"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

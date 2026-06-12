#!/usr/bin/env python3
"""chainmail entry point shim.

Allows running the tool directly from a checkout without installation:

    python3 chainmail.py user@host --password 'pw'
    python3 chainmail.py user@host -i ~/.ssh/id_rsa
"""
from chainmail.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

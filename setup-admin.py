#!/usr/bin/env python3
"""Configure or reset the Router Manager administrator password."""
import getpass
import os
from auth import set_password

if os.geteuid() != 0:
    raise SystemExit('Run as root: sudo python3 setup-admin.py')
password = getpass.getpass('New Router Manager admin password (12+ characters): ')
if password != getpass.getpass('Confirm password: '):
    raise SystemExit('Passwords do not match')
set_password(password)
print('Administrator password updated; previous sessions invalidated.')

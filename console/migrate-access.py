"""Additive access-policy migration with a root-only online SQLite backup."""
import os
from pathlib import Path
import sqlite3
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import controller as ctl
from common import lock

if os.geteuid()!=0:raise SystemExit('root required')
os.umask(0o077)
with lock(ctl.HOME/'lock'):
    backup=ctl.HOME/('before-access-policy-'+str(time.time_ns())+'.sqlite')
    source=sqlite3.connect(ctl.DB)
    target=sqlite3.connect(backup)
    try:source.backup(target)
    finally:target.close();source.close()
    backup.chmod(0o600)
    d=ctl.database()
    try:
        assert d.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        print('Migration complete. Existing plans retain tag matching. Backup:',backup)
    finally:d.close()

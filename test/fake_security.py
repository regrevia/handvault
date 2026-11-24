#!/usr/bin/env python3
"""测试用的假 security。只实现 handvault 用到的那几条命令。

add-generic-password：真 security 用裸 -w 时会从 tty 问两次，这里照样读两行，
所以这条路径测的就是 handvault 的 pty 喂值逻辑。
"""
import json
import os
import sys

store = os.environ['FAKE_STORE']
path = os.path.join(store, 'db.json')
db = json.load(open(path)) if os.path.exists(path) else {}

a = sys.argv[1:]


def val(flag, default=None):
    return a[a.index(flag) + 1] if flag in a else default


key = str(val('-s')) + '\0' + str(val('-a'))

if a[0] == 'add-generic-password':
    first = sys.stdin.readline().rstrip('\n')
    try:
        sys.stdin.readline()
    except Exception:
        pass
    db[key] = first
    with open(path, 'w') as f:
        json.dump(db, f)
    sys.exit(0)

if a[0] == 'find-generic-password':
    if key not in db:
        sys.exit(44)
    if '-w' in a:
        sys.stdout.write(db[key] + '\n')
    sys.exit(0)

if a[0] == 'delete-generic-password':
    if key not in db:
        sys.exit(44)
    del db[key]
    with open(path, 'w') as f:
        json.dump(db, f)
    sys.exit(0)

sys.exit(2)

#!/usr/bin/env python3
"""handvault — 人输密码，agent 只拿到长度。

agent 需要一份凭据时，跑 `handvault put SERVICE ACCOUNT`。人把密码打进来
（不回显）、直接进系统钥匙串；等着的那个进程只收到一个长度和一个字节数
都对不上的摘要。密码不进模型上下文、不进 argv、不进 shell 历史、不落日志。

子命令
  put    SERVICE [ACCOUNT]   弹窗或就地输入，写进钥匙串，回报长度
  get    SERVICE [ACCOUNT]   回报长度；--show 才打印明文（要求终端）
  probe  SERVICE [ACCOUNT]   用存的凭据实测 IMAP/SMTP，只回报通没通
  exec   SERVICE [ACCOUNT]   把凭据注入环境变量后执行命令，明文不上屏
  list                       存过什么、还在不在
  rm     SERVICE [ACCOUNT]   删除一条
  doctor                     自检：后端、权限、残留文件

退出码 0 成功 / 1 失败 / 2 人没输完（超时、取消）
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

VERSION = '0.1.7'
HOME = os.path.expanduser('~')
STATE_DIR = os.path.join(HOME, '.handvault')
LEDGER = os.path.join(STATE_DIR, 'ledger.tsv')
SHIM_TTL = 24 * 3600          # 残留的窗口脚本多久算过期
MAX_TOKEN = 128               # service / account 长度上限
PROBE_TIMEOUT = 15


# ---------------------------------------------------------------- 文案

_MSG = {
    'en': {
        'prompt': 'Password (no echo): ',
        'prompt2': 'Again: ',
        'got': '  {n} characters',
        'empty': '  empty, try again',
        'ws': '  note: leading/trailing space kept as typed',
        'mismatch': '  mismatch ({a} / {b}), retry',
        'thrice': 'gave up after 3 tries',
        'launch': 'a terminal window is open — type the password there',
        'timeout': 'no input within {n}s. The window stays open; what you type is '
                   'still stored. Check later with `handvault list`.',
        'stored': 'OK service={s} account={a} length={n}',
        'nokc': 'FAIL nothing stored for {s} / {a}',
        'wrote_empty': 'security did not take the value',
        'needs_tty': 'FAIL --show needs a terminal; the agent gets a length only',
        'no_cmd': 'FAIL exec needs -- followed by a command',
        'bad_token': 'FAIL {k} must be 1-{n} printable characters, not starting with -',
        'no_secret': 'FAIL no secret-tool or security found',
        'notty_hint': 'WARN reading from stdin — for test values only',
    },
    'zh': {
        'prompt': '密码（不回显，回车确认）: ',
        'prompt2': '再输一次: ',
        'got': '  收到 {n} 位字符',
        'empty': '  空值，重来',
        'ws': '  注意：首尾空格按原样保存',
        'mismatch': '  两次不一致（{a} / {b}），重来',
        'thrice': '三次不一致，放弃',
        'launch': '已弹窗：请在终端窗口里输入密码',
        'timeout': '{n} 秒内没等到输入。窗口还开着，输完照样写进钥匙串；'
                   '之后用 `handvault list` 查状态。',
        'stored': 'OK service={s} account={a} length={n}',
        'nokc': 'FAIL 没有这条：{s} / {a}',
        'wrote_empty': 'keychain 没接受这个值',
        'needs_tty': 'FAIL --show 需要在终端里跑；agent 只拿长度',
        'no_cmd': 'FAIL exec 需要 -- 后面跟命令',
        'bad_token': 'FAIL {k} 要 1-{n} 个可打印字符，不能以 - 开头',
        'no_secret': 'FAIL 找不到 secret-tool 或 security',
        'notty_hint': 'WARN 从 stdin 读入——只用于测试值',
    },
}


def t(key: str, **kw) -> str:
    lang = 'zh' if os.environ.get('LANG', '').lower().startswith(('zh', 'cn')) else 'en'
    s = _MSG[lang].get(key) or _MSG['en'][key]
    return s.format(**kw) if kw else s


# ---------------------------------------------------------------- 硬性约束

def die(msg: str, code: int = 1):
    print(msg, file=sys.stdout, flush=True)
    raise SystemExit(code)


def check_token(value: str, kind: str) -> str:
    """service / account 会进 argv、进账本、进窗口脚本，先卡住控制字符。"""
    if not value or len(value) > MAX_TOKEN or value.startswith('-'):
        die(t('bad_token', k=kind, n=MAX_TOKEN))
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in value):
        die(t('bad_token', k=kind, n=MAX_TOKEN))
    return value


def harden_process():
    """尽量把事故面收小：不要 core dump（里面有明文）。"""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass


def ensure_state_dir():
    os.makedirs(STATE_DIR, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)


def sweep_stale():
    """清掉过期的窗口脚本和状态文件——里面有 service 名。"""
    if not os.path.isdir(STATE_DIR):
        return
    now = time.time()
    for name in os.listdir(STATE_DIR):
        if not (name.startswith('run-')):
            continue
        p = os.path.join(STATE_DIR, name)
        try:
            if now - os.path.getmtime(p) > SHIM_TTL:
                os.unlink(p)
        except OSError:
            pass


# ---------------------------------------------------------------- 钥匙串后端

class Backend:
    name = 'none'

    def put(self, service, account, secret, label): ...
    def get(self, service, account): ...
    def rm(self, service, account): ...
    def exists(self, service, account): ...
    def preflight(self): ...


class MacBackend(Backend):
    """macOS：/usr/bin/security。

    两个坑：它上面没有「从 stdin 读密码」的口子，而裸 -w 的提示会把密码
    回显到终端。所以自己用 getpass 读，再把值喂进一个私有 pty——回显只落在
    我们自己的缓冲区里，人眼前一片空白。
    """

    name = 'macos-keychain'

    def __init__(self):
        self.bin = os.environ.get('HANDVAULT_SECURITY') or '/usr/bin/security'

    def preflight(self):
        if not os.path.isfile(self.bin) or not os.access(self.bin, os.X_OK):
            die(t('no_secret'))
        if os.environ.get('HANDVAULT_SECURITY'):
            # 这个口子只该给人自测用。指向别人的文件就等于把密码交出去。
            st = os.stat(self.bin)
            if st.st_uid != os.getuid() or (st.st_mode & 0o022):
                die('FAIL HANDVAULT_SECURITY must be owned by you and not '
                    'group/world-writable; refusing to run it')
        return True

    def _run(self, args, timeout=60):
        return subprocess.run([self.bin] + args, capture_output=True, text=True,
                              env=dict(os.environ, LC_ALL='C'), timeout=timeout)

    def exists(self, service, account):
        return self._run(['find-generic-password', '-s', service, '-a', account]).returncode == 0

    def get(self, service, account):
        r = self._run(['find-generic-password', '-s', service, '-a', account, '-w'])
        if r.returncode != 0:
            return None
        return r.stdout.rstrip('\n')

    def rm(self, service, account):
        return self._run(['delete-generic-password', '-s', service, '-a', account]).returncode == 0

    def put(self, service, account, secret, label):
        import pty
        args = ['add-generic-password', '-a', account, '-s', service]
        if label:
            args += ['-l', label]
        args += ['-U', '-w']

        master, slave = pty.openpty()
        proc = subprocess.Popen([self.bin] + args, stdin=slave, stdout=slave,
                                stderr=slave, close_fds=True,
                                env=dict(os.environ, LC_ALL='C'))
        os.close(slave)
        payload = secret + '\n'
        try:
            for _ in range(2):           # password data / retype password
                time.sleep(0.3)
                if proc.poll() is not None:
                    break
                try:
                    os.write(master, payload.encode())
                except OSError:
                    break
                _drain(master, 0.25)
            proc.wait(timeout=30)
        finally:
            try:
                os.close(master)
            except OSError:
                pass
        if proc.returncode != 0:
            raise RuntimeError('security add-generic-password exit %d' % proc.returncode)


class LinuxBackend(Backend):
    """Linux：secret-tool（libsecret）。它从 stdin 吃密码，比 pty 干净。"""

    name = 'libsecret'

    def __init__(self):
        self.bin = shutil.which('secret-tool')

    def preflight(self):
        if not self.bin:
            die(t('no_secret'))
        return True

    def exists(self, service, account):
        return self.get(service, account) is not None

    def get(self, service, account):
        r = subprocess.run([self.bin, 'lookup', 'service', service, 'account', account],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0 or not r.stdout:
            return None
        return r.stdout.rstrip('\n')

    def rm(self, service, account):
        r = subprocess.run([self.bin, 'clear', 'service', service, 'account', account],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0

    def put(self, service, account, secret, label):
        r = subprocess.run([self.bin, 'store', '--label', label or service,
                            'service', service, 'account', account],
                           input=secret + '\n', capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise RuntimeError('secret-tool store exit %d' % r.returncode)


def _drain(fd, seconds=0.2):
    """读掉 pty 里的回显——只是不让子进程堵在管道上，内容直接丢。"""
    import select
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if not r:
            continue
        try:
            if not os.read(fd, 4096):
                return
        except OSError:
            return


def backend() -> Backend:
    # HANDVAULT_SECURITY 指向一个 security(1) 兼容的可执行文件，任何平台都认。
    # 它只为人自测，或者是 Linux 上装了个 security 外壳；preflight 会验属主与权限。
    if os.environ.get('HANDVAULT_SECURITY'):
        return MacBackend()
    if sys.platform == 'darwin':
        return MacBackend()
    b = LinuxBackend()
    if b.bin:
        return b
    die(t('no_secret'))


# ---------------------------------------------------------------- 账本

def ledger_append(service, account, length, label, action='put'):
    ensure_state_dir()
    line = '\t'.join([time.strftime('%Y-%m-%dT%H:%M:%S'), service, account,
                      str(length), action, label or ''])
    fd = os.open(LEDGER, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (line + '\n').encode('utf-8'))
    finally:
        os.close(fd)


def ledger_read():
    if not os.path.exists(LEDGER):
        return []
    rows = []
    with open(LEDGER, encoding='utf-8') as f:
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) >= 4:
                try:
                    n = int(p[3])
                except ValueError:
                    continue
                rows.append({'ts': p[0], 'service': p[1], 'account': p[2],
                             'length': n,
                             'action': p[4] if len(p) > 4 else 'put',
                             'label': p[5] if len(p) > 5 else ''})
    return rows


# ---------------------------------------------------------------- 探针

def hostport(spec, default_port):
    if spec.count(':') == 1:
        h, p = spec.rsplit(':', 1)
        if p.isdigit():
            return h, int(p)
    return spec, default_port


def probe(secret, user, imap=None, smtp=None):
    """只回报通没通，从不回报密码。"""
    out, ok = [], True
    if imap:
        host, port = hostport(imap, 993)
        try:
            import imaplib
            if port == 143:
                m = imaplib.IMAP4(host, port, timeout=PROBE_TIMEOUT)
                try:
                    m.starttls()
                except Exception:
                    pass
            else:
                m = imaplib.IMAP4_SSL(host, port, timeout=PROBE_TIMEOUT)
            m.login(user, secret)
            m.select('INBOX')
            n = len(m.search(None, 'ALL')[1][0].split())
            m.logout()
            out.append('IMAP OK (%s:%d, inbox %d)' % (host, port, n))
        except Exception as e:
            ok = False
            out.append('IMAP FAIL %s' % str(e)[:120])
    if smtp:
        host, port = hostport(smtp, 465)
        try:
            import smtplib
            if port == 465:
                s = smtplib.SMTP_SSL(host, port, timeout=PROBE_TIMEOUT)
            else:
                s = smtplib.SMTP(host, port, timeout=PROBE_TIMEOUT)
                s.ehlo()
                if s.has_extn('starttls'):
                    s.starttls()
                    s.ehlo()
            s.login(user, secret)
            s.quit()
            out.append('SMTP OK (%s:%d)' % (host, port))
        except Exception as e:
            ok = False
            out.append('SMTP FAIL %s' % str(e)[:120])
    return ok, out


# ---------------------------------------------------------------- 弹窗模式

def status_path(run_id):
    return os.path.join(STATE_DIR, 'run-%s.json' % run_id)


def write_status(run_id, **kw):
    if not run_id:
        return
    ensure_state_dir()
    p = status_path(run_id)
    tmp = p + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(kw, f, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def open_terminal(shim):
    """macOS 用 Terminal；Linux 试几个常见终端。都失败就把命令告诉人。"""
    if sys.platform == 'darwin':
        return subprocess.run(['/usr/bin/open', '-a', 'Terminal', shim]).returncode == 0
    for term in ('x-terminal-emulator', 'gnome-terminal', 'konsole', 'alacritty', 'xterm'):
        if shutil.which(term):
            flag = '--' if term in ('gnome-terminal', 'konsole') else '-e'
            return subprocess.run([term, flag, '/bin/bash', shim]).returncode == 0
    return False


def launch_window(argv, wait_seconds):
    ensure_state_dir()
    sweep_stale()
    run_id = '%d-%d' % (int(time.time()), os.getpid())
    write_status(run_id, state='pending')

    shim = os.path.join(STATE_DIR, 'run-%s.command' % run_id)
    cmd = [sys.executable, os.path.abspath(__file__)] + argv + ['--in-window', '--run-id', run_id]
    with open(shim, 'w', encoding='utf-8') as f:
        f.write('#!/bin/bash\numask 077\ncd "$HOME"\nexec %s\n' % shlex.join(cmd))
    os.chmod(shim, 0o700)

    if not open_terminal(shim):
        print('no terminal found. Run this yourself:\n  %s' % shlex.join(cmd))
        return 2

    print(t('launch'), flush=True)
    return wait_for(run_id, wait_seconds)


def wait_for(run_id, wait_seconds):
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        try:
            with open(status_path(run_id), encoding='utf-8') as f:
                st = json.load(f)
        except (OSError, ValueError):
            st = {'state': 'pending'}
        state = st.get('state')
        if state and state != 'pending':
            _drop_shim(run_id)
            if st.get('message'):
                print(st['message'])
            return 0 if state == 'done' else 1
        time.sleep(0.4)
    print(t('timeout', n=wait_seconds))
    return 2


def _drop_shim(run_id):
    for ext in ('.command',):
        try:
            os.unlink(os.path.join(STATE_DIR, 'run-%s%s' % (run_id, ext)))
        except OSError:
            pass


# ---------------------------------------------------------------- 交互读入

def read_secret(prompt):
    import getpass
    while True:
        v = getpass.getpass(prompt)
        if not v:
            print(t('empty'))
            continue
        print(t('got', n=len(v)))
        if v != v.strip():
            print(t('ws'))
        return v


def ask_secret(confirm=True):
    for _ in range(3):
        a = read_secret(t('prompt'))
        if not confirm:
            return a
        b = read_secret(t('prompt2'))
        if a == b:
            return a
        print(t('mismatch', a=len(a), b=len(b)))
    die(t('thrice'), 2)


# ---------------------------------------------------------------- 子命令

def cmd_put(a):
    service = check_token(a.service, 'service')
    account = check_token(a.account, 'account')
    secret = None

    if a.from_stdin:
        if os.environ.get('HANDVAULT_ALLOW_STDIN') != '1':
            die('FAIL --from-stdin 需要 HANDVAULT_ALLOW_STDIN=1（仅测试用）')
        print(t('notty_hint'), file=sys.stderr)
        secret = sys.stdin.readline().rstrip('\n')

    if secret is None:
        if a.in_window:
            secret = ask_secret(confirm=not a.no_confirm)
        elif not sys.stdin.isatty():
            return launch_window([x for x in a._argv if x != '--from-stdin'], a.wait)
        else:
            secret = ask_secret(confirm=not a.no_confirm)

    b = backend()
    b.preflight()
    try:
        b.put(service, account, secret, a.label)
        if b.get(service, account) != secret:
            raise RuntimeError(t('wrote_empty'))
        ledger_append(service, account, len(secret), a.label)
    except Exception as e:
        msg = 'FAIL %s' % e
        print(msg)
        write_status(a.run_id, state='failed', message=msg)
        return 1

    lines = [t('stored', s=service, a=account, n=len(secret))]
    code = 0
    if a.imap or a.smtp:
        ok, out = probe(secret, a.user or account, a.imap, a.smtp)
        lines += out
        code = 0 if ok else 1
    msg = '\n'.join(lines)
    print(msg)
    write_status(a.run_id, state='done', length=len(secret), message=msg)
    return code


def _fetch(a, b):
    if not b.exists(a.service, a.account):
        die(t('nokc', s=a.service, a=a.account))
    v = b.get(a.service, a.account)
    if v is None:
        die(t('nokc', s=a.service, a=a.account))
    return v


def cmd_get(a):
    b = backend()
    b.preflight()
    v = _fetch(a, b)
    if a.show:
        if not sys.stdout.isatty():
            die(t('needs_tty'))
        print(v)
    else:
        print(t('stored', s=a.service, a=a.account, n=len(v)))
    return 0


ENV_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$')


def cmd_exec(a):
    b = backend()
    b.preflight()
    v = _fetch(a, b)

    if a.fd is not None:
        # 秘密走一条只读管道，落到子进程的固定 fd 上：不进环境、不进 argv、不落盘。
        if not 3 <= a.fd <= 99:
            die('FAIL --fd must be between 3 and 99', 2)
        r, w = os.pipe()
        try:
            os.write(w, v.encode())
        finally:
            os.close(w)

        try:
            os.fstat(a.fd)
        except OSError:
            pass
        else:
            die('FAIL fd %d is already open; pick another' % a.fd, 2)
        os.dup2(r, a.fd)
        os.close(r)
        try:
            return subprocess.run(a.cmdargs, env=dict(os.environ),
                                  pass_fds=(a.fd,)).returncode
        finally:
            os.close(a.fd)

    if not ENV_NAME.match(a.env or ''):
        die('FAIL --env needs a shell identifier (letters, digits, underscore)', 2)
    env = dict(os.environ, **{a.env: v})
    return subprocess.run(a.cmdargs, env=env).returncode


def cmd_probe(a):
    if not (a.imap or a.smtp):
        die('FAIL give --imap or --smtp')
    b = backend()
    b.preflight()
    v = _fetch(a, b)
    ok, out = probe(v, a.user or a.account, a.imap, a.smtp)
    print('\n'.join(out))
    return 0 if ok else 1


def cmd_list(a):
    rows = ledger_read()
    if not rows:
        print('(nothing yet)')
        return 0
    b = backend()
    latest, lastlen = {}, {}
    for r in rows:
        k = (r['service'], r['account'])
        if r['action'] != 'deleted':
            lastlen[k] = r['length']
        latest[k] = r
    for (svc, acct), r in latest.items():
        state = 'live' if b.exists(svc, acct) else 'gone'
        # a deletion row carries no length; report the last real one
        n = r['length'] if r['action'] != 'deleted' else lastlen.get((svc, acct), 0)
        print('%-28s %-28s %3d chars  %s  %-5s %s' % (
            svc, acct, n, r['ts'], state, r['label']))
    return 0


def cmd_rm(a):
    b = backend()
    b.preflight()
    _fetch(a, b)
    if not b.rm(a.service, a.account):
        die('FAIL could not delete')
    ledger_append(a.service, a.account, 0, '', 'deleted')
    print('OK deleted %s / %s' % (a.service, a.account))
    return 0


def cmd_doctor(a):
    b = backend()
    b.preflight()
    print('handvault %s' % VERSION)
    print('backend   %s (%s)' % (b.name, getattr(b, 'bin', '?')))
    print('python    %s' % sys.version.split()[0])
    if os.path.isdir(STATE_DIR):
        mode = os.stat(STATE_DIR).st_mode & 0o777
        print('state     %s mode %o %s' % (STATE_DIR, mode, 'ok' if mode == 0o700 else 'LOOSE'))
        leftovers = [n for n in os.listdir(STATE_DIR) if n.startswith('run-')]
        print('leftover  %d run files' % len(leftovers))
    else:
        print('state     not created yet')
    if os.path.exists(LEDGER):
        print('ledger    mode %o, %d rows' % (os.stat(LEDGER).st_mode & 0o777, len(ledger_read())))
    print('tty       stdin=%s stdout=%s' % (sys.stdin.isatty(), sys.stdout.isatty()))
    return 0


# ---------------------------------------------------------------- 入口

def main(argv=None):
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in ('-V', '--version'):
        print('handvault %s' % VERSION)
        return 0

    tail = []
    if raw and raw[0] == 'exec' and '--' in raw:
        cut = raw.index('--')
        tail = raw[cut + 1:]
        raw = raw[:cut]

    p = argparse.ArgumentParser(prog='handvault',
                                description='人输密码，agent 只看到长度。')
    p.add_argument('-V', '--version', action='version', version='handvault %s' % VERSION)
    sub = p.add_subparsers(dest='cmd', required=True)

    def common(sp, probey=False):
        sp.add_argument('service')
        sp.add_argument('account', nargs='?', default=None)
        if probey:
            sp.add_argument('--label', default=None)
            sp.add_argument('--imap', default=None, metavar='HOST[:PORT]')
            sp.add_argument('--smtp', default=None, metavar='HOST[:PORT]')
            sp.add_argument('--user', default=None)

    sp = sub.add_parser('put', help='存一条凭据')
    common(sp, probey=True)
    sp.add_argument('--no-confirm', action='store_true', help='不要求输两遍')
    sp.add_argument('--wait', type=int, default=300, metavar='SEC')
    sp.add_argument('--from-stdin', action='store_true', help=argparse.SUPPRESS)
    sp.add_argument('--in-window', action='store_true', help=argparse.SUPPRESS)
    sp.add_argument('--run-id', default=None, help=argparse.SUPPRESS)

    sp = sub.add_parser('get', help='查长度')
    sp.add_argument('service')
    sp.add_argument('account', nargs='?', default=None)
    sp.add_argument('--show', action='store_true')

    sp = sub.add_parser('probe', help='实测 IMAP/SMTP')
    common(sp, probey=True)

    sp = sub.add_parser('exec', help='注入环境变量后执行')
    sp.add_argument('service')
    sp.add_argument('account', nargs='?', default=None)
    sp.add_argument('--env', default=None)
    sp.add_argument('--fd', type=int, default=None)

    sub.add_parser('list', help='存过什么')
    sub.add_parser('doctor', help='自检')

    sp = sub.add_parser('rm', help='删除一条')
    sp.add_argument('service')
    sp.add_argument('account', nargs='?', default=None)

    a = p.parse_args(raw)
    a._argv = raw
    if getattr(a, 'account', None) is None and a.cmd != 'list':
        a.account = os.environ.get('USER', 'local')
    if a.cmd == 'exec':
        if not tail:
            die(t('no_cmd'), 2)
        if (a.env is None) == (a.fd is None):
            die('FAIL give exactly one of --env NAME or --fd N', 2)
        a.cmdargs = tail

    harden_process()
    handlers = {'put': cmd_put, 'get': cmd_get, 'probe': cmd_probe, 'exec': cmd_exec,
                'list': cmd_list, 'rm': cmd_rm, 'doctor': cmd_doctor}
    return handlers[a.cmd](a)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\ncancelled.')
        sys.exit(2)

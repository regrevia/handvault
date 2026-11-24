"""handvault 的回归测试。不碰真钥匙串：用一个假后端替身。

跑：python3 -m unittest discover -s test -v
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'handvault.py')


def load():
    spec = importlib.util.spec_from_file_location('handvault', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='hv-test-')
        self.bin = os.path.join(self.tmp, 'security')
        shutil.copy(os.path.join(ROOT, 'test', 'fake_security.py'), self.bin)
        os.chmod(self.bin, 0o700)
        self.env = dict(os.environ,
                        HANDVAULT_SECURITY=self.bin,
                        FAKE_STORE=self.tmp,
                        HOME=self.tmp,
                        HANDVAULT_ALLOW_STDIN='1')
        self.env.pop('LANG', None)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_hv(self, *args, stdin=None):
        return subprocess.run([sys.executable, SCRIPT] + list(args),
                              capture_output=True, text=True, env=self.env,
                              input=stdin, timeout=90)


class TestCli(Base):
    def test_put_reports_length_only(self):
        secret = 'Abc-123-test'
        r = self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin=secret + '\n')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('length=%d' % len(secret), r.stdout)
        self.assertNotIn(secret, r.stdout)
        self.assertNotIn(secret, r.stderr)

    def test_get_hides_plaintext(self):
        self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin='s3cret-value\n')
        r = self.run_hv('get', 'svc', 'acct')
        self.assertEqual(r.returncode, 0)
        self.assertNotIn('s3cret-value', r.stdout)

    def test_get_show_refused_without_tty(self):
        self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin='s3cret-value\n')
        r = self.run_hv('get', 'svc', 'acct', '--show')
        self.assertEqual(r.returncode, 1)
        self.assertNotIn('s3cret-value', r.stdout)

    def test_exec_injects_env(self):
        self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin='9' * 21 + '\n')
        r = self.run_hv('exec', 'svc', 'acct', '--env', 'S', '--',
                        sys.executable, '-c',
                        'import os;print(len(os.environ["S"]))')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), '21')

    def test_exec_fd_carries_secret_without_env(self):
        secret = 'Abc-123-test'
        self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin=secret + '\n')
        r = self.run_hv('exec', 'svc', 'acct', '--fd', '7', '--',
                        sys.executable, '-c',
                        'import os,sys;d=os.read(7,4096).decode();'
                        'print(len(d));'
                        'print("inenv", d in "".join(os.environ.values()))')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(str(len(secret)), r.stdout)
        self.assertIn('inenv False', r.stdout)
        self.assertNotIn(secret, r.stdout)

    def test_exec_needs_exactly_one_channel(self):
        self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin='x\n')
        both = self.run_hv('exec', 'svc', 'acct', '--env', 'S', '--fd', '5',
                           '--', sys.executable, '-c', 'pass')
        self.assertEqual(both.returncode, 2)
        neither = self.run_hv('exec', 'svc', 'acct', '--', sys.executable, '-c', 'pass')
        self.assertEqual(neither.returncode, 2)

    def test_exec_rejects_bad_env_name(self):
        self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin='x\n')
        bad = self.run_hv('exec', 'svc', 'acct', '--env', 'A=B',
                          '--', sys.executable, '-c', 'pass')
        self.assertEqual(bad.returncode, 2)


    def test_exec_requires_command(self):
        r = self.run_hv('exec', 'svc', 'acct', '--env', 'S')
        self.assertEqual(r.returncode, 2)

    def test_stdin_needs_optin(self):
        env = dict(self.env)
        env.pop('HANDVAULT_ALLOW_STDIN')
        r = subprocess.run([sys.executable, SCRIPT, 'put', 'svc', 'acct', '--from-stdin'],
                           capture_output=True, text=True, env=env,
                           input='x\n', timeout=60)
        self.assertEqual(r.returncode, 1)

    def test_rm_then_missing(self):
        self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin='val\n')
        self.assertEqual(self.run_hv('rm', 'svc', 'acct').returncode, 0)
        r = self.run_hv('get', 'svc', 'acct')
        self.assertEqual(r.returncode, 1)

    def test_rejects_argv_injection(self):
        self.assertNotEqual(self.run_hv('put', '-s', 'acct', '--from-stdin',
                                        stdin='v\n').returncode, 0)

    def test_rejects_control_chars(self):
        r = self.run_hv('put', 'svc\x01bad', 'acct', '--from-stdin', stdin='v\n')
        self.assertEqual(r.returncode, 1)

    def test_rejects_world_writable_backend(self):
        os.chmod(self.bin, 0o777)
        r = self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin='v\n')
        self.assertEqual(r.returncode, 1)
        self.assertIn('refusing', r.stdout)

    def test_list_keeps_length_after_delete(self):
        # a deletion row must not erase the last known length
        secret = 'Abc-123-test'
        self.run_hv('put', 'svc-a', 'eve', '--from-stdin', stdin=secret + '\n')
        r = self.run_hv('rm', 'svc-a', 'eve')
        self.assertEqual(r.returncode, 0, r.stderr)
        out = self.run_hv('list').stdout
        self.assertIn('gone', out)
        self.assertIn('%d chars' % len(secret), out)

    def test_list_shows_state(self):
        self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin='1234567\n')
        r = self.run_hv('list')
        self.assertIn('svc', r.stdout)
        self.assertIn('7 chars', r.stdout)
        self.assertIn('live', r.stdout)


    def test_no_secret_anywhere_in_state_dir(self):
        secret = 'Abc-123-test'
        self.run_hv('put', 'svc', 'acct', '--from-stdin', stdin=secret + '\n')
        state = os.path.join(self.env['HOME'], '.handvault')
        seen = 0
        for name in os.listdir(state):
            path = os.path.join(state, name)
            if not os.path.isfile(path):
                continue
            with open(path, 'rb') as fh:
                blob = fh.read()
            seen += 1
            self.assertNotIn(secret.encode(), blob, 'secret leaked into ' + name)
        self.assertGreater(seen, 0, 'expected state files to inspect')


class TestUnits(unittest.TestCase):
    def setUp(self):
        self.hv = load()
        # never touch the real ~/.handvault from tests
        self.tmp = tempfile.mkdtemp(prefix='hv-unit-')
        self.hv.STATE_DIR = os.path.join(self.tmp, 'state')
        self.hv.LEDGER = os.path.join(self.hv.STATE_DIR, 'ledger.tsv')
        os.makedirs(self.hv.STATE_DIR, mode=0o700)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_check_token(self):
        self.assertEqual(self.hv.check_token('a@b.com', 'account'), 'a@b.com')
        for bad in ('', '-x', 'a' * 200, 'a\nb', 'a\tb'):
            with self.assertRaises(SystemExit):
                self.hv.check_token(bad, 'service')

    def test_hostport(self):
        self.assertEqual(self.hv.hostport('imap.example.com', 993), ('imap.example.com', 993))
        self.assertEqual(self.hv.hostport('imap.example.com:143', 993), ('imap.example.com', 143))
        self.assertEqual(self.hv.hostport('h:notaport', 993), ('h:notaport', 993))

    def test_ledger_never_carries_secret(self):
        with tempfile.TemporaryDirectory() as d:
            self.hv.STATE_DIR = d
            self.hv.LEDGER = os.path.join(d, 'ledger.tsv')
            self.hv.ledger_append('svc', 'acct', 7, 'some label')
            mode = os.stat(self.hv.LEDGER).st_mode & 0o777
            body = open(self.hv.LEDGER, encoding='utf-8').read()
        self.assertIn('svc', body)
        self.assertIn('\t7\t', body)
        self.assertEqual(mode, 0o600)

    def test_version_matches_package_json(self):
        import json
        pkg = json.load(open(os.path.join(ROOT, 'package.json'), encoding='utf-8'))
        self.assertEqual(self.hv.VERSION, pkg['version'],
                         'handvault.py VERSION must match package.json')

    def test_window_shim_is_private_and_quoted(self):
        """没有终端时把 put 交给人：影子脚本必须 0700、参数被引用、不含秘密。"""
        captured = {}

        def fake_open(shim):
            captured['shim'] = shim
            return True

        orig = self.hv.open_terminal
        self.hv.open_terminal = fake_open
        try:
            rc = self.hv.launch_window(
                ['put', 'svc-a', 'eve', '--label', 'a b;rm -rf /'], 1)
        finally:
            self.hv.open_terminal = orig
        self.assertEqual(rc, 2, 'no one typed anything, so it must time out')

        shim = captured['shim']
        st = os.stat(shim)
        self.assertEqual(st.st_mode & 0o077, 0, 'shim must not be group/world readable')
        with open(shim, encoding='utf-8') as fh:
            body = fh.read()
        self.assertIn('--in-window', body)
        self.assertIn('--run-id', body)
        self.assertIn("'a b;rm -rf /'", body, 'label must be shell-quoted, never interpolated')
        self.assertNotIn('from-stdin', body)

    def test_status_file_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            self.hv.STATE_DIR = d
            self.hv.write_status('r1', state='done', length=5)
            p = os.path.join(d, 'run-r1.json')
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()

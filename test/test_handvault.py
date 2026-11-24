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


class TestUnits(unittest.TestCase):
    def setUp(self):
        self.hv = load()

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

    def test_status_file_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            self.hv.STATE_DIR = d
            self.hv.write_status('r1', state='done', length=5)
            p = os.path.join(d, 'run-r1.json')
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# Copyright (C) 2026 barrier-x contributors; GPL, see LICENSE.
"""Check that shallow Qt fix fetches retain their actual production diff."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('qt_sdk', Path(__file__).with_name('qt-sdk.py'))
sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdk)


class PatchTests(unittest.TestCase):
    def test_shallow_fix_changes_only_the_reviewed_file(self):
        with tempfile.TemporaryDirectory(prefix='barrier-qt-patch-') as directory:
            root = Path(directory)
            origin = root / 'origin'
            fetched = root / 'fetched'
            def git(*args, cwd=origin):
                return subprocess.check_output(['git', *args], cwd=cwd, stderr=subprocess.PIPE)
            origin.mkdir()
            git('init')
            git('config', 'user.name', 'Patch fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (origin / 'src').mkdir()
            (origin / 'src/untouched.cpp').write_text('original\n')
            (origin / 'src/fixed.cpp').write_text('before\n')
            git('add', '.')
            git('commit', '-m', 'Base fixture')
            (origin / 'src/fixed.cpp').write_text('after\n')
            git('commit', '-am', 'Fix fixture')
            sha = git('rev-parse', 'HEAD').decode().strip()
            fetched.mkdir()
            git('init', cwd=fetched)
            # Git's local path transport ignores depth; the file URL exercises it.
            git('fetch', '--depth=1', origin.as_uri(), sha, cwd=fetched)
            with self.assertRaises(subprocess.CalledProcessError):
                sdk.production_patch(fetched, sha)
            git('fetch', '--depth=2', origin.as_uri(), sha, cwd=fetched)
            patch = sdk.production_patch(fetched, sha)
            self.assertIn(b'-before', patch)
            self.assertIn(b'+after', patch)
            self.assertNotIn(b'untouched.cpp', patch)
            git('checkout', '--detach', sha + '^', cwd=fetched)
            patch_file = root / 'fix.diff'
            patch_file.write_bytes(patch)
            git('apply', '--check', str(patch_file), cwd=fetched)
            git('apply', str(patch_file), cwd=fetched)
            self.assertEqual('after\n', (fetched / 'src/fixed.cpp').read_text())
            self.assertEqual('original\n', (fetched / 'src/untouched.cpp').read_text())


if __name__ == '__main__':
    unittest.main()

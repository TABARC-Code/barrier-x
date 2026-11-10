#!/usr/bin/env python3
# Copyright (C) 2026 barrier-x contributors; GPL, see LICENSE.
"""Build the native Qt libraries from reviewed source and security fixes."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

BASE = '025bdad181de241e81bf853c8a2d7bf3d19261a9'  # Qt 6.12.0
FIXES = (
    'a2cd9d2a70575c37153d43e9c5396a9144af1923',  # CVE-2026-105924
    'aac1d303c0329241ac59c0c23cb5e4b82251fcfa',  # CVE-2026-116337, headers first
    'f78a3740281d26af7116517a2b20df36f8deffd7',
)
SOURCE = 'https://github.com/qt/qtbase.git'
IDENTITY = {'repository': SOURCE, 'base': BASE, 'fixes': list(FIXES), 'version': '6.12.0'}


def run(*args, cwd=None):
    timeout = 300 if str(args[0]) == 'git' else 2700
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True, timeout=timeout)


def production_patch(source, sha):
    # I require the parent explicitly: a shallow root makes git show invent a full-tree patch.
    return subprocess.check_output(
        ['git', 'diff', '--binary', '--full-index', '--no-ext-diff', '--no-textconv',
         '--no-color', '--src-prefix=a/', '--dst-prefix=b/', sha + '^', sha, '--', 'src'], cwd=source, timeout=30)


def build(prefix, jobs):
    prefix = prefix.resolve()
    manifest = prefix / 'barrier-qt-source.json'
    if prefix.exists() and any(prefix.iterdir()):
        raise RuntimeError('Refusing to overwrite an unrecognised Qt SDK')
    source = prefix.parent / (prefix.name + '-source')
    output = prefix.parent / (prefix.name + '-build')
    if source.exists() or output.exists():
        raise RuntimeError('Qt source/build directories already exist; inspect them before retrying')
    if not shutil.which('cmake') or not shutil.which('ninja'):
        raise RuntimeError('CMake and Ninja must be installed before building Qt')
    source.mkdir(parents=True, mode=0o700)
    patches = source / 'reviewed-patches'
    patches.mkdir(mode=0o700)
    run('git', 'init', source)
    run('git', 'config', 'maintenance.auto', 'false', cwd=source)
    run('git', 'remote', 'add', 'origin', SOURCE, cwd=source)
    run('git', 'fetch', '--no-auto-maintenance', '--depth=1', 'origin', BASE, cwd=source)
    run('git', 'checkout', '--detach', BASE, cwd=source)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True, timeout=30).strip()
    if revision != BASE:
        raise RuntimeError('Qt source revision mismatch')
    for sha in FIXES:
        run('git', 'fetch', '--no-auto-maintenance', '--depth=2', 'origin', sha, cwd=source)
        patch = production_patch(source, sha)
        if not patch:
            raise RuntimeError('The reviewed Qt fix has no production changes')
        patch_file = patches / ('qt-' + sha + '.diff')
        with patch_file.open('xb') as stream:
            stream.write(patch)
        print('Qt fix', sha, 'SHA256', hashlib.sha256(patch).hexdigest(), flush=True)
        run('git', 'apply', '--check', patch_file, cwd=source)
        run('git', 'apply', patch_file, cwd=source)
    options = [
        '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=' + str(prefix),
        '-DQT_BUILD_EXAMPLES=OFF', '-DQT_BUILD_TESTS=OFF', '-DBUILD_SHARED_LIBS=ON',
        '-DFEATURE_opengl=OFF', '-DFEATURE_sql=OFF', '-DFEATURE_dbus=OFF',
        '-DFEATURE_printsupport=OFF', '-DFEATURE_widgets=ON', '-DFEATURE_testlib=ON',
        '-DFEATURE_openssl=OFF',
    ]
    run('cmake', '-S', source, '-B', output, *options)
    run('cmake', '--build', output, '--parallel', jobs)
    run('cmake', '--install', output)
    notices = prefix / 'licenses/Qt'
    shutil.copytree(source / 'LICENSES', notices)
    manifest.write_text(json.dumps(IDENTITY, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=3, choices=range(1, 17))
    args = parser.parse_args()
    try:
        build(args.prefix, args.jobs)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print('Qt SDK build failed:', error, file=sys.stderr)
        sys.exit(1)

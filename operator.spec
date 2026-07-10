# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, copy_metadata
from sys import platform

datas = [
    ('src/common/word_lists/*', 'src/common/word_lists/'),
    ('./pyproject.toml', '.'),
    ('./GIT_SHA', '.'),
]

# Contract wrappers load their ABI relative to their own module (see
# ContractWrapper._load_abi), so every module that ships an `abi/` directory
# must be bundled. Collect them all automatically to avoid missing new modules.
for abi_dir in sorted(Path('src').rglob('abi')):
    if abi_dir.is_dir():
        datas.append((abi_dir.as_posix(), abi_dir.as_posix()))

datas += collect_data_files('certifi')
datas += collect_data_files('coincurve')
datas += collect_data_files('eth_account')
datas += collect_data_files('eth_utils')
datas += copy_metadata('py_ecc')

block_cipher = None

hiddenimports = [
    'multiaddr.codecs.uint16be',
    'multiaddr.codecs.domain',
]

a = Analysis(
    ['src/main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['hooks/hook-ssl.py'],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='operator',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

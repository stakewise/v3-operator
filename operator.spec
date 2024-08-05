# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files
from sys import platform

datas = [
    ('src/common/abi/*', 'src/common/abi/'),
    ('src/eigenlayer/abi/*', 'src/eigenlayer/abi/'),
    ('src/common/word_lists/*', 'src/common/word_lists/'),
    ('./pyproject.toml', '.'),
    ('./GIT_SHA', '.'),
]

binaries = [
    ('bin/generation', '.'),
]

datas += collect_data_files('certifi')
datas += collect_data_files('coincurve')
datas += collect_data_files('eth_account')
datas += collect_data_files('eth_utils')

block_cipher = None

a = Analysis(
    ['src/main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=['multiaddr.codecs.uint16be', 'multiaddr.codecs.idna', 'pkg_resources.extern'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
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

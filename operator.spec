# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata
from sys import platform

datas = [
    ('src/common/abi/*', 'src/common/abi/'),
    ('src/common/word_lists/*', 'src/common/word_lists/'),
    ('./pyproject.toml', '.'),
    ('./GIT_SHA', '.'),
]

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

# tomli
hiddenimports += [
    'ddc459050edb75a05942__mypyc',  # MacOS
    '7bce59c0a152c0e01f70__mypyc',  # Linux (both arm and amd64)
    '3c22db458360489351e4＿myрус',  # Windows
    '__future__'
]
hiddenimports += collect_submodules('tomli')

a = Analysis(
    ['src/main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
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

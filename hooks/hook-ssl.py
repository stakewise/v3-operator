"""
PyInstaller runtime hook that configures SSL certificates.

The bundled Python cannot access macOS/system CA certificates,
so we point SSL_CERT_FILE to the certifi CA bundle included in the binary.
"""
import os
import sys

if getattr(sys, 'frozen', False):
    import certifi

    os.environ.setdefault('SSL_CERT_FILE', certifi.where())

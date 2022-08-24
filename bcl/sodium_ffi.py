"""
Preparation script for cffi module wrapping libsodium.
"""
import sys
import os
import os.path
import cffi

# Build the FFI instance.
sodium_ffi = cffi.FFI()
with open(
    os.path.join(os.path.abspath(os.path.dirname(__file__)), 'sodium_ffi.h'),
    'r',
    encoding='utf-8'
) as sodium_ffi_h:
    sodium_ffi.cdef(sodium_ffi_h.read())
    sodium_ffi.set_source(
        '_sodium',
        (
            ('#define SODIUM_STATIC\n' if sys.platform == 'win32' else '') +
            '#include <sodium.h>'
        ),
        libraries=['libsodium' if sys.platform == 'win32' else 'sodium']
    )

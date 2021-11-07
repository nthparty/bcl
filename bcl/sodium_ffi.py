"""
Preparation script for cffi module wrapping libsodium.
"""
import sys
import os
import os.path
import shutil
import tarfile
import urllib.request
import cffi

def prepare_libsodium_source_tree():
    """
    Retrieve the libsodium source archive and extract it
    to the location used by the build process.
    """
    # URL from which libsodium source archive is retrieved,
    # and paths into which it is extracted and then moved.
    url = (
        'https://github.com/jedisct1/libsodium/releases' + \
        '/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz'
    )
    libsodium_tar_gz_path = './bcl/libsodium.tar.gz'
    libsodium_tar_gz_folder = './bcl/libsodium_tar_gz'
    libsodium_folder = './bcl/libsodium'

    # Download the source archive to a local path (unless
    # it is already present).
    if not os.path.exists(libsodium_tar_gz_path):
        try:
            urllib.request.urlretrieve(url, filename=libsodium_tar_gz_path)
        except:
            raise RuntimeError(
                'failed to download libsodium archive and no local ' + \
                'archive was found at `' + libsodium_tar_gz_path + '`'
            ) from None

    # Extract the archive into a temporary folder (removing
    # the folder if it already exists).
    with tarfile.open(libsodium_tar_gz_path) as libsodium_tar_gz:
        if os.path.exists(libsodium_tar_gz_folder):
            shutil.rmtree(libsodium_tar_gz_folder)
        libsodium_tar_gz.extractall(libsodium_tar_gz_folder)

    # Move the source tree to the destination folder (removing
    # the destination folder first, if it already exists).
    if os.path.exists(libsodium_folder):
        shutil.rmtree(libsodium_folder)
    shutil.move(
        libsodium_tar_gz_folder + '/libsodium-1.0.18',
        libsodium_folder
    )

    # Remove the archive and temporary folder.
    os.remove(libsodium_tar_gz_path)
    shutil.rmtree(libsodium_tar_gz_folder)

# Retrieve and extract the libsodium source tree.
prepare_libsodium_source_tree()

# Build the FFI instance.
sodium_ffi = cffi.FFI()
with open(
    os.path.join(os.path.abspath(os.path.dirname(__file__)), "sodium_ffi.h"),
    "r",
    encoding="utf-8"
) as sodium_ffi_h:
    sodium_ffi.cdef(sodium_ffi_h.read())
    sodium_ffi.set_source(
        "_sodium",
        (
            ("#define SODIUM_STATIC\n" if sys.platform == "win32" else "") + \
            "#include <sodium.h>"
        ),
        libraries=["libsodium" if sys.platform == "win32" else "sodium"]
    )

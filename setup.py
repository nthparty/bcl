"""
Setup, package, and build file for the bcl cryptography library.
"""
import sys
import platform
import os
import os.path
import shutil
import glob
import subprocess
import tarfile
import errno
import urllib.request
from distutils.sysconfig import get_config_vars
from setuptools import Distribution, setup
import pystache

try:
    from setuptools.command.build_clib import build_clib as _build_clib
except ImportError:
    from distutils.command.build_clib import build_clib as _build_clib

def prepare_libsodium_source_tree(libsodium_folder='src/bcl/libsodium'):
    """
    Retrieve the libsodium source archive and extract it
    to the location used by the build process.
    """

    # Return if libsodium source tree has already been prepared.
    if os.path.exists(libsodium_folder) and len(os.listdir(libsodium_folder)) != 0:
        return libsodium_folder

    # URL from which libsodium source archive is retrieved,
    # and paths into which it is extracted and then moved.
    url = (
        'https://github.com/jedisct1/libsodium/releases' +
        '/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz'
    )
    libsodium_tar_gz_path = './src/bcl/libsodium.tar.gz'
    libsodium_tar_gz_folder = './src/bcl/libsodium_tar_gz'

    # Download the source archive to a local path (unless
    # it is already present).
    if not os.path.exists(libsodium_tar_gz_path):
        try:
            urllib.request.urlretrieve(url, filename=libsodium_tar_gz_path)
        except:
            raise RuntimeError(
                'failed to download libsodium archive and no local ' +
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

    return libsodium_folder
def extract_current_build_path():
    """
    Extract path to current bcl build directory
    """

    build_dirs = os.listdir("build")
    lib_dir = None
    for item in build_dirs:
        if "lib." in item:
            lib_dir = item

    if lib_dir is None:  # If still None, then settle for just 'lib' with no '.'.
        for item in build_dirs:
            if "lib" in item:
                lib_dir = item

    if lib_dir is None:
        raise NotADirectoryError(
            "Could not locate lib.<platform>-<python_version> directory within build directory."
        )

    return f"build/{lib_dir}/bcl/"

def extract_current_lib_path():
    """
    Extract path to temp.<platform>-<arch>-<python_version> compiled libsodium library
    """

    build_dirs = os.listdir("build")
    lib_dir = None
    for item in build_dirs:
        if "temp." in item:
            lib_dir = item

    if lib_dir is None:
        raise NotADirectoryError(
            "Could not locate lib.<platform>-<python_version> directory within build directory."
        )

    return f"build/{lib_dir}/lib/"

def render_sodium():
    """
    Emit compiled sodium binary as hex string in _sodium.py file
    """

    if os.environ.get('LIB', None) is None and sys.platform == "win32":
        raise EnvironmentError(
            "For Windows builds, environment variable $LIB must be set to path to libsodium directory"
        )

    # Extract path to compiled libsodium binary
    path_to_sodium = \
        f"{os.environ.get('LIB')}/libsodium.dll" if sys.platform == "win32" \
            else f"{extract_current_lib_path()}/libsodium.so"

    data = {
        "SODIUM_HEX": open(
            path_to_sodium, "rb"
        ).read().hex()
    }
    print('\n\n\n debug \n\n\n', os.listdir(extract_current_build_path()), '?\n\n\n')
    template = open(os.path.join(extract_current_build_path(), "_sodium.tmpl"), encoding='utf-8').read()  # pylint: disable=consider-using-with

    # Emit rendered file to build directory
    with open(f"{extract_current_build_path()}/_sodium.py", "w", encoding='utf-8') as sodium_out:
        sodium_out.write(pystache.render(template, data))

class Distribution(Distribution):
    def has_c_libraries(self):
        # Even though libsodium for Windows includes a precompiled libsodium.dll binary,
        # we still need to call render_sodium() for windows builds in the build_clib.run
        # function, which only gets triggered if this function returns True
        return True

def extract_sodium_from_static_archive(lib_temp: str):
    """
    For certain versions of macOS, the libsodium.a contains multiple target architectures.
    Calls to subprocess are wrapped in a try/except because only certain macOS GH runners contain
    these multi-target files
    """

    if platform.processor() == "arm":
        try:
            subprocess.check_call(['lipo', 'libsodium.a', '-thin', 'arm64', '-output', 'libsodium.a'], cwd=lib_temp)
        except:
            pass
    else:
        try:
            subprocess.check_call(['lipo', 'libsodium.a', '-thin', 'x86_64', '-output', 'libsodium.a'], cwd=lib_temp)
        except:
            pass

class build_clib(_build_clib):
    def get_source_files(self):
        return [
            file
            for i in range(1, 8)
            for file in glob.glob(os.path.relpath('src/bcl/libsodium' + ('/*' * i)))
        ]

    def build_libraries(self, libraries):
        raise RuntimeError('`build_libraries` should not be invoked')

    def check_library_list(self, libraries):
        raise RuntimeError('`check_library_list` should not be invoked')

    def get_library_names(self):
        return ['sodium']

    def run(self):
        # On Windows, only a precompiled dynamic library file is used.
        if sys.platform == 'win32':
            render_sodium()
            return

        # Confirm that make utility can be found.
        found = False
        if not os.environ.get('PATH', None) is None:
            for p in os.environ.get('PATH', '').split(os.pathsep):
                p = os.path.join(p, 'make')
                if os.access(p, os.X_OK):
                    found = True
                for e in filter(
                    None,
                    os.environ.get('PATHEXT', '').split(os.pathsep)
                ):
                    if os.access(p + e, os.X_OK):
                        found = True
        if not found:
            raise RuntimeError('make utility cannot be found')

        # Reproduce Python's build environment variables.
        os.environ.update({
            variable: value
            for (variable, value) in get_config_vars().items()
            if (
                variable in [
                    'LDFLAGS', 'CFLAGS', 'CC', 'CCSHARED', 'LDSHARED'
                ] and variable not in os.environ
            )
        })

        # Ensure the temporary build directory exists.
        build_temp = os.path.abspath(self.build_temp)
        try:
            os.makedirs(build_temp)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        # Retrieve (if necessary) and extract the libsodium source tree.
        libsodium_folder = prepare_libsodium_source_tree()

        # Ensure that all executable files have the necessary permissions.
        for filename in [
            'autogen.sh', 'compile', 'configure', 'depcomp', 'install-sh',
            'missing', 'msvc-scripts/process.bat', 'test/default/wintest.bat',
        ]:
            os.chmod(os.path.relpath(libsodium_folder + '/' + filename), 0o755)

        # Configure libsodium, build it as a shared library file, check it,
        # and install it.
        subprocess.check_call(
            [os.path.abspath(os.path.relpath('src/bcl/libsodium/configure'))] +
            [
                '--disable-shared', '--enable-static',
                '--disable-debug', '--disable-dependency-tracking', '--with-pic',
            ] +
            (['--disable-ssp'] if platform.system() == 'SunOS' else []) +
            ['--prefix', os.path.abspath(self.build_clib)],
            cwd=build_temp
        )
        make_args = os.environ.get('LIBSODIUM_MAKE_ARGS', '').split()
        subprocess.check_call(['make'] + make_args, cwd=build_temp)
        subprocess.check_call(['make', 'check'] + make_args, cwd=build_temp)
        subprocess.check_call(['make', 'install'] + make_args, cwd=build_temp)

        # Build dynamic (shared object) library file from the statically compiled archive binary file.
        lib_temp = os.path.join(self.build_clib, 'lib')

        # Different macOS GH runners contain either single or multi-target static archives
        if sys.platform == "darwin":
            extract_sodium_from_static_archive(lib_temp)

        # Explode the archive into many individual object files.
        subprocess.check_call(['ar', '-x', 'libsodium.a'], cwd=lib_temp)

        import glob
        object_file_relpaths = glob.glob(lib_temp+"/*.o")
        object_file_names = [o.split('/')[-1] for o in object_file_relpaths]
        subprocess.check_call(['gcc', '-shared'] + object_file_names + ['-o', 'libsodium.so'], cwd=lib_temp)  # Invoke gcc to (re-)link dynamically.

        # Emit sodium binary to _sodium.py file as hex-encoded string
        render_sodium()

with open('README.rst', 'r') as fh:
    long_description = fh.read()

name = 'bcl'
version = '2.2.0'

setup(
    name=name,
    version=version,
    packages=[name],
    package_data={
        "": ["*.tmpl"]
    },
    ext_package=name,
    install_requires=['pystache~=0.6'],
    extras_require={
        'build': [
            'setuptools~=62.0',
            'wheel~=0.37',
            'pystache~=0.6'
        ],
        'docs': [
            'sphinx~=4.2.0',
            'sphinx-rtd-theme~=1.0.0'
        ],
        'test': [
            'pytest~=7.0',
            'pytest-cov~=3.0'
        ],
        'lint': [
            'pylint~=2.14.0'
        ],
        'coveralls': [
            'coveralls~=3.3.1'
        ],
        'publish': [
            'twine~=4.0'
        ]
    },
    license='MIT',
    url='https://github.com/nthparty/bcl',
    author='Nth Party, Ltd.',
    author_email='team@nthparty.com',
    description='Python library that provides a simple interface ' + \
                'for symmetric (i.e., secret-key) and asymmetric ' + \
                '(i.e., public-key) encryption/decryption primitives.',
    long_description=long_description,
    long_description_content_type='text/x-rst',
    cmdclass={
        'build_clib': build_clib
    },
    distclass=Distribution,
    zip_safe=False
)

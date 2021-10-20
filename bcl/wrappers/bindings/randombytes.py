# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

from wrappers import exceptions as exc
from wrappers._sodium import ffi, lib

randombytes_SEEDBYTES = lib.randombytes_seedbytes()


def randombytes(size):
    """
    Returns ``size`` number of random bytes from a cryptographically secure
    random source.

    :param size: int
    :rtype: bytes
    """
    buf = ffi.new("unsigned char[]", size)
    lib.randombytes(buf, size)
    return ffi.buffer(buf, size)[:]


def randombytes_buf_deterministic(size, seed):
    """
    Returns ``size`` number of deterministically generated pseudorandom bytes
    from a seed

    :param size: int
    :param seed: bytes
    :rtype: bytes
    """
    if len(seed) != randombytes_SEEDBYTES:
        raise exc.TypeError(
            "Deterministic random bytes must be generated " "from 32 bytes"
        )

    buf = ffi.new("unsigned char[]", size)
    lib.randombytes_buf_deterministic(buf, size, seed)
    return ffi.buffer(buf, size)[:]

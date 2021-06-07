# Copyright 2013-2019 Donald Stufft and individual contributors
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

from bcl.bindings.crypto_box import (
    crypto_box,
    crypto_box_BEFORENMBYTES,
    crypto_box_BOXZEROBYTES,
    crypto_box_NONCEBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SEALBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_box_SEEDBYTES,
    crypto_box_ZEROBYTES,
    crypto_box_afternm,
    crypto_box_beforenm,
    crypto_box_keypair,
    crypto_box_open,
    crypto_box_open_afternm,
    crypto_box_seal,
    crypto_box_seal_open,
    crypto_box_seed_keypair,
)
from bcl.bindings.crypto_scalarmult import (
    crypto_scalarmult,
    crypto_scalarmult_BYTES,
    crypto_scalarmult_SCALARBYTES,
    crypto_scalarmult_base,
)
from bcl.bindings.crypto_secretbox import (
    crypto_secretbox,
    crypto_secretbox_BOXZEROBYTES,
    crypto_secretbox_KEYBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_MESSAGEBYTES_MAX,
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_ZEROBYTES,
    crypto_secretbox_open,
)
from bcl.bindings.randombytes import (
    randombytes,
    randombytes_buf_deterministic,
)
from bcl.bindings.sodium_core import sodium_init
from bcl.bindings.utils import (
    sodium_add,
    sodium_increment,
    sodium_memcmp,
    sodium_pad,
    sodium_unpad,
)


__all__ = [
    "crypto_box_SECRETKEYBYTES",
    "crypto_box_PUBLICKEYBYTES",
    "crypto_box_SEEDBYTES",
    "crypto_box_NONCEBYTES",
    "crypto_box_ZEROBYTES",
    "crypto_box_BOXZEROBYTES",
    "crypto_box_BEFORENMBYTES",
    "crypto_box_SEALBYTES",
    "crypto_box_keypair",
    "crypto_box",
    "crypto_box_open",
    "crypto_box_beforenm",
    "crypto_box_afternm",
    "crypto_box_open_afternm",
    "crypto_box_seal",
    "crypto_box_seal_open",
    "crypto_box_seed_keypair",
    "crypto_scalarmult_BYTES",
    "crypto_scalarmult_SCALARBYTES",
    "crypto_scalarmult",
    "crypto_scalarmult_base",
    "crypto_secretbox_KEYBYTES",
    "crypto_secretbox_NONCEBYTES",
    "crypto_secretbox_ZEROBYTES",
    "crypto_secretbox_BOXZEROBYTES",
    "crypto_secretbox_MACBYTES",
    "crypto_secretbox_MESSAGEBYTES_MAX",
    "crypto_secretbox",
    "crypto_secretbox_open",
    "crypto_secretstream_xchacha20poly1305_ABYTES",
    "crypto_secretstream_xchacha20poly1305_HEADERBYTES",
    "crypto_secretstream_xchacha20poly1305_KEYBYTES",
    "crypto_secretstream_xchacha20poly1305_STATEBYTES",
    "crypto_secretstream_xchacha20poly1305_TAG_FINAL",
    "crypto_secretstream_xchacha20poly1305_TAG_MESSAGE",
    "crypto_secretstream_xchacha20poly1305_TAG_PUSH",
    "crypto_secretstream_xchacha20poly1305_TAG_REKEY",
    "crypto_secretstream_xchacha20poly1305_init_pull",
    "crypto_secretstream_xchacha20poly1305_init_push",
    "crypto_secretstream_xchacha20poly1305_keygen",
    "crypto_secretstream_xchacha20poly1305_pull",
    "crypto_secretstream_xchacha20poly1305_push",
    "crypto_secretstream_xchacha20poly1305_rekey",
    "crypto_secretstream_xchacha20poly1305_state",
    "randombytes",
    "randombytes_buf_deterministic",
    "sodium_init",
    "sodium_add",
    "sodium_increment",
    "sodium_memcmp",
    "sodium_pad",
    "sodium_unpad",
]


# Initialize Sodium
sodium_init()

"""
CFFI interface to NaCl and libsodium library
"""
from __future__ import absolute_import
from __future__ import division

import functools

from cffi import FFI


__all__ = ["ffi", "lib"]


ffi = FFI()
ffi.cdef(
    # Secret Key Encryption
    """
        static const int crypto_secretbox_KEYBYTES;
        static const int crypto_secretbox_NONCEBYTES;
        static const int crypto_secretbox_ZEROBYTES;
        static const int crypto_secretbox_BOXZEROBYTES;

        int crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_secretbox_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
    """

    # Public Key Encryption - Signatures
    """
        static const int crypto_sign_PUBLICKEYBYTES;
        static const int crypto_sign_SECRETKEYBYTES;
        static const int crypto_sign_BYTES;

        int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, unsigned char *seed);
        int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
        int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);
    """

    # Public Key Encryption
    """
        static const int crypto_box_PUBLICKEYBYTES;
        static const int crypto_box_SECRETKEYBYTES;
        static const int crypto_box_BEFORENMBYTES;
        static const int crypto_box_NONCEBYTES;
        static const int crypto_box_ZEROBYTES;
        static const int crypto_box_BOXZEROBYTES;

        int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
        int crypto_box_afternm(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_box_open_afternm(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
        int crypto_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk);
    """

    # Hashing
    """
        static const int crypto_hash_BYTES;
        static const int crypto_hash_sha256_BYTES;
        static const int crypto_hash_sha512_BYTES;

        int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen);
    """

    # Secure Random
    """
        void randombytes(unsigned char * const buf, const unsigned long long buf_len);
    """

    # Low Level - Scalar Multiplication
    """
        int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);
    """
)

SOURCES = """
	crypto_auth/crypto_auth.c
	crypto_auth/hmacsha256/auth_hmacsha256_api.c
	crypto_auth/hmacsha256/ref/api.h
	crypto_auth/hmacsha256/ref/hmac_hmacsha256.c
	crypto_auth/hmacsha256/ref/verify_hmacsha256.c
	crypto_auth/hmacsha512256/auth_hmacsha512256_api.c
	crypto_auth/hmacsha512256/ref/api.h
	crypto_auth/hmacsha512256/ref/hmac_hmacsha512256.c
	crypto_auth/hmacsha512256/ref/verify_hmacsha512256.c
	crypto_box/crypto_box.c
	crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305_api.c
	crypto_box/curve25519xsalsa20poly1305/ref/api.h
	crypto_box/curve25519xsalsa20poly1305/ref/after_curve25519xsalsa20poly1305.c
	crypto_box/curve25519xsalsa20poly1305/ref/before_curve25519xsalsa20poly1305.c
	crypto_box/curve25519xsalsa20poly1305/ref/box_curve25519xsalsa20poly1305.c
	crypto_box/curve25519xsalsa20poly1305/ref/keypair_curve25519xsalsa20poly1305.c
	crypto_core/hsalsa20/ref2/core_hsalsa20.c
	crypto_core/hsalsa20/core_hsalsa20_api.c
	crypto_core/hsalsa20/ref2/api.h
	crypto_core/salsa20/ref/core_salsa20.c
	crypto_core/salsa20/core_salsa20_api.c
	crypto_core/salsa20/ref/api.h
	crypto_core/salsa2012/ref/core_salsa2012.c
	crypto_core/salsa2012/core_salsa2012_api.c
	crypto_core/salsa2012/ref/api.h
	crypto_core/salsa208/ref/core_salsa208.c
	crypto_core/salsa208/core_salsa208_api.c
	crypto_core/salsa208/ref/api.h
	crypto_generichash/crypto_generichash.c
	crypto_generichash/blake2/generichash_blake2_api.c
	crypto_generichash/blake2/ref/api.h
	crypto_generichash/blake2/ref/blake2-impl.h
	crypto_generichash/blake2/ref/blake2.h
	crypto_generichash/blake2/ref/blake2b-ref.c
	crypto_generichash/blake2/ref/generichash_blake2b.c
	crypto_hash/crypto_hash.c
	crypto_hash/sha256/hash_sha256_api.c
	crypto_hash/sha256/ref/api.h
	crypto_hash/sha256/ref/hash_sha256.c
	crypto_hash/sha512/hash_sha512_api.c
	crypto_hash/sha512/ref/api.h
	crypto_hash/sha512/ref/hash_sha512.c
	crypto_hashblocks/sha256/ref/blocks_sha256.c
	crypto_hashblocks/sha256/hashblocks_sha256_api.c
	crypto_hashblocks/sha256/ref/api.h
	crypto_hashblocks/sha512/ref/blocks_sha512.c
	crypto_hashblocks/sha512/hashblocks_sha512_api.c
	crypto_hashblocks/sha512/ref/api.h
	crypto_onetimeauth/crypto_onetimeauth.c
	crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
	crypto_onetimeauth/poly1305/onetimeauth_poly1305_api.c
	crypto_onetimeauth/poly1305/onetimeauth_poly1305_try.c
	crypto_onetimeauth/poly1305/53/api.h
	crypto_onetimeauth/poly1305/53/auth_poly1305_53.c
	crypto_onetimeauth/poly1305/53/verify_poly1305_53.c
	crypto_onetimeauth/poly1305/ref/api.h
	crypto_onetimeauth/poly1305/ref/auth_poly1305_ref.c
	crypto_onetimeauth/poly1305/ref/verify_poly1305_ref.c
	crypto_scalarmult/crypto_scalarmult.c
	crypto_secretbox/crypto_secretbox.c
	crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305_api.c
	crypto_secretbox/xsalsa20poly1305/ref/api.h
	crypto_secretbox/xsalsa20poly1305/ref/box_xsalsa20poly1305.c
	crypto_shorthash/crypto_shorthash.c
	crypto_shorthash/siphash24/shorthash_siphash24_api.c
	crypto_shorthash/siphash24/ref/api.h
	crypto_shorthash/siphash24/ref/shorthash_siphash24.c
	crypto_sign/crypto_sign.c
	crypto_sign/ed25519/ref10/base.h
	crypto_sign/ed25519/ref10/base2.h
	crypto_sign/ed25519/sign_ed25519_api.c
	crypto_sign/ed25519/ref10/api.h
	crypto_sign/ed25519/ref10/d.h
	crypto_sign/ed25519/ref10/d2.h
	crypto_sign/ed25519/ref10/fe.h
	crypto_sign/ed25519/ref10/fe_0.c
	crypto_sign/ed25519/ref10/fe_1.c
	crypto_sign/ed25519/ref10/fe_add.c
	crypto_sign/ed25519/ref10/fe_cmov.c
	crypto_sign/ed25519/ref10/fe_copy.c
	crypto_sign/ed25519/ref10/fe_frombytes.c
	crypto_sign/ed25519/ref10/fe_invert.c
	crypto_sign/ed25519/ref10/fe_isnegative.c
	crypto_sign/ed25519/ref10/fe_isnonzero.c
	crypto_sign/ed25519/ref10/fe_mul.c
	crypto_sign/ed25519/ref10/fe_neg.c
	crypto_sign/ed25519/ref10/fe_pow22523.c
	crypto_sign/ed25519/ref10/fe_sq.c
	crypto_sign/ed25519/ref10/fe_sq2.c
	crypto_sign/ed25519/ref10/fe_sub.c
	crypto_sign/ed25519/ref10/fe_tobytes.c
	crypto_sign/ed25519/ref10/ge.h
	crypto_sign/ed25519/ref10/ge_add.c
	crypto_sign/ed25519/ref10/ge_add.h
	crypto_sign/ed25519/ref10/ge_double_scalarmult.c
	crypto_sign/ed25519/ref10/ge_frombytes.c
	crypto_sign/ed25519/ref10/ge_madd.c
	crypto_sign/ed25519/ref10/ge_madd.h
	crypto_sign/ed25519/ref10/ge_msub.c
	crypto_sign/ed25519/ref10/ge_msub.h
	crypto_sign/ed25519/ref10/ge_p1p1_to_p2.c
	crypto_sign/ed25519/ref10/ge_p1p1_to_p3.c
	crypto_sign/ed25519/ref10/ge_p2_0.c
	crypto_sign/ed25519/ref10/ge_p2_dbl.c
	crypto_sign/ed25519/ref10/ge_p2_dbl.h
	crypto_sign/ed25519/ref10/ge_p3_0.c
	crypto_sign/ed25519/ref10/ge_p3_dbl.c
	crypto_sign/ed25519/ref10/ge_p3_to_cached.c
	crypto_sign/ed25519/ref10/ge_p3_to_p2.c
	crypto_sign/ed25519/ref10/ge_p3_tobytes.c
	crypto_sign/ed25519/ref10/ge_precomp_0.c
	crypto_sign/ed25519/ref10/ge_scalarmult_base.c
	crypto_sign/ed25519/ref10/ge_sub.c
	crypto_sign/ed25519/ref10/ge_sub.h
	crypto_sign/ed25519/ref10/ge_tobytes.c
	crypto_sign/ed25519/ref10/keypair.c
	crypto_sign/ed25519/ref10/open.c
	crypto_sign/ed25519/ref10/pow22523.h
	crypto_sign/ed25519/ref10/pow225521.h
	crypto_sign/ed25519/ref10/sc.h
	crypto_sign/ed25519/ref10/sc_muladd.c
	crypto_sign/ed25519/ref10/sc_reduce.c
	crypto_sign/ed25519/ref10/sign.c
	crypto_sign/ed25519/ref10/sqrtm1.h
	crypto_sign/edwards25519sha512batch/sign_edwards25519sha512batch_api.c
	crypto_sign/edwards25519sha512batch/ref/api.h
	crypto_sign/edwards25519sha512batch/ref/fe25519.h
	crypto_sign/edwards25519sha512batch/ref/fe25519_edwards25519sha512batch.c
	crypto_sign/edwards25519sha512batch/ref/ge25519.h
	crypto_sign/edwards25519sha512batch/ref/ge25519_edwards25519sha512batch.c
	crypto_sign/edwards25519sha512batch/ref/sc25519.h
	crypto_sign/edwards25519sha512batch/ref/sc25519_edwards25519sha512batch.c
	crypto_sign/edwards25519sha512batch/ref/sign_edwards25519sha512batch.c
	crypto_stream/crypto_stream.c
	crypto_stream/aes128ctr/portable/afternm_aes128ctr.c
	crypto_stream/aes128ctr/stream_aes128ctr_api.c
	crypto_stream/aes128ctr/portable/api.h
	crypto_stream/aes128ctr/portable/beforenm_aes128ctr.c
	crypto_stream/aes128ctr/portable/common.h
	crypto_stream/aes128ctr/portable/common_aes128ctr.c
	crypto_stream/aes128ctr/portable/consts.h
	crypto_stream/aes128ctr/portable/consts_aes128ctr.c
	crypto_stream/aes128ctr/portable/int128.h
	crypto_stream/aes128ctr/portable/int128_aes128ctr.c
	crypto_stream/aes128ctr/portable/stream_aes128ctr.c
	crypto_stream/aes128ctr/portable/types.h
	crypto_stream/aes128ctr/portable/xor_afternm_aes128ctr.c
	crypto_stream/aes256estream/hongjun/aes-table.h
	crypto_stream/aes256estream/hongjun/aes256-ctr.c
	crypto_stream/aes256estream/hongjun/aes256.h
	crypto_stream/aes256estream/stream_aes256estream_api.c
	crypto_stream/aes256estream/hongjun/api.h
	crypto_stream/aes256estream/hongjun/ecrypt-sync.h
	crypto_stream/salsa2012/stream_salsa2012_api.c
	crypto_stream/salsa2012/ref/api.h
	crypto_stream/salsa2012/ref/stream_salsa2012.c
	crypto_stream/salsa2012/ref/xor_salsa2012.c
	crypto_stream/salsa208/stream_salsa208_api.c
	crypto_stream/salsa208/ref/api.h
	crypto_stream/salsa208/ref/stream_salsa208.c
	crypto_stream/salsa208/ref/xor_salsa208.c
	crypto_stream/xsalsa20/stream_xsalsa20_api.c
	crypto_stream/xsalsa20/ref/api.h
	crypto_stream/xsalsa20/ref/stream_xsalsa20.c
	crypto_stream/xsalsa20/ref/xor_xsalsa20.c
	crypto_verify/16/verify_16_api.c
	crypto_verify/16/ref/api.h
	crypto_verify/16/ref/verify_16.c
	crypto_verify/32/verify_32_api.c
	crypto_verify/32/ref/api.h
	crypto_verify/32/ref/verify_32.c
	randombytes/randombytes.c
	randombytes/salsa20/randombytes_salsa20_random.c
	randombytes/sysrandom/randombytes_sysrandom.c
	sodium/compat.c
	sodium/core.c
	sodium/utils.c
	sodium/version.c

	crypto_scalarmult/curve25519/ref/api.h
	crypto_scalarmult/curve25519/ref/base_curve25519_ref.c
	crypto_scalarmult/curve25519/ref/smult_curve25519_ref.c

	crypto_stream/salsa20/ref/api.h
	crypto_stream/salsa20/ref/stream_salsa20_ref.c
	crypto_stream/salsa20/ref/xor_salsa20_ref.c

""".strip().split()

# TODO: include the alternate code, it probably has internal #ifndefs

from os.path import dirname, join, exists
srcdir = join(dirname(__file__), "libsodium-0.4.2")
sources = [join(srcdir, "src", s) for s in SOURCES if s.endswith(".c")]
for s in sources:
    assert exists(s), s

# try removing the #include, I think it's breaking stuff
lib = ffi.verify("#include <sodium.h>",
                 sources=sources,
                 include_dirs=[#join(srcdir, "include"),
                               join(srcdir, "include", "sodium")])


# This works around a bug in PyPy where CFFI exposed functions do not have a
#   __name__ attribute. See https://bugs.pypy.org/issue1452
def wraps(wrapped):
    def inner(func):
        if hasattr(wrapped, "__name__"):
            return functools.wraps(wrapped)(func)
        else:
            return func
    return inner


# A lot of the functions in nacl return 0 for success and a negative integer
#   for failure. This is inconvenient in Python as 0 is a falsey value while
#   negative integers are truthy. This wrapper has them return True/False as
#   you'd expect in Python
def wrap_nacl_function(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        return ret == 0
    return wrapper

lib.crypto_secretbox = wrap_nacl_function(lib.crypto_secretbox)
lib.crypto_secretbox_open = wrap_nacl_function(lib.crypto_secretbox_open)

lib.crypto_sign_seed_keypair = wrap_nacl_function(lib.crypto_sign_seed_keypair)
lib.crypto_sign = wrap_nacl_function(lib.crypto_sign)
lib.crypto_sign_open = wrap_nacl_function(lib.crypto_sign_open)

lib.crypto_box_keypair = wrap_nacl_function(lib.crypto_box_keypair)
lib.crypto_box_afternm = wrap_nacl_function(lib.crypto_box_afternm)
lib.crypto_box_open_afternm = wrap_nacl_function(lib.crypto_box_open_afternm)
lib.crypto_box_beforenm = wrap_nacl_function(lib.crypto_box_beforenm)

lib.crypto_hash = wrap_nacl_function(lib.crypto_hash)
lib.crypto_hash_sha256 = wrap_nacl_function(lib.crypto_hash_sha256)
lib.crypto_hash_sha512 = wrap_nacl_function(lib.crypto_hash_sha512)

lib.crypto_scalarmult_curve25519_base = wrap_nacl_function(lib.crypto_scalarmult_curve25519_base)

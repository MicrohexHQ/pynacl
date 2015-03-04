
import timeit, time

def bench(setup_statements, test_statement):
    t = timeit.Timer(test_statement, ";".join(setup_statements), time.time)
    # determine number so that 0.2 <= total time < 2.0
    for i in range(1, 10):
        number = 10**i
        x = t.timeit(number)
        if x >= 0.2:
            break
    r = t.repeat(3, number)
    best = min(r)
    usec = best * 1e6 / number
    if usec < 1000:
        return "%.3g usec" % usec
    else:
        msec = usec / 1000
        if msec < 1000:
            return "%.3g msec" % msec
        else:
            sec = msec / 1000
            return "%.3g sec" % sec

def run():
    IM = "from nacl import bindings as raw; msg='H'*10000"

    # Hash
    S1 = "raw.crypto_hash(msg)"
    S2 = "raw.crypto_hash_sha256(msg)"
    S3 = "raw.crypto_hash_sha512(msg)"
    print " Hash (default):", bench([IM], S1)
    print " Hash (sha256):", bench([IM], S2)
    print " Hash (sha512):", bench([IM], S3)

    if False:
        # OneTimeAuth
        S1 = "k = 'k'*raw.crypto_onetimeauth_KEYBYTES"
        S2 = "auth = raw.crypto_onetimeauth(msg, k)"
        S3 = "raw.crypto_onetimeauth_verify(auth, msg, k)"
        print "OneTimeAuth:", bench([IM,S1], S2)
        print "OneTimeAuth verify:", bench([IM,S1,S2], S3)

    # SecretBox
    S1 = "k = 'k'*raw.crypto_secretbox_KEYBYTES"
    S2 = "nonce = raw.randombytes(raw.crypto_secretbox_NONCEBYTES)"
    S3 = "c = raw.crypto_secretbox(msg, nonce, k)"
    S4 = "raw.crypto_secretbox_open(c, nonce, k)"
    print " Secretbox encryption:", bench([IM,S1,S2], S3)
    print " Secretbox decryption:", bench([IM,S1,S2,S3], S4)

    # Box (Curve25519 + Salsa20 + Poly1305)
    S1 = "pk,sk = raw.crypto_box_keypair()"
    S2 = "nonce = raw.randombytes(raw.crypto_box_NONCEBYTES)"
    S3 = "ct = raw.crypto_box(msg, nonce, pk, sk)"
    S4 = "k = raw.crypto_box_beforenm(pk, sk)"
    S5 = "ct = raw.crypto_box_afternm(msg, nonce, k)"
    print " Curve25519 keypair generation:", bench([IM], S1)
    print " Curve25519 encryption:", bench([IM,S1,S2,S3], S3)
    print " Curve25519 beforenm (setup):", bench([IM,S1,S2,S3], S4)
    print " Curve25519 afternm:", bench([IM,S1,S2,S3,S4], S5)

    # Curve25519 (scalarmult)
    S1 = "n = '1'*raw.crypto_scalarmult_SCALARBYTES"
    S2 = "p1 = raw.crypto_scalarmult_base(n)"
    S3 = "p2 = raw.crypto_scalarmult(n, p1)"
    print " Curve25519 scalarmult_base:", bench([IM,S1], S2)
    print " Curve25519 scalarmult:", bench([IM,S1,S2], S3)

    # Ed25519
    S1 = "vk,sk = raw.crypto_sign_keypair()"
    S2 = "sig = raw.crypto_sign(msg, sk)"
    S3 = "raw.crypto_sign_open(sig, vk)"

    print " Ed25519 keypair generation:", bench([IM], S1)
    print " Ed25519 signing:", bench([IM,S1], S2)
    print " Ed25519 verifying:", bench([IM,S1,S2], S3)

run()

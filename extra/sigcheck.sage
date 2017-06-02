
# some code to verify a sign-to-contract in Bitcoin txid
# ff1dca15029d1df57a601f180308bcb6b91f2e8e129668452eaf066cd0668fa6

import hashlib
import codecs
import binascii

# Parameters for secp256k1
F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
C = EllipticCurve ([F (0), F (7)])
G = C.lift_x(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)

## Thing I sign-to-contracted to
msghash = hashlib.sha256('This is andytoshi on 2017-05-16 21:30 UTC').digest()

## Original R value (you cannot verify the s2c unless someone tells you this)
R = C.lift_x(0x08aec434612f56df3f02c4e678260424415882ebd3efc16d52e3f9c1e39afdb0)

## Compute tweak
h = hashlib.sha256()
# same as R, but encoded in compact form (0x03 then just x-value)
h.update(binascii.unhexlify("0308aec434612f56df3f02c4e678260424415882ebd3efc16d52e3f9c1e39afdb0"))
h.update(msghash)
tweak = int(h.digest().encode('hex'), 16)

## Output tweaked R
Rfinal = R + tweak * G
print ("The r-value in the sig of ff1dca15029d1df57a601f180308bcb6b91f2e8e129668452eaf066cd0668fa6")
print ("should be the x-coordinate %x" % Rfinal.xy()[0])


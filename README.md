
# SigHacker

Simple tool to produce digital signatures using the secp256k1 library.

## Basics

To produce a keypair, start with a 32-byte hex-encoded private key. To get
the corresponding public key run
```
sighacker publickey <hex-encoded secret key>
```

To sign a message using a hex-encoded private key, simply run the tool as
```
sighacker sign <secret key> 'This is my message'
```
which will output a hex-encoded signature. To verify the signature, given
a hex-encoded public key, type
```
sighacker verify <public key> <signature> 'This is my message'
```

## Advanced

However, SigHacker is capable of more interesting things. In particular it can
produce *sign-to-contract* signatures, which commit to some extra data. To do
this run
```
sighacker signtocontract <secret key> <hex-encoded commitment> <message>
```
The output will be two lines. The first is the hex-encoded signature, and the
second is the hex-encoded *original nonce*. You can verify a commitment with
nonce `N` by computing `N' = sha256(N || commitment)` and checking that the
result is used in the signature.



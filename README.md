
# SigHacker

Simple tool to produce digital signatures using the secp256k1 library.

## Basics

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

However, SigHacker is capable of more interesting things.




# Throwaway test keys

These private keys protect nothing. They were generated for
`tests/key_loading.rs` with OpenSSL 3.5.7 on 2026-09-29, so that key loading
is checked against an independent implementation:

```console
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out p256.pem   # likewise P-384, P-521
$ openssl genpkey -algorithm ED25519 -out ed25519.pem
$ openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048.pem  # and 1024, to be refused
$ openssl genpkey -algorithm X25519 -out x25519.pem                              # cannot sign: refused
$ openssl genpkey -algorithm ML-DSA-65 -out mldsa65-both.pem                     # seed and expanded key
$ openssl pkey -in mldsa65-both.pem -provparam ml-dsa.output_formats=seed-only -out mldsa65-seed.pem
$ openssl genpkey -algorithm ML-DSA-87 -out mldsa87-both.pem                     # likewise seed-only
$ openssl ec -in p256.pem -out p256-sec1.pem                                     # SEC1: refused
$ openssl pkcs8 -topk8 -in p256.pem -passout pass:x -v2 aes-256-cbc -out p256-encrypted.pem  # refused
$ openssl pkey -in <key>.pem -pubout -outform DER -out <key>.spki.der
```

`msg.bin` holds `IronSocketLayer PKCS#8 fixture`. The `.sig` files are
OpenSSL's signatures over it: `openssl dgst -sha256|384|512 -sign` for ECDSA,
with `-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest` for RSA,
and `openssl pkeyutl -sign -rawin` for Ed25519, ML-DSA-65 and ML-DSA-87.

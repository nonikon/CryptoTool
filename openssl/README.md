
OpenSSL1.1.1w build with:
```dos
perl Configure VC-WIN64A --release ^
    no-afalgeng no-async no-autoalginit no-autoerrinit no-autoload-config ^
    no-capieng no-cms no-comp no-ct no-deprecated no-dgram no-dso no-dynamic-engine ^
    no-ec no-ec2m no-engine no-err no-filenames no-gost no-hw-padlock no-makedepend ^
    no-nextprotoneg no-ocsp no-posix-io no-psk no-rfc3779 no-sock no-srp no-srtp no-tests no-threads ^
    no-cmac no-dh no-dsa no-ecdh no-ecdsa no-ocb no-poly1305 no-scrypt no-siphash
nmake
```
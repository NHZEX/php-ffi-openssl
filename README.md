# COpenSSL


[![Build Status](https://drone.cijber.net/api/badges/cijber/copenssl/status.svg)](https://drone.cijber.net/cijber/copenssl)

An effort to make OpenSSL more accessible in PHP via FFI bindings.

**⚠ WARNING:** If you just need a solution to encrypt and sign stuff please look at `libsodium`,
COpenSSL is only meant to be used for in-depth crypto routines.

---

## Install

```bash
composer install cijber/copenssl
```

## Details

Currently this library is implemented as needed. on the current roadmap is PKCS#7 support.

BIO is almost fully implemented

## Headers

`resources` contain the headers used for FFI, these are all concatenated into one string and then loaded in `Cijber\OpenSSL\Instance`.

`resources/gen` contains `template.h` and `full.h`, `full.h` is a fully pre-processed header generated from `template.h`
by running `gcc -E template.h > full.h`, this file helps with creating the headers needed for FFI


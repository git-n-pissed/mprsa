# Description
This module is a mash-up of [python-rsa](https://github.com/sybrenstuvel/python-rsa),
[Toms Fast Math](https://github.com/libtom/tomsfastmath) (ported to MicroPython by
[Damiano Mazzella](https://github.com/dmazzella), the author of [ucrypto](https://github.com/dmazzella/ucrypto)),
and [python-asn1](https://github.com/andrivet/python-asn1).
The goal was to create a MicroPython module that would:

1. Be simple to use
2. Support loading/exporting RSA keys in common formats/structures
3. Support generation of new keys
4. Support signing/verification with common hashing algorithms
5. Support encryption/decryption

# Supported Key Formats
- ### Private:
  - PKCS#1 DER
  - PKCS#1 PEM
  - PKCS#8 DER
  - PKCS#8 PEM
    

- ### Public:
  - PKCS#1 DER
  - PKCS#1 PEM
  - X.509/SPKI DER
  - X.509/SPKI PEM
  
The OpenSSL commands used to generate supported keys are contained in the docstrings for the
functions that operate on those keys.

# Supported Hashing Algorithms
- SHA-1
- SHA-256

# How to Build
1. Clone or copy the repo.
2. Copy the contents (not the actual directory) of the `port_modules` directory into the `modules` directory of the
   MicroPython port you are building for.
3. Copy the `user_c_modules` directory (the actual directory) somewhere you can reference it your MicroPython build
   command.  The MicroPython docs recommend placing user C modules outside the MicroPython directory, but I find it
   easier to simply have a `user_c_modules` directory inside the MicroPython directory which contains all the user C
   modules I want to build.  This way you can simply make sure any other user C modules are included in the
   `micropython.cmake` in that directory.
4. Run a command similar to this.  The command may change based on your port, board, and directory structure:
    ```bash
    make -j8 BOARD=GENERIC_S3 USER_C_MODULES="$(pwd)/micropython/user_c_modules/mprsa/micropython.cmake" -C "$(pwd)/micropython/ports/esp32"
    ```

# Examples
  See [test.py](https://github.com/git-n-pissed/mprsa/blob/master/tests/test.py)
  
# Supported Hardware
Hardware for which it has been confirmed this module works on is listed below.  If you are willing to try the module
out on other hardware and run [test.py](https://github.com/git-n-pissed/mprsa/blob/master/tests/test.py) to verify it
works, that would be appreciated.  Make an issue with your findings and I'll update this
[README.md](https://github.com/git-n-pissed/mprsa/blob/main/README.md), or make a PR which updates this section of the
[README.md](https://github.com/git-n-pissed/mprsa/blob/main/README.md).

* ESP32-S3

# Known Limitations
- Key generation speed
  - Even when using Toms Fast Math, generating a key of any size that can offer real security is slow.  The `gen_key`
    function defaults to the fastest possible options for key generation (i.e. allowing modulus "n" to be of slightly
    fewer bits than specified and not requiring "p" and "q" to be safe primes), but generating a 2048-bit key on an
    ESP32-S3 still takes 3 - 5 minutes.  When a modulus "n" of an exact size and/or "p" and "q" values which are safe
    primes are desired, the time to generate keys increases dramatically.  In the case of 2048-bit keys sometimes 30
    minutes, sometimes an hour or more.

# Licenses
All the code in this module is copyright under the Apache License, the MIT License, or is public domain.

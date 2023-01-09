# -*- coding: utf-8 -*-

# Parts of this file are copyright (c) 2011 by Sybren A. Stüvel <sybren@stuvel.eu>
# The remainder is copyright (c) 2023 by the AUTHORS under the LICENSE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Classes and functions supporting RSA public/private keys.
"""

from . import _asn1 as asn1

import _mprsa
import binascii
import hashlib
import os
import struct


# The typing module is helpful during development, but isn't supported by MicroPython, so wrap import in try/except
try:
    import typing
except:
    pass


DEFAULT_EXPONENT = const(65537)  # 65537 is the most commonly used as a public exponent with RSA
KEY_BIT_CNT_MIN = const(32)  # Any keys smaller than this will result in prime number bit counts under 16 bits
KEY_BIT_CNT_MAX = const(7711)  # Any keys larger than this will result in prime number bit counts over 4096 bits
PKCS1_OID = const('1.2.840.113549.1.1.1')  # This OID is defined in Public-Key Cryptography Standards (PKCS) #1


# ASN.1 codes that describe the hash algorithm used.  It is ok to have ASN.1 codes here whose hash function doesn't have
# an entry in the HASH_FUNCTIONS dict.  The ASN.1 codes here just allow us to detect what hash function was used to sign
# a message.
HASH_FUNCTION_ASN1_CODES = {
    'MD5': b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
    'SHA-1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    'SHA-224': b'\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c',
    'SHA-256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    'SHA-384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    'SHA-512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

HASH_FUNCTIONS = {
    'SHA-1': hashlib.sha1,
    'SHA-256': hashlib.sha256,
}


def _get_hash_function(decrypted_signature: bytes) -> typing.Optional[str]:
    """
    Get the hash function used on the decrypted signature.  The hash function must exist as a key in
    `HASH_FUNCTION_ASN1_CODES`, if not, `None` will be returned.

    Args:
        decrypted_signature (bytes): The decrypted signature, fully padded with ASN.1 code.

    Returns:
        result (str): The hash function used on the decrypted signature, or `None` if the hash function used cannot be
            determined.
    """

    for (hash_function, asn1_code) in HASH_FUNCTION_ASN1_CODES.items():
        if asn1_code in decrypted_signature:
            return hash_function

    return None


def _int_to_bytes(unsigned_integer: int, fill_size: typing.Optional[int] = None) -> bytes:
    """
    Convert `unsigned_integer` to raw bytes, base 256 representation.  Does not preserve leading zeros if `fill_size` is
    specified.

    Args:
        unsigned_integer (int): The unsigned integer to process.

    fill_size (typing.Optional[int]): Optional.  Causes the resulting byte string to be padded from the beginning with
        0 bytes until the value specified by `fill_size` is reached.  The value specified must be larger than the
        resulting byte string with no fill, lest an `OverflowError` exception occur.  Defaults to `None`.

    Returns:
        result (bytes): Raw bytes in a base 256 representation.
    """

    # Verify the integer arg is an unsigned integer
    if unsigned_integer < 0 or not isinstance(unsigned_integer, int):
        raise ValueError('Expected unsigned integer, but got: {unsigned_integer}'.format(unsigned_integer=unsigned_integer))

    # Pack the integer into bytes
    max_uint64 = 0xFFFFFFFFFFFFFFFF
    max_uint32 = 0xFFFFFFFF
    max_uint16 = 0xFFFF
    max_uint8 = 0xFF

    if unsigned_integer > max_uint32:
        # 64-bit unsigned integer
        word_bits, max_uint, pack_format = 64, max_uint64, '>Q'
    elif unsigned_integer > max_uint16:
        # 32-bit unsigned integer
        word_bits, max_uint, pack_format = 32, max_uint32, '>L'
    elif unsigned_integer > max_uint8:
        # 16-bit unsigned integer
        word_bits, max_uint, pack_format = 16, max_uint16, '>H'
    else:
        # 8-bit unsigned integer
        word_bits, max_uint, pack_format = 8, max_uint8, '>B'

    raw_bytes = b''
    i = unsigned_integer
    while i > 0:
        raw_bytes = struct.pack(pack_format, i & max_uint) + raw_bytes
        i >>= word_bits

    # Obtain the index of the first non-zero byte
    leading_zero_idx = 0
    for b in raw_bytes:
        if b == b'\x00':
            leading_zero_idx += 1
        else:
            break

    if unsigned_integer == 0:
        raw_bytes = b'\x00'

    # Remove padding from raw_bytes
    raw_bytes = raw_bytes[leading_zero_idx:]

    raw_bytes_len = len(raw_bytes)
    if fill_size:
        if raw_bytes_len > fill_size:
            raise OverflowError('Need {raw_bytes_len} bytes for number, but fill size is {fill_size}'.format(raw_bytes_len=raw_bytes_len, fill_size=fill_size))

        raw_bytes = (b'\x00' * (fill_size - len(raw_bytes))) + raw_bytes

    return raw_bytes


def _pad_for_encryption(message_decrypted: bytes, target_len: int) -> bytes:
    """
    Pads the message for encryption, returning the padded message.  The padding bytes are always random.

    Args:
        message_decrypted (bytes): The message to pad.

        target_len (int): The target length of the padded message.

    Returns:
        result (bytes): The message, padded to the length the target length, in the format "00 02 PADDING 00 MESSAGE".
    """

    max_msg_len = target_len - 11
    msg_len = len(message_decrypted)

    if msg_len > max_msg_len:
        raise OverflowError('Message requires {msg_len} bytes, but there is only space for a message of {max_msg_len} bytes'.format(msg_len=msg_len, max_msg_len=max_msg_len))

    # Get random padding
    padding = b''
    padding_len = target_len - msg_len - 3

    # We remove all 0 bytes, so we'll end up with less padding than desired.
    # Keep adding padding until the correct length has been reached.
    while len(padding) < padding_len:
        needed_bytes = padding_len - len(padding)

        # Always read at least 8 bytes more than we need, and trim off the rest after removing the 0 bytes. This
        # increases the chance of getting enough bytes, especially when needed_bytes is small
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b'\x00', b'')
        padding = padding + new_padding[:needed_bytes]

    assert len(padding) == padding_len

    return b''.join([b'\x00\x02', padding, b'\x00', message_decrypted])


def _pad_for_signing(message: bytes, target_len: int) -> bytes:
    """
    Pads the message for signing, returning the padded message.  The padding bytes are always "FF".

    Args:
        message (bytes): The message to pad.

        target_len (int): The target length of the padded message.

    Returns:
        result (bytes): The message, padded to the length the target length, in the format "00 01 PADDING 00 MESSAGE".
    """

    max_msg_len = target_len - 11
    msg_len = len(message)

    if msg_len > max_msg_len:
        raise OverflowError('Message requires {msg_len} bytes, but there is only space for a message of {max_msg_len} bytes'.format(msg_len=msg_len, max_msg_len=max_msg_len))

    padding_len = target_len - msg_len - 3

    return b''.join([b'\x00\x01', padding_len * b'\xff', b'\x00', message])


def _pem_to_der(pem_data: typing.Union[bytes, str], pem_marker: typing.Union[bytes, str]) -> bytes:
    """
    Convert PEM data to DER data.

    Args:
        pem_data (typing.Union[bytes, str]): The PEM data to convert.

        pem_marker (typing.Union[bytes, str]): The marker of the PEM content, such as 'RSA PRIVATE KEY' when your file
            has "-----BEGIN RSA PRIVATE KEY-----" and "-----END RSA PRIVATE KEY-----" markers.

    Returns:
        result (bytes): The PEM data converted to DER data.
    """

    # We want bytes, not text. If it's text, it can be converted to ASCII bytes.
    if not isinstance(pem_data, bytes):
        pem_data = pem_data.encode('ascii')

    if not isinstance(pem_marker, bytes):
        pem_marker = pem_marker.encode('ascii')

    pem_start = b'-----BEGIN ' + pem_marker + b'-----'
    pem_end = b'-----END ' + pem_marker + b'-----'

    pem_lines = []
    in_pem_part = False

    for line in pem_data.split(b'\n'):
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Handle start marker
        if line == pem_start:
            if in_pem_part:
                raise ValueError('Seen start marker "{pem_start}" twice'.format(pem_start=pem_start))

            in_pem_part = True
            continue

        # Skip stuff before first marker
        if not in_pem_part:
            continue

        # Handle end marker
        if in_pem_part and line == pem_end:
            in_pem_part = False
            break

        # Load fields
        if b':' in line:
            continue

        pem_lines.append(line)

    # Do some sanity checks
    if not pem_lines:
        raise ValueError('No PEM start marker "{pem_start}" found'.format(pem_start=pem_start))

    if in_pem_part:
        raise ValueError('No PEM end marker "{pem_end}" found'.format(pem_end=pem_end))

    # Base64-decode the contents
    pem = b''.join(pem_lines)
    return binascii.a2b_base64(pem)


def _der_to_pem(der_data: bytes, pem_marker: typing.Union[bytes, str]) -> bytes:
    """
    Convert DER data to PEM data.

    Args:
        der_data (typing.Union[bytes, str]): The DER data to convert.

        pem_marker (typing.Union[bytes, str]): The marker of the PEM content, such as 'RSA PRIVATE KEY' when your file
            has "-----BEGIN RSA PRIVATE KEY-----" and "-----END RSA PRIVATE KEY-----" markers.

    Returns:
        result (bytes): The DER data converted to PEM data.
    """

    if not isinstance(pem_marker, bytes):
        pem_marker = pem_marker.encode('ascii')

    pem_start = b'-----BEGIN ' + pem_marker + b'-----'
    pem_end = b'-----END ' + pem_marker + b'-----'

    b64 = binascii.b2a_base64(der_data).replace(b'\n', b'')
    pem_lines = [pem_start]

    for block_start in range(0, len(b64), 64):
        block = b64[block_start: block_start + 64]
        pem_lines.append(block)

    pem_lines.append(pem_end)
    pem_lines.append(b'')

    return b'\n'.join(pem_lines)


class AbstractKey(object):
    """
    Abstract superclass for private and public keys.
    """

    def __init__(self, n: int, e: int) -> None:
        self.n = n
        self.e = e

    @classmethod
    def load_pkcs1_der_data(cls, der_data: bytes) -> 'AbstractKey':
        """
        Loads a key in PKCS#1 DER format.

        Args:
            der_data (bytes): Contents of a PKCS#1 DER encoded key file.

        Returns:
            result (AbstractKey): The loaded key.
        """

    @classmethod
    def load_pkcs1_pem_data(cls, pem_data: bytes) -> 'AbstractKey':
        """
        Loads a key in PKCS#1 PEM format.

        Args:
            pem_data (bytes): Contents of a PKCS#1 PEM encoded key file.

        Returns:
            result (AbstractKey): The loaded key.
        """

    def get_pkcs1_der_data(self) -> bytes:
        """
        Gets PKCS#1 DER encoded key file data.

        Returns:
            result (bytes): Contents of a PKCS#1 DER encoded file.
        """

    def get_pkcs1_pem_data(self) -> bytes:
        """
        Gets PKCS#1 PEM encoded key file data.

        Returns:
            result (bytes): Contents of a PKCS#1 PEM encoded file.
        """

    def blind(self, message: int, r: int) -> int:
        """
        Performs blinding on the message using random number 'r'.
        The blinding is such that `message = unblind(decrypt(blind(encrypt(message)))`.
        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29

        Args:
            message (int): The message, as integer, to blind.

            r (int): The random number to blind with.

        Returns:
            result (int): The blinded message.
        """

        return (message * _mprsa.exptmod(r, self.e, self.n)) % self.n

    def unblind(self, blinded: int, r: int) -> int:
        """
        Performs unblinding on the message using random number 'r'.
        The blinding is such that `message = unblind(decrypt(blind(encrypt(message)))`.
        See https://en.wikipedia.org/wiki/Blinding_%28cryptography%29

        Args:
            blinded (int): The blinded message, as integer, to unblind.

            r (int): The random number to unblind with.

        Returns:
            result (int): The original message.
        """

        return (blinded * _mprsa.invmod(r, self.n)) % self.n


class PublicKey(AbstractKey):
    """
    Represents a public RSA key.
    """

    def __getitem__(self, key: str) -> typing.Any:
        return getattr(self, key)

    def __repr__(self) -> str:
        return 'PublicKey({n}, {e})'.format(n=self.n, e=self.e)

    def __getstate__(self) -> typing.Tuple[int, int]:
        return self.n, self.e

    def __setstate__(self, state: typing.Tuple[int, int]) -> None:
        self.n, self.e = state

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PublicKey):
            return False

        return self.n == other.n and self.e == other.e

    def __ne__(self, other: typing.Any) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash((self.n, self.e))

    def encrypt(self, message_decrypted: bytes) -> bytes:
        """
        Encrypts the message using PKCS#1 v1.5.

        Args:
            message_decrypted (bytes): The message to encrypt.  Must be a byte string no longer than "k - 11" bytes, where
                "k" is the number of bytes needed to encode the "n" component of the public key.

        Returns:
            result (bytes): The encrypted message.
        """

        modulus_len = _mprsa.count_bytes(self.n)
        message_decrypted_padded = _pad_for_encryption(message_decrypted, modulus_len)
        message_decrypted_padded_int = int(binascii.hexlify(message_decrypted_padded), 16)
        message_encrypted_int = _mprsa.exptmod(message_decrypted_padded_int, self.e, self.n)
        message_encrypted = _int_to_bytes(message_encrypted_int, modulus_len)

        return message_encrypted

    def get_signature_hash_function(self, encrypted_signature: bytes) -> typing.Optional[str]:
        """
        Get the hash function used on the encrypted signature.  The hash function must exist as a key in
        `HASH_FUNCTION_ASN1_CODES`, if not, `None` will be returned.

        Args:
            encrypted_signature (bytes): The encrypted signature, fully padded with ASN.1 code.

        Returns:
            result (str): The hash function used on the encrypted signature, or `None` if the hash function used cannot be
                determined.
        """

        key_len = _mprsa.count_bytes(self.n)
        encrypted_signature_int = int(binascii.hexlify(encrypted_signature), 16)
        decrypted_signature_int = _mprsa.exptmod(encrypted_signature_int, self.e, self.n)
        decrypted_signature = _int_to_bytes(decrypted_signature_int, key_len)

        return _get_hash_function(decrypted_signature)

    @classmethod
    def load_pkcs1_der_data(cls, der_data: bytes) -> 'PublicKey':
        """
        Loads PCSK#1 DER encoded public key file data.  A key in this format could be generated with the OpenSSL 3.0
        commands:

            `openssl genrsa -traditional -out private_pkcs1.pem 2048`
            `openssl rsa -in private_pkcs1.pem -pubout -RSAPublicKey_out -outform DER -out public_pkcs1.der`

        Args:
            der_data (bytes): Contents of a PKCS#1 DER encoded public key file.

        Returns:
            result (PublicKey): A public key.
        """

        success = False
        do = True
        try:
            while do:
                do = False

                decoder = asn1.Decoder()
                decoder.start(der_data)

                tag = decoder.peek()
                if tag.nr != asn1.Numbers.Sequence:
                    break

                decoder.enter()

                tag, n = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                tag, e = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                success = True

        except:
            pass

        if not success:
            raise ValueError('Invalid key data')

        return cls(n=n, e=e)

    @classmethod
    def load_pkcs1_pem_data(cls, pem_data: bytes) -> 'PublicKey':
        """
        Loads PKCS#1 PEM encoded public key file data.  A key in this format could be generated with the OpenSSL 3.0
        command:

            `openssl genrsa -traditional -out private_pkcs1.pem 2048`
            `openssl rsa -in private_pkcs1.pem -pubout -RSAPublicKey_out -outform PEM -out public_pkcs1.pem`

        Args:
            pem_data (bytes): Contents of a PKCS#1 PEM encoded public key file.

        Returns:
            result (PublicKey): A public key.
        """

        der_data = _pem_to_der(pem_data, 'RSA PUBLIC KEY')
        return cls.load_pkcs1_der_data(der_data)

    @classmethod
    def load_x509_spki_der_data(cls, der_data: bytes) -> 'PublicKey':
        """
        Loads X.509 SPKI (Subject Public Key Info) DER encoded public key file data.  A key in this format could be
        generated with the OpenSSL 3.0 commands:

            `openssl genrsa -out private_pkcs8.pem 2048`
            `openssl rsa -in private_pkcs8.pem -pubout -outform DER -out public_x509_spki.der`

        Args:
            der_data (bytes): Contents of an X.509 SPKI DER encoded private key file.

        Returns:
            result (PublicKey): A public key.
        """

        success = False
        do = True
        try:
            while do:
                do = False

                decoder = asn1.Decoder()
                decoder.start(der_data)

                tag = decoder.peek()
                if tag.nr != asn1.Numbers.Sequence:
                    break

                decoder.enter()

                if tag.nr != asn1.Numbers.Sequence:
                    break

                decoder.enter()

                tag, oid = decoder.read()
                if tag.nr != asn1.Numbers.ObjectIdentifier and oid != PKCS1_OID:
                    break

                decoder.leave()

                tag, pkcs1_der_data = decoder.read()
                if tag.nr != asn1.Numbers.BitString:
                    break

                success = True

        except:
            pass

        if not success:
            raise ValueError('Invalid key data')

        return cls.load_pkcs1_der_data(pkcs1_der_data)

    @classmethod
    def load_x509_spki_pem_data(cls, pem_data: bytes) -> 'PublicKey':
        """
        Loads X.509 SPKI (Subject Public Key Info) PEM encoded public key file data.  A key in this format could be
        generated with the OpenSSL 3.0 commands:

            `openssl genrsa -out private_pkcs8.pem 2048`
            `openssl rsa -in private_pkcs8.pem -pubout -outform PEM -out public_x509_spki.pem`

        Args:
            pem_data (bytes): Contents of an X.509 SPKI PEM encoded public key file.

        Returns:
            result (PublicKey): A public key.
        """

        der_data = _pem_to_der(pem_data, 'PUBLIC KEY')
        return cls.load_x509_spki_der_data(der_data)

    def get_pkcs1_der_data(self) -> bytes:
        """
        Gets PKCS#1 PEM DER encoded public key file data.  A key in this format could be generated with the OpenSSL 3.0
        commands:

            `openssl genrsa -traditional -out private_pkcs1.pem 2048`
            `openssl rsa -in private_pkcs1.pem -pubout -RSAPublicKey_out -outform DER -out public_pkcs1.der`

        Returns:
            result (bytes): Contents of an X.509 SPKI DER encoded file that contains the public key.
        """

        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(self.n, asn1.Numbers.Integer)
        encoder.write(self.e, asn1.Numbers.Integer)
        encoder.leave()

        return encoder.output()

    def get_pkcs1_pem_data(self) -> bytes:
        """
        Gets PKCS#1 PEM encoded public key file data.  A key in this format could be generated with the OpenSSL 3.0
        commands:

            `openssl genrsa -traditional -out private_pkcs1.pem 2048`
            `openssl rsa -in private_pkcs1.pem -pubout -RSAPublicKey_out -outform PEM -out public_pkcs1.pem`

        Returns:
            result (bytes): Contents of an X.509 SPKI PEM encoded file that contains the public key.
        """

        der_data = self.get_pkcs1_der_data()
        return _der_to_pem(der_data, 'RSA PUBLIC KEY')

    def get_x509_spki_der_data(self) -> bytes:
        """
        Gets X.509 SPKI (Subject Public Key Info) DER encoded public key file data.  A key in this format could be
        generated with the OpenSSL 3.0 commands:

            `openssl genrsa -out private_pkcs8.pem 2048`
            `openssl rsa -in private_pkcs8.pem -pubout -outform DER -out public_x509_spki.der`

        Returns:
            result (bytes): Contents of an X.509 SPKI DER encoded file that contains the public key.
        """

        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(PKCS1_OID, asn1.Numbers.ObjectIdentifier)
        encoder.write(None)  # Keys generated with OpenSSL have a NULL at this position per https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2
        encoder.leave()
        encoder.write(self.get_pkcs1_der_data(), asn1.Numbers.BitString)
        encoder.leave()

        return encoder.output()

    def get_x509_spki_pem_data(self) -> bytes:
        """
        Gets X.509 SPKI (Subject Public Key Info) PEM encoded public key file data.  A key in this format could be
        generated with the OpenSSL 3.0 commands:

            `openssl genrsa -out private_pkcs8.pem 2048`
            `openssl rsa -in private_pkcs8.pem -pubout -outform PEM -out public_x509_spki.pem`

        Returns:
            result (bytes): Contents of an X.509 SPKI PEM encoded file that contains the public key.
        """

        der_data = self.get_x509_spki_der_data()
        return _der_to_pem(der_data, 'PUBLIC KEY')

    def verify(self, message: typing.Union[bytes, str, typing.IO[typing.Union[bytes, str]]],
               signature_encrypted: bytes) -> typing.Tuple[bool, typing.Optional[str]]:
        """
        Verifies that the signature matches the message.  The hash function is detected automatically from the signature,
        but must exist as a key in `HASH_FUNCTIONS`.

        Args:
            message (typing.Union[bytes, str, typing.IO[typing.Union[bytes, str]]]): The signed message.

            signature_encrypted (bytes): The encrypted signature, fully padded with ASN.1 code.

        Returns:
            result (typing.Tuple[bool, typing.Optional[str]]): A two item tuple where the first item is a boolean which is
                `True` if the message was verified, otherwise `False`, and the second item is a string identifying the hash
                function used to sign the message, or `None` if the hash function could not be determined.
        """

        success = False
        hash_function = None

        try:
            key_len = _mprsa.count_bytes(self.n)
            encrypted = int(binascii.hexlify(signature_encrypted), 16)
            decrypted = _mprsa.exptmod(encrypted, self.e, self.n)
            decrypted_signature = _int_to_bytes(decrypted, key_len)

            # Get the hash function
            hash_function = _get_hash_function(decrypted_signature)
            if hash_function:
                message_hash = compute_hash(message, hash_function)

                # Reconstruct the expected padded hash
                clear_text = HASH_FUNCTION_ASN1_CODES[hash_function] + message_hash
                expected = _pad_for_signing(clear_text, key_len)

                # Compare with the signed one
                success = expected == decrypted_signature

        except:
            pass

        return success, hash_function


class PrivateKey(AbstractKey):
    """
    Represents a private RSA key.
    """

    def __init__(self, n: int, e: int, d: int, p: int, q: int) -> None:
        AbstractKey.__init__(self, n, e)
        self.d = d
        self.p = p
        self.q = q

        # Calculate exponents and coefficient.
        self.exp1 = int(d % (p - 1))
        self.exp2 = int(d % (q - 1))
        self.coef = _mprsa.invmod(q, p)

    def __getitem__(self, key: str) -> typing.Any:
        return getattr(self, key)

    def __repr__(self) -> str:
        return 'PrivateKey({n}, {e}, {d}, {p}, {q})'.format(n=self.n, e=self.e, d=self.d, p=self.p, q=self.q)

    def __getstate__(self) -> typing.Tuple[int, int, int, int, int, int, int, int]:
        return self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef

    def __setstate__(self, state: typing.Tuple[int, int, int, int, int, int, int, int]) -> None:
        self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef = state

    def __eq__(self, other: typing.Any) -> bool:
        if other is None:
            return False

        if not isinstance(other, PrivateKey):
            return False

        return (
            self.n == other.n
            and self.e == other.e
            and self.d == other.d
            and self.p == other.p
            and self.q == other.q
            and self.exp1 == other.exp1
            and self.exp2 == other.exp2
            and self.coef == other.coef
        )

    def __ne__(self, other: typing.Any) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash((self.n, self.e, self.d, self.p, self.q, self.exp1, self.exp2, self.coef))

    def blinded_decrypt(self, message_encrypted_int: int) -> int:
        """
        Decrypts the message using blinding to prevent side-channel attacks.

        Args:
            message_encrypted_int (int): The encrypted message as an integer.

        Returns:
            result (int): The decrypted message.
        """

        blind_r = _mprsa.gen_rand_int_for_blinding(self.n)
        blinded = self.blind(message_encrypted_int, blind_r)
        decrypted = _mprsa.exptmod(blinded, self.d, self.n)
        return self.unblind(decrypted, blind_r)

    def blinded_encrypt(self, message_decrypted_int: int) -> int:
        """
        Encrypts the message using blinding to prevent side-channel attacks.

        Args:
            message_decrypted_int (int): The decrypted message as an integer.

        Return:
            result (int): The encrypted message.
        """

        blind_r = _mprsa.gen_rand_int_for_blinding(self.n)
        blinded = self.blind(message_decrypted_int, blind_r)
        encrypted = _mprsa.exptmod(blinded, self.d, self.n)
        return self.unblind(encrypted, blind_r)

    def decrypt(self, message_encrypted: bytes) -> typing.Tuple[bool, typing.Optional[bytes]]:
        """
        Decrypts the message using PKCS#1 v1.5.

        Args:
            message_encrypted (bytes): The message to decrypt.

        Returns:
            result (typing.Tuple[bool, typing.Optional[bytes]]): A two item tuple where the first item is a boolean which is
                `True` if the message was decrypted, otherwise `False`, and the second item is the decrypted message, or
                `None` if the message could not be decrypted.
        """

        success = False
        message_decrypted = None

        try:
            modulus_len = _mprsa.count_bytes(self.n)
            message_encrypted_int = int(binascii.hexlify(message_encrypted), 16)
            message_decrypted_padded_int = self.blinded_decrypt(message_encrypted_int)
            message_decrypted_padded = _int_to_bytes(message_decrypted_padded_int, modulus_len)

            # Find the 00 separator between the padding and the message
            padding_idx = message_decrypted_padded.index(b'\x00', 2)
            message_decrypted = message_decrypted_padded[padding_idx + 1:]
            success = True

        except:
            pass

        return success, message_decrypted

    @classmethod
    def load_pkcs1_der_data(cls, der_data: bytes) -> 'PrivateKey':
        """
        Loads PCSK#1 DER encoded private key file data.  A key in this format could be generated with the OpenSSL 3.0
        commands:

            `openssl genrsa -traditional -out private_pkcs1.pem 2048`
            `openssl rsa -traditional -in private_pkcs1.pem -outform DER -out private_pkcs1.der`

        Args:
            der_data (bytes): Contents of a PKCS#1 DER encoded private key file.

        Returns:
            result (PrivateKey): A private key.
        """

        success = False
        do = True
        try:
            while do:
                do = False

                decoder = asn1.Decoder()
                decoder.start(der_data)

                tag = decoder.peek()
                if tag.nr != asn1.Numbers.Sequence:
                    break

                decoder.enter()

                tag, version = decoder.read()
                if tag.nr != asn1.Numbers.Integer or version != 0:  # Version 0 indicates the key is 2 prime RSA.  See http://mpqs.free.fr/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp_EMC_Corporation_Public-Key_Cryptography_Standards_(PKCS).pdf#page=56
                    break

                tag, n = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                tag, e = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                tag, d = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                tag, p = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                tag, q = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                tag, exp1 = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                tag, exp2 = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                tag, coef = decoder.read()
                if tag.nr != asn1.Numbers.Integer:
                    break

                success = True

        except:
            pass

        if not success:
            raise ValueError('Invalid key data')

        private_key = cls(n, e, d, p, q)

        if (private_key.exp1, private_key.exp2, private_key.coef) != (exp1, exp2, coef):
            raise ValueError('Invalid key data')

        return private_key

    @classmethod
    def load_pkcs1_pem_data(cls, pem_data: bytes) -> 'PrivateKey':
        """
        Loads PKCS#1 PEM encoded private key file data.  A key in this format could be generated with the OpenSSL 3.0
        command:

            `openssl genrsa -traditional -out private_pkcs1.pem 2048`

        Args:
            pem_data (bytes): Contents of a PKCS#1 PEM encoded private key file.

        Returns:
            result (PrivateKey): A private key.
        """

        der_data = _pem_to_der(pem_data, 'RSA PRIVATE KEY')
        return cls.load_pkcs1_der_data(der_data)

    @classmethod
    def load_pkcs8_der_data(cls, der_data: bytes) -> 'PrivateKey':
        """
        Loads PCSK#8 DER encoded private key file data.  A key in this format could be generated with the OpenSSL 3.0
        commands:

            `openssl genrsa -out private_pkcs8.pem 2048`
            `openssl rsa -in private_pkcs8.pem -outform DER -out private_pkcs8.der`

        Args:
            der_data (bytes): Contents of a PKCS#1 DER encoded private key file.

        Returns:
            result (PrivateKey): A private key.
        """

        success = False
        do = True
        try:
            while do:
                do = False

                decoder = asn1.Decoder()
                decoder.start(der_data)

                tag = decoder.peek()
                if tag.nr != asn1.Numbers.Sequence:
                    break

                decoder.enter()

                tag, version = decoder.read()
                if tag.nr != asn1.Numbers.Integer or version != 0:  # Version 0 indicates the key is 2 prime RSA.  See http://mpqs.free.fr/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp_EMC_Corporation_Public-Key_Cryptography_Standards_(PKCS).pdf#page=56
                    break

                tag = decoder.peek()
                if tag.nr != asn1.Numbers.Sequence:
                    break

                decoder.enter()

                tag, oid = decoder.read()
                if tag.nr != asn1.Numbers.ObjectIdentifier and oid != PKCS1_OID:
                    break

                decoder.leave()

                tag, pkcs1_der_data = decoder.read()
                if tag.nr != asn1.Numbers.OctetString:
                    break

                success = True

        except:
            pass

        if not success:
            raise ValueError('Invalid key data')

        return cls.load_pkcs1_der_data(pkcs1_der_data)

    @classmethod
    def load_pkcs8_pem_data(cls, pem_data: bytes) -> 'PrivateKey':
        """
        Loads PKCS#8 PEM encoded private key file data.  A key in this format could be generated with the OpenSSL 3.0
        command:

            `openssl genrsa -out private_pkcs8.pem 2048`

        Args:
            pem_data (bytes): Contents of a PKCS#8 PEM encoded private key file.

        Returns:
            result (PrivateKey): A private key.
        """

        der_data = _pem_to_der(pem_data, 'PRIVATE KEY')
        return cls.load_pkcs8_der_data(der_data)

    def get_pkcs1_der_data(self) -> bytes:
        """
        Gets PKCS#1 DER encoded private key file data.  A key in this format could be generated with the OpenSSL 3.0
        commands:

            `openssl genrsa -traditional -out private_pkcs1.pem 2048`
            `openssl rsa -traditional -in private_pkcs1.pem -outform DER -out private_pkcs1.der`

        Returns:
            result (bytes): Contents of a PKCS#1 PEM encoded file that contains the private key.
        """

        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(0, asn1.Numbers.Integer)  # Version 0 indicates the key is 2 prime RSA.  See http://mpqs.free.fr/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp_EMC_Corporation_Public-Key_Cryptography_Standards_(PKCS).pdf#page=56
        encoder.write(self.n, asn1.Numbers.Integer)
        encoder.write(self.e, asn1.Numbers.Integer)
        encoder.write(self.d, asn1.Numbers.Integer)
        encoder.write(self.p, asn1.Numbers.Integer)
        encoder.write(self.q, asn1.Numbers.Integer)
        encoder.write(self.exp1, asn1.Numbers.Integer)
        encoder.write(self.exp2, asn1.Numbers.Integer)
        encoder.write(self.coef, asn1.Numbers.Integer)
        encoder.leave()

        return encoder.output()

    def get_pkcs1_pem_data(self) -> bytes:
        """
        Gets PKCS#1 PEM encoded private key file data.  A key in this format could be generated with the OpenSSL 3.0
        command:

            `openssl genrsa -traditional -out private_pkcs1.pem 2048`

        Returns:
            result (bytes): Contents of a PKCS#1 PEM encoded file that contains the private key.
        """

        der_data = self.get_pkcs1_der_data()
        return _der_to_pem(der_data, 'RSA PRIVATE KEY')

    def get_pkcs8_der_data(self) -> bytes:
        """
        Gets PKCS#8 DER encoded private key file data.  A key in this format could be generated with the OpenSSL 3.0
        commands:

            `openssl genrsa -out private_pkcs8.pem 2048`
            `openssl rsa -in private_pkcs8.pem -outform DER -out private_pkcs8.der`

        Returns:
            result (bytes): Contents of a PKCS#1 PEM encoded file that contains the private key.
        """

        encoder = asn1.Encoder()
        encoder.start()
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(0, asn1.Numbers.Integer)  # Version 0 indicates the key is 2 prime RSA.  See http://mpqs.free.fr/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp_EMC_Corporation_Public-Key_Cryptography_Standards_(PKCS).pdf#page=56
        encoder.enter(asn1.Numbers.Sequence)
        encoder.write(PKCS1_OID, asn1.Numbers.ObjectIdentifier)
        encoder.write(None)  # Keys generated with OpenSSL have a NULL at this position per https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2
        encoder.leave()
        encoder.write(self.get_pkcs1_der_data(), asn1.Numbers.OctetString)
        encoder.leave()

        return encoder.output()

    def get_pkcs8_pem_data(self) -> bytes:
        """
        Gets PKCS#8 PEM encoded private key file data.  A key in this format could be generated with the OpenSSL 3.0
        command:

            `openssl genrsa -out private_pkcs8.pem 2048`

        Returns:
            result (bytes): Contents of a PKCS#8 PEM encoded file that contains the private key.
        """

        der_data = self.get_pkcs8_der_data()
        return _der_to_pem(der_data, 'PRIVATE KEY')

    def sign(self, message: typing.Union[bytes, str, typing.IO[typing.Union[bytes, str]]],
             hash_function: typing.Literal['SHA-1', 'SHA-256']) -> bytes:
        """
        Hashes the message and signs the hash digest with the private key.

        Args:
            message (typing.Union[bytes, str, typing.IO[typing.Union[bytes, str]]]): The message to sign.

            hash_function (typing.Literal['SHA-1', 'SHA-256']): The hash function to use.  Must exist as a key in
                `HASH_FUNCTIONS`.

        Returns:
            result (bytes): The encrypted signature.
        """

        msg_hash = compute_hash(message, hash_function)
        return self.sign_hash(msg_hash, hash_function)

    def sign_hash(self, hash_value: bytes, hash_function: typing.Literal['SHA-1', 'SHA-256']) -> bytes:
        """
        Signs a precomputed hash with the private key.

        Args:
            hash_value (bytes): The pre-computed hash to sign.

            hash_function (typing.Literal['SHA-1', 'SHA-256']): The hash function to use.  Must exist as a key in
                `HASH_FUNCTIONS`.

        Returns:
            result (bytes): The encrypted signature.
        """

        # Get the ASN.1 code for this hash function
        if hash_function not in HASH_FUNCTION_ASN1_CODES:
            raise ValueError('The hash function {hash_function} is unsupported'.format(hash_function=hash_function))

        asn1_code = HASH_FUNCTION_ASN1_CODES[hash_function]

        # Encrypt the hash with the private key
        signature_decrypted = asn1_code + hash_value
        modulus_len = _mprsa.count_bytes(self.n)
        signature_decrypted_padded = _pad_for_signing(signature_decrypted, modulus_len)
        signature_decrypted_padded_int = int(binascii.hexlify(signature_decrypted_padded), 16)
        signature_encrypted_int = self.blinded_encrypt(signature_decrypted_padded_int)
        signature_encrypted = _int_to_bytes(signature_encrypted_int, modulus_len)

        return signature_encrypted


def compute_hash(message: typing.Union[bytes, str, typing.IO[typing.Union[bytes, str]]],
                 hash_function: str) -> bytes:
    """
    Hashes the message and returns the hash digest.

    Args:
        message (typing.Union[bytes, str, typing.IO[typing.Union[bytes, str]]]): The message to hash.

        hash_function (str): The hash function to use.  Must exist as a key in `HASH_FUNCTIONS`.

    Returns:
        result (bytes): The hash digest of `message`.
    """

    if hash_function not in HASH_FUNCTIONS:
        raise ValueError('The hash function {hash_function} is unsupported'.format(hash_function=hash_function))

    method = HASH_FUNCTIONS[hash_function]
    hasher = method()

    if hasattr(message, 'read') and hasattr(message.read, '__call__'):
        read_size = 1024
        while True:
            chunk = message.read(read_size)
            chunk_len = len(chunk)

            if chunk_len == 0:
                break

            hasher.update(chunk)

            if chunk_len < read_size:
                break

    else:
        hasher.update(message)

    return hasher.digest()


def gen_keys(bit_cnt: int,
             e: int = DEFAULT_EXPONENT,
             accurate_modulus: bool = False,
             safe_primes: bool = False) -> typing.Tuple['PublicKey', 'PrivateKey']:
    """
    Generates public and private keys.  This can take a long time, depending on the key size.

    Args:
        bit_cnt (int): The number of bits required to store "n = p * q".  Said another way; the total number of combined
            bits in "p" and "q".  Both "p" and "q" will use `bit_cnt`/2 bits.  Must be in the range 24 - 8192 bits.
            It may not be possible to generate large keys on some devices due to memory constraints.

        e (int): The exponent for the key.  Defaults to `DEFAULT_EXPONENT`.  Only change this if you know what you're
            doing, as the exponent influences how difficult your private key can be cracked.

        accurate_modulus (bool): When `True`, "n" will be exactly `bit_cnt` bits in size.  However, this makes key
            generation much slower.  When False, "n" may have slightly fewer bits.  Defaults to `True`.

        safe_primes (bool): When `True`, the prime numbers generated for "p" and "q" will be safe primes
            (aka: Sophie Germain primes).  However, this makes key generation much slower.  Defaults to `True`.  The
            consensus among the cryptography community is that using safe primes produces only slightly stronger keys.
            See https://crypto.stackexchange.com/a/47733/105655.

    Returns:
        result (typing.Tuple[PublicKey, PrivateKey]): A two item tuple where the first item is a public key and the
            second item is a private key.
    """

    if bit_cnt < KEY_BIT_CNT_MIN or KEY_BIT_CNT_MAX < bit_cnt:
        raise ValueError('Key size must be in the range {key_bit_cnt_min} - {key_bit_cnt_max} bits.'.format(key_bit_cnt_min=KEY_BIT_CNT_MIN, key_bit_cnt_max=KEY_BIT_CNT_MAX))

    # Make sure that p and q aren't too close together to prevent easy factoring of n
    half_bit_cnt = bit_cnt // 2
    shift = half_bit_cnt // 16
    p_bit_cnt = half_bit_cnt + shift
    q_bit_cnt = half_bit_cnt - shift

    # Regenerate p and q until appropriate values are obtained
    while True:
        # Choose the initial prime numbers and modulus
        p = _mprsa.gen_prime(p_bit_cnt, safe_prime=safe_primes)
        q = _mprsa.gen_prime(q_bit_cnt, safe_prime=safe_primes)
        n = p * q

        # Keep generating primes for p and q until they match our requirements
        change_p = False
        while p == q or (accurate_modulus and bit_cnt != _mprsa.count_bits(n)):
            # Change p on one iteration and q on the other
            if change_p:
                p = _mprsa.gen_prime(p_bit_cnt, safe_prime=safe_primes)
            else:
                q = _mprsa.gen_prime(q_bit_cnt, safe_prime=safe_primes)

            # Update modulus
            n = p * q

            # Alternate which prime will be generated next loop
            change_p = not change_p

        # Make sure p > q.  See http://www.di-mgt.com.au/rsa_alg.html#crt
        p, q = max(p, q), min(p, q)

        try:
            phi_n = (p - 1) * (q - 1)
            d = _mprsa.invmod(e, phi_n)
            if (e * d) % phi_n != 1:
                continue

            break

        except ValueError:
            pass

    # Create the key objects
    n = p * q

    return PublicKey(n, e), PrivateKey(n, e, d, p, q)

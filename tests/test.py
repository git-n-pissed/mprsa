# -*- coding: utf-8 -*-

# This file is copyright (c) 2023 by the AUTHORS under the LICENSE
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import binascii
import mprsa

# The typing module is helpful during development, but isn't supported by MicroPython, so wrap import in try/except
try:
    import typing
except:
    pass


# If True, debug messages will be printed
DEBUG = False

# Define some key data.  All these keys have the same "guts", but are represented here in various formats and structures.
# Because these keys are publicly available, they are ONLY FOR TESTING.  Don't use them for anything but testing!
PRIVATE_PKCS1_DER = b'0\x82\x04\xa3\x02\x01\x00\x02\x82\x01\x01\x00\xaflJ\x13\xb7\xeeO\xf5U\xd8\xb9;\x81\xf0\xa4\x03\x8cNM\xc1WY\xba\x13\'\xa6F\xc7\\\xd6\x08\xff\x1d\xd6\x969\x99\x83\xf1\xfd\xd4\xd4\x80;T\x8d\xa6\x06!\x12r\xe8o1`\xb6o\x8fm\x9acy\x7f\r\xd7\xe0-\xf98\x06\xbfdj\xd7\xb11)\x8aG@\xbd\x85PV\r\xb0\xa4\xe9\x13\x8a\xf5\xda\x84^\xec\xc6\x9a\x95\xe1}\xc6,\xff\xd7K\xd8\xdf\x82\xa6\xd8\xecKs\xdc\x06<l\x95\xc0I\x85C:\xd22\xd5\xfb]\xcd\xa3\xdeC\x07\r_\xd4\xf0\x84ot\r}\xfcqT\x11\x18/;\xf5\xdb\x18\x1a}(\xda\n\x8f\xaec\xf0T\x80\xa6\xe6Ss\x8e\xe9mp\xfb\xcc\xfc\xd7\xbb~\x9f]f\xb9\xfa\x1b\x08zr\xc7\x97\xfd\xc7\xb3\xba\xea\x01\x1cO\xc6\x13\xe8[X\x10\xf4\x98U\xbcO\xa9{\xde\x05\x96\x95\x01G\xb4\xb8\xa9ow\xbc\x99\x13\x96@\x7f"\x87,\xdaS\xf3\x96\xb2\xff\'\xc0\xe8\xee\x01\xf6\x1c,\x94\xcd\x84\x97\x98\x1e\xdcR\x8b\xe7x\xd5\x15\x02\x03\x01\x00\x01\x02\x82\x01\x00*\x03\xf9\x0b\x17\x80\xf5\xf88\x1f@ [[8a\\+\xce\x0eJ~de\x9d\x97\xc2\xf8\x91\x88\xf7\x1f)u\xa1\xc5\xfay\xa2\x8em\xf9\x16\x9c\x7f@,\xfdgR\xec\xa04\xaf\xa2/\x17\xf1\xc5\xa9\xd6|\xfd\\"\xb2 8\xc2}E>\x87#\x91\x9eI\x89\x83\xce\xe3\x05\xa8\xeb\xef{\xf9G\x94\xe5q\xc4\xacs2\xe9O\x91\xa9\xf0.\xb4\xcc\xf33H\xa6\xa1\xfb\x95\xd5\xa4\xad\xc3\x8b_\xd2\x0f\x1c\xfe\xce\xf2\xff\x05\xe4\xe4\xa0\xff\\\xd4-u\xa2*!-\xe5\x8a\x92\x05\x86\xf5KI\xd3\xecPU<*\x18\x8d)O}A\xb1\x8d\x0b\xba\xc5\xbe\xb8\xddSH\xdbV\x02\x16>\xe1{}\xf4\xf7sF\x91\xeb\x1e\xbcc\xc6\xfc\x14\xe2\xe2\x0f^4\x9f\xb8+\xbeYR\x92Y\xd4\x89\xad\x92\xcd\xcbB\xe2hYO\xffU}\xaf\x1cR*>81\x9eix\x8f\xaac\xecX\xa2v\x91C\xd29$W\xc8n\xbd\x13\x97\xde9v\xf8\xb9"\xb8\x9cE\xa6\xeeDW09\x02\x81\x81\x00\xe9\xfd\xfc\xa1O\x7f@\xb8\xeb\x9a0q\x0b\xca\'V\xf2\xe9\xae\x8d\x15\xfc\x1e\xe3\xdc\xf0\xbe \x02r\x9f\x1c0\xaf\x87Vo\x93\xfa\x80\xe5M\xc7\xe8T\xc4\t\x83\xc989i\xf9\xa1%u\xe3\xf5M\x19\x1f\x98~p\xb6\r\xe5\xdfm\\uYB\xc9\xe8\xcc\xcavD1\xac\'\x1cGf\xa8\r\xfe\x11\xbf\x11\xa5\x9e\xfc\x1dL\xddt[\xfbQU\xfc\xf8\xebE\x95\xce5\xdbC|\x900\xe6\xe6m\'w\x94\xc7\xdbUR;[\xf4\x1d\x02\x81\x81\x00\xbf\xec\x16^\xcbmw\x0fZ\x01\x17\x10\xa8_KR[i,\xc8\x87\x1d\x86\xacb;\xbf3h?k\x1c\x96C\xa4\xb6\xd05e\xe2\xb6mQ\x19\xdbQ(\xe7\xea\x9aU\xf5\x9a\xfe\xd2\x9b\xa1%l\x10\x19\xba\x8c\x9b \xc4^U|\x9b%y\xf8\xa3\x0c\xd57\xe6\x06\xb7\xdf\xc1\xcb\x99.\xef\x1b\'dJd7qC\xe1\xd4(e\xac\xb3\x13j\xcd\xdb\xab\x98\\H\x88H\xd8\xfe\x186\x92\xf6v\xb4\x9b\xa7\x07\xc9G,\x0e\xd5#Y\x02\x81\x80-\xf7\xfa\xc8\x8a\x00\x9a\xebyE\xaa\\\x9b\x0fT\xd9-\x11\xa1|\x10$\x9e\xc0\xef\'\xd0\x82#X\xf7O\'udf#\xb7s\x90\x1c\xfcA\xd8\xaf\xc6o\x84\x17d\xd7J\xad\x82\xee\x04\x12\x0b\x9f\xe0\xde\xa7+\xb7\xe2\xdc*\x1b\xd1\xb5GL\x88\xe5w\xb9\xbb\xd0\xae\'\x00\x06\x12\xf5(\x02\xbd\xf4\xfa\xf1\x89z\xfb\x17\xd6}\xc2G\xd8\xc6/\xbdo\xdcK\x049\xa0\xf0M\xaa\x1do\x8a[\xe2J\xf1d\xf9\xb2\xa5\xb1F]h\xfc5\x02\x81\x81\x00\x97\xdcf\x83\x11\xb2\x87@\x05v\xd1Zc\xf0+xzNI\x9aN\x97\x85e\xc7\xc1\x00\xf4\xdbk;\x04\xfe\xbd}\x8b\x0eK\x02X\x97\x02\xfe\xe6W\xcc\xebr?\x07j7\x122\xcaQL\xfc\x80zh\xf1\\\xaa\xaf\r\xd2\x9b\x10"\xefO\x88\xf6\xf3\x83\x8f\\\x9b:Iz]\xf0\xd2\xdbn\x00\x08rx\xc4\n\x02\xad\xa1\xa3ixr\xa6M\x9f\xa0O2\x1a\xebe\xb3F\xc8 >\xa6\xa1\x10\xa2\xae{GD\xf3\xe5\x1f\xc3t\xd9\x02\x81\x80\x02\x9c\xee\xf4\xae\xbcI\xe6\x96\x19Lf\xde[\x8a\x90\x9c\x957m)\xb6\x04.\xd6\xef\xb2Y6x\xd4\xaa\xc9\xad\xe7\xdc\x13\xb7\xb7\xb1V\x8f\'\xefO\x9e\x99\'\x95\x17\xb1-\x13b\xda\xb9]\xc5V\xaf|\xb0w\x0b+\xe6\\\x1b\xffi`\xb4k\xf8\xd0\xd5_(m\x8eZ\xa4\xd8\xe2\xcd\xf8\xd8p\xa8\x1a\xd5\x89\xf0\xa7G\xbf\xb6`\x0ei.I\x1f\xdf&F\xbc\xb2\xa8\xd3W7\x96\xbf<\x8a\x0b>\xe4K\x1f\x8a\xd1\x0b\xc8<z\xa3'
PRIVATE_PKCS1_PEM = b'-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAr2xKE7fuT/VV2Lk7gfCkA4xOTcFXWboTJ6ZGx1zWCP8d1pY5\nmYPx/dTUgDtUjaYGIRJy6G8xYLZvj22aY3l/DdfgLfk4Br9katexMSmKR0C9hVBW\nDbCk6ROK9dqEXuzGmpXhfcYs/9dL2N+CptjsS3PcBjxslcBJhUM60jLV+13No95D\nBw1f1PCEb3QNffxxVBEYLzv12xgafSjaCo+uY/BUgKbmU3OO6W1w+8z817t+n11m\nufobCHpyx5f9x7O66gEcT8YT6FtYEPSYVbxPqXveBZaVAUe0uKlvd7yZE5ZAfyKH\nLNpT85ay/yfA6O4B9hwslM2El5ge3FKL53jVFQIDAQABAoIBACoD+QsXgPX4OB9A\nIFtbOGFcK84OSn5kZZ2XwviRiPcfKXWhxfp5oo5t+Racf0As/WdS7KA0r6IvF/HF\nqdZ8/VwisiA4wn1FPocjkZ5JiYPO4wWo6+97+UeU5XHErHMy6U+RqfAutMzzM0im\nofuV1aStw4tf0g8c/s7y/wXk5KD/XNQtdaIqIS3lipIFhvVLSdPsUFU8KhiNKU99\nQbGNC7rFvrjdU0jbVgIWPuF7ffT3c0aR6x68Y8b8FOLiD140n7grvllSklnUia2S\nzctC4mhZT/9Vfa8cUio+ODGeaXiPqmPsWKJ2kUPSOSRXyG69E5feOXb4uSK4nEWm\n7kRXMDkCgYEA6f38oU9/QLjrmjBxC8onVvLpro0V/B7j3PC+IAJynxwwr4dWb5P6\ngOVNx+hUxAmDyTg5afmhJXXj9U0ZH5h+cLYN5d9tXHVZQsnozMp2RDGsJxxHZqgN\n/hG/EaWe/B1M3XRb+1FV/PjrRZXONdtDfJAw5uZtJ3eUx9tVUjtb9B0CgYEAv+wW\nXsttdw9aARcQqF9LUltpLMiHHYasYju/M2g/axyWQ6S20DVl4rZtURnbUSjn6ppV\n9Zr+0puhJWwQGbqMmyDEXlV8myV5+KMM1TfmBrffwcuZLu8bJ2RKZDdxQ+HUKGWs\nsxNqzdurmFxIiEjY/hg2kvZ2tJunB8lHLA7VI1kCgYAt9/rIigCa63lFqlybD1TZ\nLRGhfBAknsDvJ9CCI1j3Tyd1ZGYjt3OQHPxB2K/Gb4QXZNdKrYLuBBILn+Depyu3\n4twqG9G1R0yI5Xe5u9CuJwAGEvUoAr30+vGJevsX1n3CR9jGL71v3EsEOaDwTaod\nb4pb4krxZPmypbFGXWj8NQKBgQCX3GaDEbKHQAV20Vpj8Ct4ek5Jmk6XhWXHwQD0\n22s7BP69fYsOSwJYlwL+5lfM63I/B2o3EjLKUUz8gHpo8Vyqrw3SmxAi70+I9vOD\nj1ybOkl6XfDS224ACHJ4xAoCraGjaXhypk2foE8yGutls0bIID6moRCirntHRPPl\nH8N02QKBgAKc7vSuvEnmlhlMZt5bipCclTdtKbYELtbvslk2eNSqya3n3BO3t7FW\njyfvT56ZJ5UXsS0TYtq5XcVWr3ywdwsr5lwb/2lgtGv40NVfKG2OWqTY4s342HCo\nGtWJ8KdHv7ZgDmkuSR/fJka8sqjTVzeWvzyKCz7kSx+K0QvIPHqj\n-----END RSA PRIVATE KEY-----\n'
PRIVATE_PKCS8_DER = b'0\x82\x04\xbd\x02\x01\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x04\x82\x04\xa70\x82\x04\xa3\x02\x01\x00\x02\x82\x01\x01\x00\xaflJ\x13\xb7\xeeO\xf5U\xd8\xb9;\x81\xf0\xa4\x03\x8cNM\xc1WY\xba\x13\'\xa6F\xc7\\\xd6\x08\xff\x1d\xd6\x969\x99\x83\xf1\xfd\xd4\xd4\x80;T\x8d\xa6\x06!\x12r\xe8o1`\xb6o\x8fm\x9acy\x7f\r\xd7\xe0-\xf98\x06\xbfdj\xd7\xb11)\x8aG@\xbd\x85PV\r\xb0\xa4\xe9\x13\x8a\xf5\xda\x84^\xec\xc6\x9a\x95\xe1}\xc6,\xff\xd7K\xd8\xdf\x82\xa6\xd8\xecKs\xdc\x06<l\x95\xc0I\x85C:\xd22\xd5\xfb]\xcd\xa3\xdeC\x07\r_\xd4\xf0\x84ot\r}\xfcqT\x11\x18/;\xf5\xdb\x18\x1a}(\xda\n\x8f\xaec\xf0T\x80\xa6\xe6Ss\x8e\xe9mp\xfb\xcc\xfc\xd7\xbb~\x9f]f\xb9\xfa\x1b\x08zr\xc7\x97\xfd\xc7\xb3\xba\xea\x01\x1cO\xc6\x13\xe8[X\x10\xf4\x98U\xbcO\xa9{\xde\x05\x96\x95\x01G\xb4\xb8\xa9ow\xbc\x99\x13\x96@\x7f"\x87,\xdaS\xf3\x96\xb2\xff\'\xc0\xe8\xee\x01\xf6\x1c,\x94\xcd\x84\x97\x98\x1e\xdcR\x8b\xe7x\xd5\x15\x02\x03\x01\x00\x01\x02\x82\x01\x00*\x03\xf9\x0b\x17\x80\xf5\xf88\x1f@ [[8a\\+\xce\x0eJ~de\x9d\x97\xc2\xf8\x91\x88\xf7\x1f)u\xa1\xc5\xfay\xa2\x8em\xf9\x16\x9c\x7f@,\xfdgR\xec\xa04\xaf\xa2/\x17\xf1\xc5\xa9\xd6|\xfd\\"\xb2 8\xc2}E>\x87#\x91\x9eI\x89\x83\xce\xe3\x05\xa8\xeb\xef{\xf9G\x94\xe5q\xc4\xacs2\xe9O\x91\xa9\xf0.\xb4\xcc\xf33H\xa6\xa1\xfb\x95\xd5\xa4\xad\xc3\x8b_\xd2\x0f\x1c\xfe\xce\xf2\xff\x05\xe4\xe4\xa0\xff\\\xd4-u\xa2*!-\xe5\x8a\x92\x05\x86\xf5KI\xd3\xecPU<*\x18\x8d)O}A\xb1\x8d\x0b\xba\xc5\xbe\xb8\xddSH\xdbV\x02\x16>\xe1{}\xf4\xf7sF\x91\xeb\x1e\xbcc\xc6\xfc\x14\xe2\xe2\x0f^4\x9f\xb8+\xbeYR\x92Y\xd4\x89\xad\x92\xcd\xcbB\xe2hYO\xffU}\xaf\x1cR*>81\x9eix\x8f\xaac\xecX\xa2v\x91C\xd29$W\xc8n\xbd\x13\x97\xde9v\xf8\xb9"\xb8\x9cE\xa6\xeeDW09\x02\x81\x81\x00\xe9\xfd\xfc\xa1O\x7f@\xb8\xeb\x9a0q\x0b\xca\'V\xf2\xe9\xae\x8d\x15\xfc\x1e\xe3\xdc\xf0\xbe \x02r\x9f\x1c0\xaf\x87Vo\x93\xfa\x80\xe5M\xc7\xe8T\xc4\t\x83\xc989i\xf9\xa1%u\xe3\xf5M\x19\x1f\x98~p\xb6\r\xe5\xdfm\\uYB\xc9\xe8\xcc\xcavD1\xac\'\x1cGf\xa8\r\xfe\x11\xbf\x11\xa5\x9e\xfc\x1dL\xddt[\xfbQU\xfc\xf8\xebE\x95\xce5\xdbC|\x900\xe6\xe6m\'w\x94\xc7\xdbUR;[\xf4\x1d\x02\x81\x81\x00\xbf\xec\x16^\xcbmw\x0fZ\x01\x17\x10\xa8_KR[i,\xc8\x87\x1d\x86\xacb;\xbf3h?k\x1c\x96C\xa4\xb6\xd05e\xe2\xb6mQ\x19\xdbQ(\xe7\xea\x9aU\xf5\x9a\xfe\xd2\x9b\xa1%l\x10\x19\xba\x8c\x9b \xc4^U|\x9b%y\xf8\xa3\x0c\xd57\xe6\x06\xb7\xdf\xc1\xcb\x99.\xef\x1b\'dJd7qC\xe1\xd4(e\xac\xb3\x13j\xcd\xdb\xab\x98\\H\x88H\xd8\xfe\x186\x92\xf6v\xb4\x9b\xa7\x07\xc9G,\x0e\xd5#Y\x02\x81\x80-\xf7\xfa\xc8\x8a\x00\x9a\xebyE\xaa\\\x9b\x0fT\xd9-\x11\xa1|\x10$\x9e\xc0\xef\'\xd0\x82#X\xf7O\'udf#\xb7s\x90\x1c\xfcA\xd8\xaf\xc6o\x84\x17d\xd7J\xad\x82\xee\x04\x12\x0b\x9f\xe0\xde\xa7+\xb7\xe2\xdc*\x1b\xd1\xb5GL\x88\xe5w\xb9\xbb\xd0\xae\'\x00\x06\x12\xf5(\x02\xbd\xf4\xfa\xf1\x89z\xfb\x17\xd6}\xc2G\xd8\xc6/\xbdo\xdcK\x049\xa0\xf0M\xaa\x1do\x8a[\xe2J\xf1d\xf9\xb2\xa5\xb1F]h\xfc5\x02\x81\x81\x00\x97\xdcf\x83\x11\xb2\x87@\x05v\xd1Zc\xf0+xzNI\x9aN\x97\x85e\xc7\xc1\x00\xf4\xdbk;\x04\xfe\xbd}\x8b\x0eK\x02X\x97\x02\xfe\xe6W\xcc\xebr?\x07j7\x122\xcaQL\xfc\x80zh\xf1\\\xaa\xaf\r\xd2\x9b\x10"\xefO\x88\xf6\xf3\x83\x8f\\\x9b:Iz]\xf0\xd2\xdbn\x00\x08rx\xc4\n\x02\xad\xa1\xa3ixr\xa6M\x9f\xa0O2\x1a\xebe\xb3F\xc8 >\xa6\xa1\x10\xa2\xae{GD\xf3\xe5\x1f\xc3t\xd9\x02\x81\x80\x02\x9c\xee\xf4\xae\xbcI\xe6\x96\x19Lf\xde[\x8a\x90\x9c\x957m)\xb6\x04.\xd6\xef\xb2Y6x\xd4\xaa\xc9\xad\xe7\xdc\x13\xb7\xb7\xb1V\x8f\'\xefO\x9e\x99\'\x95\x17\xb1-\x13b\xda\xb9]\xc5V\xaf|\xb0w\x0b+\xe6\\\x1b\xffi`\xb4k\xf8\xd0\xd5_(m\x8eZ\xa4\xd8\xe2\xcd\xf8\xd8p\xa8\x1a\xd5\x89\xf0\xa7G\xbf\xb6`\x0ei.I\x1f\xdf&F\xbc\xb2\xa8\xd3W7\x96\xbf<\x8a\x0b>\xe4K\x1f\x8a\xd1\x0b\xc8<z\xa3'
PRIVATE_PKCS8_PEM = b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvbEoTt+5P9VXY\nuTuB8KQDjE5NwVdZuhMnpkbHXNYI/x3WljmZg/H91NSAO1SNpgYhEnLobzFgtm+P\nbZpjeX8N1+At+TgGv2Rq17ExKYpHQL2FUFYNsKTpE4r12oRe7MaaleF9xiz/10vY\n34Km2OxLc9wGPGyVwEmFQzrSMtX7Xc2j3kMHDV/U8IRvdA19/HFUERgvO/XbGBp9\nKNoKj65j8FSApuZTc47pbXD7zPzXu36fXWa5+hsIenLHl/3Hs7rqARxPxhPoW1gQ\n9JhVvE+pe94FlpUBR7S4qW93vJkTlkB/Iocs2lPzlrL/J8Do7gH2HCyUzYSXmB7c\nUovneNUVAgMBAAECggEAKgP5CxeA9fg4H0AgW1s4YVwrzg5KfmRlnZfC+JGI9x8p\ndaHF+nmijm35Fpx/QCz9Z1LsoDSvoi8X8cWp1nz9XCKyIDjCfUU+hyORnkmJg87j\nBajr73v5R5TlccSsczLpT5Gp8C60zPMzSKah+5XVpK3Di1/SDxz+zvL/BeTkoP9c\n1C11oiohLeWKkgWG9UtJ0+xQVTwqGI0pT31BsY0LusW+uN1TSNtWAhY+4Xt99Pdz\nRpHrHrxjxvwU4uIPXjSfuCu+WVKSWdSJrZLNy0LiaFlP/1V9rxxSKj44MZ5peI+q\nY+xYonaRQ9I5JFfIbr0Tl945dvi5IricRabuRFcwOQKBgQDp/fyhT39AuOuaMHEL\nyidW8umujRX8HuPc8L4gAnKfHDCvh1Zvk/qA5U3H6FTECYPJODlp+aEldeP1TRkf\nmH5wtg3l321cdVlCyejMynZEMawnHEdmqA3+Eb8RpZ78HUzddFv7UVX8+OtFlc41\n20N8kDDm5m0nd5TH21VSO1v0HQKBgQC/7BZey213D1oBFxCoX0tSW2ksyIcdhqxi\nO78zaD9rHJZDpLbQNWXitm1RGdtRKOfqmlX1mv7Sm6ElbBAZuoybIMReVXybJXn4\nowzVN+YGt9/By5ku7xsnZEpkN3FD4dQoZayzE2rN26uYXEiISNj+GDaS9na0m6cH\nyUcsDtUjWQKBgC33+siKAJrreUWqXJsPVNktEaF8ECSewO8n0IIjWPdPJ3VkZiO3\nc5Ac/EHYr8ZvhBdk10qtgu4EEguf4N6nK7fi3Cob0bVHTIjld7m70K4nAAYS9SgC\nvfT68Yl6+xfWfcJH2MYvvW/cSwQ5oPBNqh1vilviSvFk+bKlsUZdaPw1AoGBAJfc\nZoMRsodABXbRWmPwK3h6TkmaTpeFZcfBAPTbazsE/r19iw5LAliXAv7mV8zrcj8H\najcSMspRTPyAemjxXKqvDdKbECLvT4j284OPXJs6SXpd8NLbbgAIcnjECgKtoaNp\neHKmTZ+gTzIa62WzRsggPqahEKKue0dE8+Ufw3TZAoGAApzu9K68SeaWGUxm3luK\nkJyVN20ptgQu1u+yWTZ41KrJrefcE7e3sVaPJ+9PnpknlRexLRNi2rldxVavfLB3\nCyvmXBv/aWC0a/jQ1V8obY5apNjizfjYcKga1Ynwp0e/tmAOaS5JH98mRryyqNNX\nN5a/PIoLPuRLH4rRC8g8eqM=\n-----END PRIVATE KEY-----\n'
PUBLIC_PKCS1_DER = b'0\x82\x01\n\x02\x82\x01\x01\x00\xaflJ\x13\xb7\xeeO\xf5U\xd8\xb9;\x81\xf0\xa4\x03\x8cNM\xc1WY\xba\x13\'\xa6F\xc7\\\xd6\x08\xff\x1d\xd6\x969\x99\x83\xf1\xfd\xd4\xd4\x80;T\x8d\xa6\x06!\x12r\xe8o1`\xb6o\x8fm\x9acy\x7f\r\xd7\xe0-\xf98\x06\xbfdj\xd7\xb11)\x8aG@\xbd\x85PV\r\xb0\xa4\xe9\x13\x8a\xf5\xda\x84^\xec\xc6\x9a\x95\xe1}\xc6,\xff\xd7K\xd8\xdf\x82\xa6\xd8\xecKs\xdc\x06<l\x95\xc0I\x85C:\xd22\xd5\xfb]\xcd\xa3\xdeC\x07\r_\xd4\xf0\x84ot\r}\xfcqT\x11\x18/;\xf5\xdb\x18\x1a}(\xda\n\x8f\xaec\xf0T\x80\xa6\xe6Ss\x8e\xe9mp\xfb\xcc\xfc\xd7\xbb~\x9f]f\xb9\xfa\x1b\x08zr\xc7\x97\xfd\xc7\xb3\xba\xea\x01\x1cO\xc6\x13\xe8[X\x10\xf4\x98U\xbcO\xa9{\xde\x05\x96\x95\x01G\xb4\xb8\xa9ow\xbc\x99\x13\x96@\x7f"\x87,\xdaS\xf3\x96\xb2\xff\'\xc0\xe8\xee\x01\xf6\x1c,\x94\xcd\x84\x97\x98\x1e\xdcR\x8b\xe7x\xd5\x15\x02\x03\x01\x00\x01'
PUBLIC_PKCS1_PEM = b'-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAr2xKE7fuT/VV2Lk7gfCkA4xOTcFXWboTJ6ZGx1zWCP8d1pY5mYPx\n/dTUgDtUjaYGIRJy6G8xYLZvj22aY3l/DdfgLfk4Br9katexMSmKR0C9hVBWDbCk\n6ROK9dqEXuzGmpXhfcYs/9dL2N+CptjsS3PcBjxslcBJhUM60jLV+13No95DBw1f\n1PCEb3QNffxxVBEYLzv12xgafSjaCo+uY/BUgKbmU3OO6W1w+8z817t+n11mufob\nCHpyx5f9x7O66gEcT8YT6FtYEPSYVbxPqXveBZaVAUe0uKlvd7yZE5ZAfyKHLNpT\n85ay/yfA6O4B9hwslM2El5ge3FKL53jVFQIDAQAB\n-----END RSA PUBLIC KEY-----\n'
PUBLIC_X509_SPKI_DER = b'0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xaflJ\x13\xb7\xeeO\xf5U\xd8\xb9;\x81\xf0\xa4\x03\x8cNM\xc1WY\xba\x13\'\xa6F\xc7\\\xd6\x08\xff\x1d\xd6\x969\x99\x83\xf1\xfd\xd4\xd4\x80;T\x8d\xa6\x06!\x12r\xe8o1`\xb6o\x8fm\x9acy\x7f\r\xd7\xe0-\xf98\x06\xbfdj\xd7\xb11)\x8aG@\xbd\x85PV\r\xb0\xa4\xe9\x13\x8a\xf5\xda\x84^\xec\xc6\x9a\x95\xe1}\xc6,\xff\xd7K\xd8\xdf\x82\xa6\xd8\xecKs\xdc\x06<l\x95\xc0I\x85C:\xd22\xd5\xfb]\xcd\xa3\xdeC\x07\r_\xd4\xf0\x84ot\r}\xfcqT\x11\x18/;\xf5\xdb\x18\x1a}(\xda\n\x8f\xaec\xf0T\x80\xa6\xe6Ss\x8e\xe9mp\xfb\xcc\xfc\xd7\xbb~\x9f]f\xb9\xfa\x1b\x08zr\xc7\x97\xfd\xc7\xb3\xba\xea\x01\x1cO\xc6\x13\xe8[X\x10\xf4\x98U\xbcO\xa9{\xde\x05\x96\x95\x01G\xb4\xb8\xa9ow\xbc\x99\x13\x96@\x7f"\x87,\xdaS\xf3\x96\xb2\xff\'\xc0\xe8\xee\x01\xf6\x1c,\x94\xcd\x84\x97\x98\x1e\xdcR\x8b\xe7x\xd5\x15\x02\x03\x01\x00\x01'
PUBLIC_X509_SPKI_PEM = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2xKE7fuT/VV2Lk7gfCk\nA4xOTcFXWboTJ6ZGx1zWCP8d1pY5mYPx/dTUgDtUjaYGIRJy6G8xYLZvj22aY3l/\nDdfgLfk4Br9katexMSmKR0C9hVBWDbCk6ROK9dqEXuzGmpXhfcYs/9dL2N+Cptjs\nS3PcBjxslcBJhUM60jLV+13No95DBw1f1PCEb3QNffxxVBEYLzv12xgafSjaCo+u\nY/BUgKbmU3OO6W1w+8z817t+n11mufobCHpyx5f9x7O66gEcT8YT6FtYEPSYVbxP\nqXveBZaVAUe0uKlvd7yZE5ZAfyKHLNpT85ay/yfA6O4B9hwslM2El5ge3FKL53jV\nFQIDAQAB\n-----END PUBLIC KEY-----\n'

# 277 bytes of Lorem Ipsum
LOREM_IPSUM = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Facilisis leo vel fringilla est ullamcorper eget. Imperdiet nulla malesuada pellentesque elit. Dui nunc mattis enim ut. Mi in nulla posuere sollicitudin.'

# Hashes of the above snippet of Lorem Ipsum
LOREM_IPSUM_HASHES = {
    'SHA-1': b'258eae8bb8d0a0993ab7e4c76435cab169ee4acc',
    'SHA-256': b'92e4077e45c9a8c1a9f54505c4431bcab8130276b7bc2f1ff538d48683657877'
}


def debug_print(s: str):
    """
    Print messages when `DEBUG` is set to `True`.

    Args:
        s (str): The string to print.
    """

    if DEBUG:
        print(s)


def test_key_importing_and_exporting():
    """
    Test key importing and exporting.
    """

    debug_print('Loading PRIVATE_PKCS1_DER')
    private_pkcs1_der_key = mprsa.PrivateKey.load_pkcs1_der_data(PRIVATE_PKCS1_DER)
    debug_print('Loading PRIVATE_PKCS1_PEM')
    private_pkcs1_pem_key = mprsa.PrivateKey.load_pkcs1_pem_data(PRIVATE_PKCS1_PEM)
    debug_print('Loading PRIVATE_PKCS8_DER')
    private_pkcs8_der_key = mprsa.PrivateKey.load_pkcs8_der_data(PRIVATE_PKCS8_DER)
    debug_print('Loading PRIVATE_PKCS8_PEM')
    private_pkcs8_pem_key = mprsa.PrivateKey.load_pkcs8_pem_data(PRIVATE_PKCS8_PEM)
    debug_print('Loading PUBLIC_PKCS1_DER')
    public_pkcs1_der_key = mprsa.PublicKey.load_pkcs1_der_data(PUBLIC_PKCS1_DER)
    debug_print('Loading PUBLIC_PKCS1_PEM')
    public_pkcs1_pem_key = mprsa.PublicKey.load_pkcs1_pem_data(PUBLIC_PKCS1_PEM)
    debug_print('Loading PUBLIC_X509_SPKI_DER')
    public_x509_spki_der_key = mprsa.PublicKey.load_x509_spki_der_data(PUBLIC_X509_SPKI_DER)
    debug_print('Loading PUBLIC_X509_SPKI_PEM')
    public_x509_spki_pem_key = mprsa.PublicKey.load_x509_spki_pem_data(PUBLIC_X509_SPKI_PEM)

    debug_print('Verifying all the PrivateKey objects are identical')
    assert private_pkcs1_der_key == private_pkcs1_pem_key and private_pkcs1_pem_key == private_pkcs8_der_key and private_pkcs8_der_key == private_pkcs8_pem_key, 'Test failure: Private keys do not match'

    debug_print('Verifying all the PublicKey objects are identical')
    assert public_pkcs1_der_key == public_pkcs1_pem_key and public_pkcs1_pem_key == public_x509_spki_der_key and public_x509_spki_der_key == public_x509_spki_pem_key, 'Test failure: Public keys do not match'

    debug_print('Verifying PrivateKey.get_pkcs1_der_data')
    assert private_pkcs1_der_key.get_pkcs1_der_data() == PRIVATE_PKCS1_DER, 'Test failure: The function "PrivateKey.get_pkcs1_der_data" did not return the expected data'
    debug_print('Verifying PrivateKey.get_pkcs1_pem_data')
    assert private_pkcs1_der_key.get_pkcs1_pem_data() == PRIVATE_PKCS1_PEM, 'Test failure: The function "PrivateKey.get_pkcs1_pem_data" did not return the expected data'
    debug_print('Verifying PrivateKey.get_pkcs8_der_data')
    assert private_pkcs1_der_key.get_pkcs8_der_data() == PRIVATE_PKCS8_DER, 'Test failure: The function "PrivateKey.get_pkcs8_der_data" did not return the expected data'
    debug_print('Verifying PrivateKey.get_pkcs8_pem_data')
    assert private_pkcs1_der_key.get_pkcs8_pem_data() == PRIVATE_PKCS8_PEM, 'Test failure: The function "PrivateKey.get_pkcs8_pem_data" did not return the expected data'
    debug_print('Verifying PublicKey.get_pkcs1_der_data')
    assert public_pkcs1_der_key.get_pkcs1_der_data() == PUBLIC_PKCS1_DER, 'Test failure: The function "PublicKey.get_pkcs1_der_data" did not return the expected data'
    debug_print('Verifying PublicKey.get_pkcs1_pem_data')
    assert public_pkcs1_der_key.get_pkcs1_pem_data() == PUBLIC_PKCS1_PEM, 'Test failure: The function "PublicKey.get_pkcs1_pem_data" did not return the expected data'
    debug_print('Verifying PublicKey.get_x509_spki_der_data')
    assert public_pkcs1_der_key.get_x509_spki_der_data() == PUBLIC_X509_SPKI_DER, 'Test failure: The function "PublicKey.get_x509_spki_der_data" did not return the expected data'
    debug_print('Verifying PublicKey.get_x509_spki_pem_data')
    assert public_pkcs1_der_key.get_x509_spki_pem_data() == PUBLIC_X509_SPKI_PEM, 'Test failure: The function "PublicKey.get_x509_spki_pem_data" did not return the expected data'


def test_key_generation(bit_cnt: int, accurate_modulus: bool, safe_primes: bool) -> typing.Tuple[mprsa.PublicKey, mprsa.PrivateKey]:
    """
    Test key generation.

    Args:
        bit_cnt (int): The size to use during key generation.

        accurate_modulus (bool): A boolean used to determine if a modulus "n" must match the exact number of bits
            specified during key generation.

        safe_primes (bool): A boolean used to determine if prime numbers "p" and "q" must be safe primes during key
            generation.

    Returns:
        result (typing.Tuple[mprsa.PublicKey, mprsa.PrivateKey]): A two item tuple where the first item is an instance
            of `mprsa.PublicKey` and the second item is an instance of `mprsa.PrivateKey`.
    """

    debug_print('Generate a new {bit_cnt} bit key pair.  Be patient, this may take a while.'.format(bit_cnt=bit_cnt))
    return mprsa.gen_keys(bit_cnt, accurate_modulus=accurate_modulus, safe_primes=safe_primes)


def test_encryption_and_decryption(public_key: mprsa.PublicKey, private_key: mprsa.PrivateKey):
    """
    Test encryption and decryption.

    Args:
        public_key (mprsa.PublicKey): An instance of `mprsa.PublicKey`.

        private_key (mprsa.PrivateKey): An instance of `mprsa.PrivateKey`.
    """

    byte_cnt = 2048 // 8 - 11

    debug_print('Encrypting {byte_cnt} bytes (the max that can be encrypted by a 2048 bit key) of Lorem Ipsum'.format(byte_cnt=byte_cnt))
    encrypted_msg = public_key.encrypt(LOREM_IPSUM[0: byte_cnt])

    debug_print('Decrypting previously encrypted message')
    decrypted_msg = private_key.decrypt(encrypted_msg)

    debug_print('Verifying encryption/decryption were successful')
    assert decrypted_msg[0], 'Test failure: Message decryption was unsuccessful.  This could result from a problem with encryption, decryption, or both.'
    assert decrypted_msg[1] == LOREM_IPSUM[0: byte_cnt], 'Test failure: Decrypted message does not match original input.  This could result from a problem with encryption, decryption, or both.'


def test_signing_and_verification(public_key: mprsa.PublicKey, private_key: mprsa.PrivateKey, hashing_algorithm: str):
    """
    Test signing and verification.

    Args:
        public_key (mprsa.PublicKey): An instance of `mprsa.PublicKey`.

        private_key (mprsa.PrivateKey): An instance of `mprsa.PrivateKey`.

        hashing_algorithm (str): The hashing algorithm to use.  Current options are "SHA-1" and "SHA-256".
    """

    debug_print('Signing {lorem_ipsum_len} bytes of Lorem Ipsum using {hashing_algorithm} for hashing'.format(lorem_ipsum_len=len(LOREM_IPSUM), hashing_algorithm=hashing_algorithm))
    signature_encrypted = private_key.sign(LOREM_IPSUM, hashing_algorithm)

    debug_print('Verifying (without pre-computed hash) the signature of the previously signed message')
    verification_result = public_key.verify(LOREM_IPSUM, signature_encrypted)

    debug_print('Verifying signing/verification were successful')
    assert verification_result[0], 'Test failure: Signature verification (without pre-computed hash) with {hashing_algorithm} hashing was unsuccessful.  This could result from a problem with signing, verification, or both.'.format(hashing_algorithm=hashing_algorithm)
    assert verification_result[1] == hashing_algorithm, 'Test failure: Signature verification hashing function does not match original input of {hashing_algorithm}.  This could result from a problem with signing, verification, or both.'.format(hashing_algorithm=hashing_algorithm)

    debug_print('Pre-computing {hashing_algorithm} hash on {lorem_ipsum_len} bytes of Lorem Ipsum'.format(hashing_algorithm=hashing_algorithm, lorem_ipsum_len=len(LOREM_IPSUM)))
    lorem_ipsum_hash = mprsa.compute_hash(LOREM_IPSUM, hashing_algorithm)

    debug_print('Verifying (with pre-computed hash) the signature of the previously signed message')
    verification_result = public_key.verify_hash(lorem_ipsum_hash, signature_encrypted)

    debug_print('Verifying signing/verification were successful')
    assert verification_result[0], 'Test failure: Signature verification (with pre-computed hash) with {hashing_algorithm} hashing was unsuccessful.  This could result from a problem with signing, verification, or both.'.format(hashing_algorithm=hashing_algorithm)
    assert verification_result[1] == hashing_algorithm, 'Test failure: Signature verification hashing function does not match original input of {hashing_algorithm}.  This could result from a problem with signing, verification, or both.'.format(hashing_algorithm=hashing_algorithm)

    debug_print('Verifying the {hashing_algorithm} hashing function used by signing/verification produces the expected result'.format(hashing_algorithm=hashing_algorithm))
    assert binascii.hexlify(lorem_ipsum_hash) == LOREM_IPSUM_HASHES[hashing_algorithm]


def main(test_loops: int = 1, debug: bool = False):
    """
    Test all functions of the mprsa module.

    Args:
        test_loops (int): Number of times to run the tests.  Defaults to 1.

        debug (bool): A boolean which when `True` causes debug messages to be printed.  Defaults to `False`.
    """

    global DEBUG
    DEBUG = debug

    for test_loop in range(0, test_loops):
        print('Test loop {test_loop}... '.format(test_loop=test_loop), end='\n' if DEBUG else '')
        try:
            test_key_importing_and_exporting()
            test_key_generation(bit_cnt=64, accurate_modulus=True, safe_primes=False)
            test_key_generation(bit_cnt=64, accurate_modulus=False, safe_primes=True)
            test_key_generation(bit_cnt=64, accurate_modulus=True, safe_primes=True)
            public_key, private_key = test_key_generation(bit_cnt=2048, accurate_modulus=False, safe_primes=False)
            test_encryption_and_decryption(public_key, private_key)
            test_signing_and_verification(public_key, private_key, 'SHA-1')
            test_signing_and_verification(public_key, private_key, 'SHA-256')
            print('SUCCESS!')
        except Exception as e:
            print('FAIL!')
            print(e)


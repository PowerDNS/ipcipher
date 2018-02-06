                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **ipcipher: encrypting IP addresses**

STATUS: This standard is open for discussion. We hope to finalize it
quickly - bert.hubert@powerdns.com /
[@PowerDNS_Bert](https://twitter.com/PowerDNS_Bert).

ipcipher
========
This page documents a simple way to encrypt IPv4 and IPv6 addresses such
that any address encrypts to a valid address.  This enables existing tools
to be used on encrypted IPv4 and IPv6 addresses.

There are many ways to do this, especially for IPv6, but the method
described here is simple and interoperable.  This page:

 * Describes the algorithms used to encrypt/decrypt IP addresses
 * Specifies how to derive the key from a password
 * Links to reference implementations in various languages
 * Provides a set of published test vectors to test interoperabilty

In order to enhance interoperability, implementations that want to encrypt
IP addresses are encouraged to do so using this 'ipcipher' standard.

Why encrypt IP addresses?
=========================
Frequently, privacy concerns and regulations get in the way of security
analysis.  Privacy is important, but so is security.  Compromised systems
eventually also harm privacy.

Per-customer/subscriber traces are extremely useful for researching the
security of networks.  However, privacy officers rightly object the
unbridled sharing of which IP address did what. 

One potential solution is to encrypt IP addresses in log files or PCAPs with
a secret key.  Crucially, this can be done in a way that the IP addresses
still look like IP addresses, and can be stored 'in place'.

The encryption key is held by the privacy officer, or their department, and
if based on encrypted IP addresses something interesting is found, the
address can be decrypted for further action.

The needs and merits of IP encryption are further explored in '[On IP address encryption: security analysis with respect for
privacy](https://medium.com/@bert.hubert/on-ip-address-encryption-security-analysis-with-respect-for-privacy-dabe1201b476)'.
Importantly, this also touches on inherent limitations of encrypting IP
addresses for privacy.

Key derivation
==============
Both IPv4 and IPv6 encryption use a 128-bit key. To derive this key from the
passphrase, use PBKDF2 as follows:

```
DK = PBKDF2(SHA1, Password, "ipcipheripcipher", 50000, 16)
```

Or in words, RFC 2898 with SHA1 as hashing function, `ipcipheripcipher` as
salt, 50000 iterations, 16 bytes of key `DK`. In OpenSSL this
corresponds to:

```
  static const char* salt="ipcipheripcipher";
  unsigned char out[16];
  PKCS5_PBKDF2_HMAC_SHA1(passwordptr, passwordlen, (const unsigned char*)salt, sizeof(salt), 50000, sizeof(out), out);

```

The key derivation step is not optional.  The `ipcrypt` algorithm used for
IPv4 requires a fully randomized key and is not secure without it. In
addition, PBKDF2 protects against brute forcing of the passphrase.

Some test vectors for key derivation, where first entry is an empty string:

 * "" -> 99 be 12 3a c5 f8 67 db 37 19 3d b7 ae e6 7e 73
 * "3.141592653589793" -> 23 07 23 58 ad cb 9b 23 05 57 4e 23 29 1b 40 ad
 * "crypto is not a coin" -> c8 18 0e 56 05 6d 3e cb f8 50 50 0b fd 84 19 3d 
 
Take care not to process a possible trailing 0 in the password.

IPv4 algorithm
==============
An IPv4 address is a 32 bit value, and to encrypt it to another IPv4 address
we need a block cipher that is 32 bit native.  A modern and suitable
algorithm is '[ipcrypt](https://github.com/veorq/ipcrypt)' by [Jean-Philippe
Aumasson](https://aumasson.jp/). ipcrypt was inspired by
[SipHash](https://en.wikipedia.org/wiki/SipHash) (which was invented by
Aumasson and Dan J.  Bernstein).

ipcrypt uses a 128 bit key, there is no padding, no cipher modes or anything
else.

Implementations:

 * [C](https://github.com/jedisct1/c-ipcrypt) by Frank Denis
 * [Python](https://github.com/veorq/ipcrypt) by Jean-Philippe Aumasson
 * [Go](https://github.com/veorq/ipcrypt) by Jean-Philips Aumasson

Note that the Python and Go repository also includes command line tools.
 
Test vectors using the derived key "some 16-byte key" (minus the quotes):

 * 127.0.0.1 -> 114.62.227.59
 * 8.8.8.8 -> 46.48.51.50
 * 1.2.3.4 -> 171.238.15.199
 
Using the following key in hex: 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15
16

 * Start with IP address 192.168.69.42 and encrypt it 100 million times ->
   93.155.197.186 (so keep on encrypting the encrypted address)
   
Using the password "crypto is not a coin":

 * 198.41.0.4 -> 78.178.254.81
 * 130.161.180.1 -> 207.193.250.137
 * 0.0.0.0 -> 134.197.67.89
 
Note that this password needs to be used to derive they key first.

IPv6 algorithm
==============
IPv6 addresses are 128 bits, and there is a wealth of suitable algorithms
available. AES is robust and widely available, and more than good enough.

AES is typically deployed in a mode like Cipher Block Chaining, but no such
mode is required to encrypt IP addresses. A straight AES operation is used,
with no further XORing, as in Electronic Code Book "mode".

AES is almost always already available.  To get a raw AES encryption
operation out of OpenSSL or its variants:

```
  AES_KEY wctx;
  AES_set_encrypt_key(key, 128, &wctx);
  AES_encrypt((const unsigned char*)&ca.sin6.sin6_addr.s6_addr,
              (unsigned char*)&ret.sin6.sin6_addr.s6_addr, &wctx);  
```

Decryption is the same, with the obvious s/encrypt/decrypt/ change.

There is as yet no command line tool that performs these operations,
although PowerDNS `pdnsutil` will feature this in the 4.2 release.

Test vectors using the key "some 16-byte key":

 * ::1 -> 3718:8853:1723:6c88:7e5f:2e60:c79a:2bf
 * 2001:503:ba3e::2:30 -> 64d2:883d:ffb5:dd79:24b:943c:22aa:4ae7
 * 2001:DB8:: -> ce7e:7e39:d282:e7b1:1d6d:5ca1:d4de:246f

Using the password "crypto is not a coin":

 * ::1 -> 2ec1:fa64:6771:a68b:dcb:6cca:8422:5c1c
 * 2001:503:ba3e::2:30 -> d8a9:27d7:b9d1:492f:670e:6ffc:e427:fe49
 * 2001:DB8:: -> 6709:bdb1:cd1e:354f:ebfb:5775:fb51:8e64

Note that this password needs to be used to derive they key first.

<script>window.markdeepOptions={};
window.markdeepOptions.tocStyle="short";</script>
<!--  Markdeep:  --><style  class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script  src="markdeep.min.js"></script><script  src="https://casual-effects.com/markdeep/latest/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>

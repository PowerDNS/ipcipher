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

Known implementations:

 * [In Go, by Silke Hofstra](https://github.com/silkeh/ipcipher)
 * PowerDNS

Discussion on how and when to use `ipcipher` can be found in the
[meta](meta.md.html) document.

Acknowledgements
================
Silke Hofstra built the first interoperable implementation and found many
mistakes in the specification and test vectors. Jean-Philippe Aumasson
supplied the `ipcrypt` algorithm & guidance on key derivation. Further thanks to: 
Frank Denis for providing the C implementation of `ipcrypt` and general
advice, Edwin van Vliet for noting the risk of checksums providing hint of
old IP address.


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

Guidance on how to use `ipcipher` can be found [here](meta.md.html).

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
  static const char salt[]="ipcipheripcipher";
  unsigned char out[16];
  PKCS5_PBKDF2_HMAC_SHA1(passwordptr, passwordlen, (const unsigned char*)salt, sizeof(salt)-1, 50000, sizeof(out), out);

```

The key derivation step is not optional.  The `ipcrypt` algorithm used for
IPv4 requires a fully randomized key and is not secure without it. In
addition, PBKDF2 protects against brute forcing of the passphrase.

Some test vectors for key derivation, where first entry is an empty string:

 * "" -> bb 8d cd 7b e9 a6 f4 3b 33 04 c6 40 d7 d7 10 3c
 * "3.141592653589793" ->  37 05 bd 6c 0e 26 a1 a8 39 89 8f 1f a0 16 a3 74
 * "crypto is not a coin" -> 06 c4 ba d2 3a 38 b9 e0 ad 9d 05 90 b0 a3 d9 3a
 
Take care not to process a possible trailing 0 in the password (or salt).

Note: it is of course also possible to use a fully random 128-bit key that
is not derived from a passphrase. This offers some security advantages too,
as the full 128-bit keyspace is used. Implementations are encouraged to make
it possible to either provide a passphrase or a 128-bit string, but be
careful that it is not possible to disambiguate between these two
automatically!

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
 * [Go](https://github.com/veorq/ipcrypt) by Jean-Philippe Aumasson
 * [Python](https://github.com/veorq/ipcrypt) by Jean-Philippe Aumasson
 * [Rust](https://github.com/stbuehler/rust-ipcrypt) by Stefan Bühler

Note that the (combined) Python and Go repository also includes command line
tools.
 
Test vectors using the derived key "some 16-byte key" (minus the quotes):

 * 127.0.0.1 -> 114.62.227.59
 * 8.8.8.8 -> 46.48.51.50
 * 1.2.3.4 -> 171.238.15.199
 
Using the following key in hex: 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 
10

 * Start with IP address 192.168.69.42 and encrypt it 100 million times ->
   93.155.197.186 (so keep on encrypting the encrypted address)
   
Using the password "crypto is not a coin":

 * 198.41.0.4 -> 139.111.117.167
 * 130.161.180.1 -> 66.235.221.231
 * 0.0.0.0 -> 203.253.152.187
 
Note that this password needs to be used to derive the actual key first.

IPv6 algorithm
==============
IPv6 addresses are 128 bits, and there is a wealth of suitable algorithms
available.  AES-128 is robust and widely available, and more than good
enough.

AES is typically deployed in a mode like Cipher Block Chaining, but no such
mode is required to encrypt IP addresses. A straight AES operation is used,
with no further XORing, as in Electronic Code Book "mode".

AES is almost always already available.  To get a raw AES-128 encryption
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

 * ::1 -> a551:9cb0:c9b:f6e1:6112:58a:af29:3a6c
 * 2001:503:ba3e::2:30 -> 6e60:2674:2fac:d383:f9d5:dcfe:fc53:328e
 * 2001:DB8:: -> a8f5:16c8:e2ea:23b9:748d:67a2:4107:9d2e

Note that this password needs to be used to derive the key first.

<script>window.markdeepOptions={};
window.markdeepOptions.tocStyle="short";</script>
<!--  Markdeep:  --><style  class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script  src="markdeep.min.js"></script><script  src="https://casual-effects.com/markdeep/latest/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>

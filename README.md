# go-past

[![GoDoc](https://godoc.org/github.com/ericchiang/go-past/past?status.svg)](https://godoc.org/github.com/ericchiang/go-past/past)
[![Build Status](https://travis-ci.org/ericchiang/go-past.svg?branch=master)](https://travis-ci.org/ericchiang/go-past)

A Go implementation of [Platform-Agnostic Security Tokens (PAST)][past], [_"a secure alternative to JWT."_][hacker-news]

## Warning

This package still needs to be check for conformance against the original PHP implementaiton.

This package may change in the future, hasn't been audited, isn't thoroughly tested, and hasn't been fuzzed. Proceed with caution.

## PAST

PAST is a JWT alternative for authenticating, signing, and encrypting payloads into URL frendly tokens. As opposed to JWTs which require parsing a complex header to determine the signature algorithm, PAST token headers only hold a version and an operation. For example the following token uses PAST `v2` to authenticate (`auth`) a message.

```
v2.auth.ewogICJkYXRhIjogInRoaXMgaXMgYW4gYXV0aGVudGljYXRlZCBtZXNzYWdlIiwKICAiZXhwIjogIjIwMzktMDEtMDFUMDA6MDA6MDAiCn3OF39sdzCcOyUiVSSQwRfGoauVG5Xt9eZc45k31wdxjA
```

`v2.auth.` indicates that this token is authenticated with a symmetric key using HMAC-SHA512. The payload is a plain text and a MAC.

The map of versions and operations to algorithms can be found here: https://github.com/paragonie/past/tree/master/docs/01-Protocol-Versions

## Usage

Given a symmetric key and a payload, a user can construct an authenticated message encoded as a PAST token.

```go
key, err := past.NewKey()
if err != nil {
    // Handle error
}

payload := []byte(`{
  "data": "this is an authenticated message",
  "exp": "2039-01-01T00:00:00"
}`)

token, err := past.V2.Auth(key, payload)
if err != nil {
    // Handle error
}
fmt.Printf("%x\n", key)
fmt.Println(token)
```

The program above prints the generated authentication key and the PAST token.

```
e0ea39822d1b9fa67da2c63dd51b47892f66a1e80d14a40fb3d96dc0ab839fbd
v2.auth.ewogICJkYXRhIjogInRoaXMgaXMgYW4gYXV0aGVudGljYXRlZCBtZXNzYWdlIiwKICAiZXhwIjogIjIwMzktMDEtMDFUMDA6MDA6MDAiCn3OF39sdzCcOyUiVSSQwRfGoauVG5Xt9eZc45k31wdxjA
```

The key can be used at a later time to verify the token.

```
key, _ := hex.DecodeString("e0ea39822d1b9fa67da2c63dd51b47892f66a1e80d14a40fb3d96dc0ab839fbd")

token := "v2.auth.ewogICJkYXRhIjogInRoaXMgaXMgYW4gYXV0aGVudGljYXRlZCBtZXNzYWdlIiwKICAiZXhwIjogIjIwMzktMDEtMDFUMDA6MDA6MDAiCn3OF39sdzCcOyUiVSSQwRfGoauVG5Xt9eZc45k31wdxjA"

payload, err := past.V2.AuthVerify(key, token)
if err != nil {
    // Handle error
}
fmt.Printf("%s\n", payload)
```

The program above prints the original payload.

```
{
  "data": "this is an authenticated message",
  "exp": "2039-01-01T00:00:00"
}
```

The package also supports signing with an asymmetric key and encrypted authentication with a symmetric key.

## Missing features

This implementation is missing the following features:

* `v1.sign` (RSASSA-PSS) - PAST requires specifying the mask length, which Go doesn't expose directly
* `v2.enc` (XChaCha20-Poly1305) - no XChaCha20 implementation in golang.org/x/crypto (only straight ChaCha20)
* Footer data

## Implementer experience report

Currently, PAST is more of a documented PHP library than a specification. Many of the implementation details require reading the source code, while certain aspects are extremely PHP specific (for example the [pre-authentication encoding (PAE)][pae] just describes performing PHP's [`pack('P', n)`][pack]). Also, aspects of PAST sometime seem more complex than they need to be. `v1.enc`'s use of HKDF to derive keys and the pre-authentication encoding seralization are good examples of this.

Though PAST is more straight forward than a JWT, cookbooks like [`gtank/cryptopasta`][cryptopasta] might also be of interest for users looking for simpler strategies.

[past]: https://github.com/paragonie/past
[hacker-news]: https://news.ycombinator.com/item?id=16070394
[pae]: https://github.com/paragonie/past/blob/v0.2.0/docs/01-Protocol-Versions/Common.md#pae-definition
[pack]: https://secure.php.net/manual/en/function.pack.php
[cryptopasta]: https://github.com/gtank/cryptopasta

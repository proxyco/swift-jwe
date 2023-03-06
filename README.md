# Swift JWE

Swift JWE is a Swift package that provides a convenient way to encrypt and decrypt data using JSON Web Encryption (JWE) [RFC7516](https://www.rfc-editor.org/rfc/rfc7516).

## Supported Key Management Algorithms

The package supports the following key management algorithms:

- `ECDH-ES`
- `ECDH-ES+A128KW`
- `ECDH-ES+A192KW`
- `ECDH-ES+A256KW`
- `ECDH-1PU` [draft-madden-jose-ecdh-1pu-04](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04)

## Supported Content Encryption Algorithms

The package supports the following content encryption algorithms:

- `A128GCM`
- `A192GCM`
- `A256GCM`

## Supported Elliptic Curves

The package supports the following elliptic curves:

- `P-256`
- `P-384`
- `P-521`
- `X25519`
- `X448`
- `secp256k1` [RFC8812 Section 3.1](https://www.rfc-editor.org/rfc/rfc8812#section-3.1)

## Usage

To use Swift JWE, follow these simple steps:

1. Load / Generate the recipient's key pair.
2. Create a `JWE` instance with the appropriate protected header.
3. Use the `encrypt` method to encrypt the plaintext using the recipient's public key.
4. Send the compact serialization of the JWE to the recipient.
5. Use the `decrypt` method to decrypt the ciphertext using the recipient's private key.

Here's an example:

```swift
// Generate recipient key pair
let recipientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
let recipientPublicKey = recipientPrivateKey.publicKey

// Encrypt plaintext using JWE
let plaintext = "Hello, World!".data(using: .utf8)!
var jwe = JWE(
    protectedHeader: .init(
        alg: .ecdhESA256KW,
        enc: .a256GCM,
        zip: .deflate
    )
)
try jwe.encrypt(
    plaintext: plaintext,
    to: recipientPublicKey.jwkRepresentation
)
let compactSerialization = jwe.compactSerialization

// Sender sends JWE compact serialization to recipient...
// ...

// Decrypt ciphertext
let receivedJWE = try JWE(compactSerialization: compactSerialization)
let receivedPlaintext = try receivedJWE.decrypt(
    using: recipientPrivateKey.jwkRepresentation
)
```

For more information on how to use Swift JWE, please refer to the [documentation](https://swiftpackageindex.com/proxyco/swift-jwe).

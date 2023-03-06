import CryptoKit
import Foundation
import secp256k1

/// A protocol for types that can be represented as a JWK.
///
/// Types conforming to this protocol can be represented as a JWK by providing a `jwkRepresentation` property.
public protocol JWKRepresentable {
    /// Returns the JWK representation of the conforming type.
    var jwkRepresentation: JWK { get }
}

extension JWK: JWKRepresentable {
    /// Returns the JWK representation of a `JWK` instance.
    public var jwkRepresentation: JWK {
        self
    }
}

public extension JWKRepresentable where Self == JWK {
    /// Returns the public key of a `JWK` instance.
    var publicKey: JWK {
        var copy = self
        copy.d = nil
        return copy
    }
}

extension P256.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `P256.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = publicKey.rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            kty: .ec,
            crv: .p256,
            x: Base64URL.encode(x),
            y: Base64URL.encode(y),
            d: Base64URL.encode(rawRepresentation)
        )
    }
}

extension P384.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `P384.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = publicKey.rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            kty: .ec,
            crv: .p384,
            x: Base64URL.encode(x),
            y: Base64URL.encode(y),
            d: Base64URL.encode(rawRepresentation)
        )
    }
}

extension P521.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `P521.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = publicKey.rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            kty: .ec,
            crv: .p521,
            x: Base64URL.encode(x),
            y: Base64URL.encode(y),
            d: Base64URL.encode(rawRepresentation)
        )
    }
}

extension Curve25519.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `Curve25519.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        JWK(
            kty: .okp,
            crv: .x25519,
            x: Base64URL.encode(publicKey.rawRepresentation),
            d: Base64URL.encode(rawRepresentation)
        )
    }
}

extension Curve448.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `Curve448.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        JWK(
            kty: .okp,
            crv: .x448,
            x: Base64URL.encode(publicKey.rawRepresentation),
            d: Base64URL.encode(rawRepresentation)
        )
    }
}

extension secp256k1.KeyAgreement.PrivateKey: JWKRepresentable {
    /// Returns the JWK representation of a `secp256k1.KeyAgreement.PrivateKey` instance.
    public var jwkRepresentation: JWK {
        // The uncompressed public key is 65 bytes long: a single byte prefix (0x04) followed by the two 32-byte coordinates.
        let publicKeyRawRepresentation = publicKey.rawRepresentation.dropFirst(1)
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            kty: .ec,
            crv: .secp256k1,
            x: Base64URL.encode(x),
            y: Base64URL.encode(y),
            d: Base64URL.encode(rawRepresentation)
        )
    }
}

extension P256.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `P256.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            kty: .ec,
            crv: .p256,
            x: Base64URL.encode(x),
            y: Base64URL.encode(y)
        )
    }
}

extension P384.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `P384.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            kty: .ec,
            crv: .p384,
            x: Base64URL.encode(x),
            y: Base64URL.encode(y)
        )
    }
}

extension P521.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `P521.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        let publicKeyRawRepresentation = rawRepresentation
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            kty: .ec,
            crv: .p521,
            x: Base64URL.encode(x),
            y: Base64URL.encode(y)
        )
    }
}

extension Curve25519.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `Curve25519.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        JWK(
            kty: .okp,
            crv: .x25519,
            x: Base64URL.encode(rawRepresentation)
        )
    }
}

extension Curve448.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `Curve448.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        JWK(
            kty: .okp,
            crv: .x448,
            x: Base64URL.encode(rawRepresentation)
        )
    }
}

extension secp256k1.KeyAgreement.PublicKey: JWKRepresentable {
    /// Returns the JWK representation of a `secp256k1.KeyAgreement.PublicKey` instance.
    public var jwkRepresentation: JWK {
        // The uncompressed public key is 65 bytes long: a single byte prefix (0x04) followed by the two 32-byte coordinates.
        let publicKeyRawRepresentation = rawRepresentation.dropFirst(1)
        let x = publicKeyRawRepresentation.prefix(publicKeyRawRepresentation.count / 2)
        let y = publicKeyRawRepresentation.suffix(publicKeyRawRepresentation.count / 2)
        return JWK(
            kty: .ec,
            crv: .secp256k1,
            x: Base64URL.encode(x),
            y: Base64URL.encode(y)
        )
    }
}

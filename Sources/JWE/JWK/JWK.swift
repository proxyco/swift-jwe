import CryptoKit
import Foundation

/// A JSON Web Key (JWK) representation [RFC7517](https://www.rfc-editor.org/rfc/rfc7517)
///
/// This implementation supports the EC and OKP key types, and the P-256, P-384, P-521, X25519, and X448 cryptographic curves.
public struct JWK: Codable, Equatable {
    /// The key type.
    public var kty: KeyType

    /// The cryptographic curve.
    public var crv: Curve?

    /// The algorithm used with the key.
    public var alg: String?

    /// A boolean value indicating whether the key is intended for external use.
    public var ext: Bool?

    /// The value of the "e" parameter for an RSA key.
    public var e: String?

    /// The value of the "n" parameter for an RSA key.
    public var n: String?

    /// The value of the "x" parameter for an EC or OKP key.
    public var x: String?

    /// The value of the "y" parameter for an EC key.
    public var y: String?

    /// The value of the "d" parameter for an EC or RSA key.
    public var d: String?

    /// The key ID.
    public var kid: String?

    /// The key operations that the key is intended to be used for.
    public var keyOps: [String]?

    /// The intended use of the key.
    public var use: Use?
}

public extension JWK {
    /// The intended use of the key.
    ///
    /// For more information, see https://www.rfc-editor.org/rfc/rfc7517#section-4.2
    enum Use: String, Codable, Equatable {
        case signature = "sig"
        case encryption = "enc"
    }

    /// The supported key types.
    ///
    /// For more information, see https://www.rfc-editor.org/rfc/rfc7518#section-6.1
    enum KeyType: String, Codable, Equatable {
        case ec = "EC"
        case okp = "OKP"
    }

    /// The supported cryptographic curves.
    ///
    /// For more information, see https://www.rfc-editor.org/rfc/rfc7518#section-6.1
    enum Curve: String, Codable, CaseIterable, Equatable {
        case p256 = "P-256"
        case p384 = "P-384"
        case p521 = "P-521"
        case x25519 = "X25519"
        case ed25519 = "Ed25519"
        case x448 = "X448"
        case ed448 = "Ed448"
        case secp256k1
    }
}

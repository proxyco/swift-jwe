import CryptoKit
import Foundation
import secp256k1

/// An extension for `JWK` providing convenience functions for working with `CryptoKit`.
public extension JWK {
    /// Returns a `CryptoKit` representation of the JWK.
    ///
    /// - Parameter type: The type of `CryptoKit` object to return.
    /// - Returns: The `CryptoKit` object.
    /// - Throws: `JWKError` if the JWK is not compatible with the specified `CryptoKit` type, or if a required component is missing.
    func cryptoKitRepresentation<T>(type: T.Type) throws -> T {
        guard kty == .ec || kty == .okp else {
            throw JWKError.unsupportedKey
        }

        switch type {
        case is P256.KeyAgreement.PrivateKey.Type,
             is P384.KeyAgreement.PrivateKey.Type,
             is P521.KeyAgreement.PrivateKey.Type,
             is secp256k1.KeyAgreement.PrivateKey.Type,
             is Curve25519.KeyAgreement.PrivateKey.Type,
             is Curve448.KeyAgreement.PrivateKey.Type:

            guard let d else {
                throw JWKError.missingDComponent
            }
            let dData = try Base64URL.decode(d)
            switch type {
            case is P256.KeyAgreement.PrivateKey.Type:
                return try P256.KeyAgreement.PrivateKey(rawRepresentation: dData) as! T
            case is P384.KeyAgreement.PrivateKey.Type:
                return try P384.KeyAgreement.PrivateKey(rawRepresentation: dData) as! T
            case is P521.KeyAgreement.PrivateKey.Type:
                return try P521.KeyAgreement.PrivateKey(rawRepresentation: dData) as! T
            case is secp256k1.KeyAgreement.PrivateKey.Type:
                return try secp256k1.KeyAgreement.PrivateKey(rawRepresentation: dData, format: .uncompressed) as! T
            case is Curve25519.KeyAgreement.PrivateKey.Type:
                return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: dData) as! T
            case is Curve448.KeyAgreement.PrivateKey.Type:
                return try Curve448.KeyAgreement.PrivateKey(rawRepresentation: dData) as! T
            default:
                throw JWKError.unsupportedKey
            }

        case is P256.KeyAgreement.PublicKey.Type,
             is P384.KeyAgreement.PublicKey.Type,
             is P521.KeyAgreement.PublicKey.Type,
             is secp256k1.KeyAgreement.PublicKey.Type:

            guard let x else {
                throw JWKError.missingXComponent
            }
            guard let y else {
                throw JWKError.missingYComponent
            }
            let xData = try Base64URL.decode(x)
            let yData = try Base64URL.decode(y)
            let data = xData + yData
            switch type {
            case is P256.KeyAgreement.PublicKey.Type:
                return try P256.KeyAgreement.PublicKey(rawRepresentation: data) as! T
            case is P384.KeyAgreement.PublicKey.Type:
                return try P384.KeyAgreement.PublicKey(rawRepresentation: data) as! T
            case is P521.KeyAgreement.PublicKey.Type:
                return try P521.KeyAgreement.PublicKey(rawRepresentation: data) as! T
            case is secp256k1.KeyAgreement.PublicKey.Type:
                // The uncompressed public key is 65 bytes long: a single byte prefix (0x04) followed by the two 32-byte coordinates.
                return try secp256k1.KeyAgreement.PublicKey(
                    rawRepresentation: [0x04] + data,
                    format: .uncompressed
                ) as! T
            default:
                throw JWKError.unsupportedKey
            }

        case is Curve25519.KeyAgreement.PublicKey.Type,
             is Curve448.KeyAgreement.PublicKey.Type:

            guard let x else {
                throw JWKError.missingXComponent
            }
            let xData = try Base64URL.decode(x)
            let data = xData
            switch type {
            case is Curve25519.KeyAgreement.PublicKey.Type:
                return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data) as! T
            case is Curve448.KeyAgreement.PublicKey.Type:
                return try Curve448.KeyAgreement.PublicKey(rawRepresentation: data) as! T
            default:
                throw JWKError.unsupportedKey
            }

        default:
            throw JWKError.unsupportedKey
        }
    }

    /// Computes the shared secret between the private key represented by this JWK and the public key represented by the given JWK.
    ///
    /// - Parameter publicKeyShare: The JWK representing the public key to use for key agreement.
    /// - Returns: The shared secret.
    /// - Throws: `JWKError` if the JWKs are not compatible, or if a required component is missing.
    func sharedSecretFromKeyAgreement(with publicKeyShare: JWK) throws -> Data {
        guard kty == publicKeyShare.kty, crv == publicKeyShare.crv else {
            throw JWKError.incompatibleKeys
        }
        switch kty {
        case .ec:
            switch crv {
            case .p256:
                let privateKey = try cryptoKitRepresentation(type: P256.KeyAgreement.PrivateKey.self)
                let publicKey = try publicKeyShare.cryptoKitRepresentation(type: P256.KeyAgreement.PublicKey.self)
                return try privateKey.sharedSecretFromKeyAgreement(with: publicKey).data
            case .p384:
                let privateKey = try cryptoKitRepresentation(type: P384.KeyAgreement.PrivateKey.self)
                let publicKey = try publicKeyShare.cryptoKitRepresentation(type: P384.KeyAgreement.PublicKey.self)
                return try privateKey.sharedSecretFromKeyAgreement(with: publicKey).data
            case .p521:
                let privateKey = try cryptoKitRepresentation(type: P521.KeyAgreement.PrivateKey.self)
                let publicKey = try publicKeyShare.cryptoKitRepresentation(type: P521.KeyAgreement.PublicKey.self)
                return try privateKey.sharedSecretFromKeyAgreement(with: publicKey).data
            case .secp256k1:
                let privateKey = try cryptoKitRepresentation(type: secp256k1.KeyAgreement.PrivateKey.self)
                let publicKey = try publicKeyShare.cryptoKitRepresentation(type: secp256k1.KeyAgreement.PublicKey.self)
                return try Data(privateKey.sharedSecretFromKeyAgreement(with: publicKey).bytes)
            default:
                throw JWKError.unsupportedKey
            }
        case .okp:
            switch crv {
            case .x25519:
                let privateKey = try cryptoKitRepresentation(type: Curve25519.KeyAgreement.PrivateKey.self)
                let publicKey = try publicKeyShare.cryptoKitRepresentation(type: Curve25519.KeyAgreement.PublicKey.self)
                return try privateKey.sharedSecretFromKeyAgreement(with: publicKey).data
            case .x448:
                let privateKey = try cryptoKitRepresentation(type: Curve448.KeyAgreement.PrivateKey.self)
                let publicKey = try publicKeyShare.cryptoKitRepresentation(type: Curve448.KeyAgreement.PublicKey.self)
                return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            default:
                throw JWKError.unsupportedKey
            }
        }
    }
}

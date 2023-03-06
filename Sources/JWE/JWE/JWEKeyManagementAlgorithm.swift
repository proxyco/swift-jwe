import Foundation

/// Supported JWE cryptographic algorithms for key management.
///
/// For more information, see [RFC7518 Section 4.1](https://www.rfc-editor.org/rfc/rfc7518#section-4.1)
public enum JWEKeyManagementAlgorithm: String, Codable, Equatable, CaseIterable {
    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    case ecdhES = "ECDH-ES"

    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
    case ecdhESA128KW = "ECDH-ES+A128KW"

    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
    case ecdhESA192KW = "ECDH-ES+A192KW"

    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
    case ecdhESA256KW = "ECDH-ES+A256KW"

    /// ECDH-ES Key Agreement with Elliptic Curve Diffie-Hellman One-Pass Unified Model
    ///
    /// For more information, see [ECDH-1PU Draft](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04)
    case ecdh1PU = "ECDH-1PU"

    /// Returns a Boolean value indicating whether this algorithm uses ECDH-ES.
    var isECDHES: Bool {
        rawValue.hasPrefix("ECDH")
    }

    /// Returns a Boolean value indicating whether this algorithm uses AES key wrap.
    var usesAESKeyWrap: Bool {
        rawValue.hasSuffix("A128KW") ||
            rawValue.hasSuffix("A192KW") ||
            rawValue.hasSuffix("A256KW")
    }

    /// Returns a Boolean value indicating whether this algorithm uses a direct encryption key.
    var usesDirectEncryptionKey: Bool {
        switch self {
        case .ecdhES, .ecdh1PU:
            return true
        default:
            return false
        }
    }
}

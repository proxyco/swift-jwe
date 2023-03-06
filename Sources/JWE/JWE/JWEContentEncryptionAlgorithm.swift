import Foundation

/// Supported JWE cryptographic algorithms for content encryption.
///
/// For more information, see [RFC7518 Section 5.1](https://www.rfc-editor.org/rfc/rfc7518#section-5.1)
public enum JWEContentEncryptionAlgorithm: String, Codable, Equatable, CaseIterable {
    case a128GCM = "A128GCM"
    case a192GCM = "A192GCM"
    case a256GCM = "A256GCM"
}

extension JWEContentEncryptionAlgorithm {
    /// Returns the key size in bits.
    var keySize: Int {
        switch self {
        case .a128GCM: return 128
        case .a192GCM: return 192
        case .a256GCM: return 256
        }
    }
}

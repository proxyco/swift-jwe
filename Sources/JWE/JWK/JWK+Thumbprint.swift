import CryptoKit
import Foundation

public extension JWK {
    /// Calculates the JWK thumbprint as per [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)
    ///
    /// - Parameters:
    ///   - hashFunction: The hash function to use for the JWK thumbprint calculation. Defaults to SHA-256.
    /// - Returns: The Base64URL-encoded JWK thumbprint.
    /// - Throws: `JWKError.unsupportedKey` if the JWK type is not supported.
    func thumbprint<H>(
        with _: H = CryptoKit.SHA256()
    ) throws -> String where H: HashFunction {
        // Get required members of JWK
        // See https://www.rfc-editor.org/rfc/rfc7638#section-3.2
        let requiredMembers: [String: Any]
        switch kty {
        case .ec:
            guard let crv, let x, let y else {
                throw JWKError.unsupportedKey
            }
            requiredMembers = [
                "crv": crv.rawValue,
                "kty": kty.rawValue,
                "x": x,
                "y": y,
            ]
        case .okp:
            guard let crv, let x else {
                throw JWKError.unsupportedKey
            }
            requiredMembers = [
                "crv": crv.rawValue,
                "kty": kty.rawValue,
                "x": x,
            ]
        }

        // Construct JSON object with sorted keys
        let jsonData = try JSONSerialization.data(
            withJSONObject: requiredMembers,
            options: .sortedKeys
        )

        // Hash the JSON data using the specified hash function
        let hashData = H.hash(data: jsonData).withUnsafeBytes { Data($0) }

        // Encode the hash data as a Base64URL string and return it
        return Base64URL.encode(hashData)
    }
}

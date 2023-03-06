import Foundation

/// A simple implementation of Base64URL decoding and encoding.
/// For more information, see https://www.rfc-editor.org/rfc/rfc4648#section-5.
enum Base64URL {
    /// Decodes a base64Url encoded string to a Data object.
    ///
    /// - Parameter value: The base64Url encoded string to be decoded.
    ///
    /// - Throws: `Base64URLError.invalidBase64` if the input string is not a valid base64Url encoded string.
    ///           `Base64URLError.unableToCreateDataFromBase64String` if the input string cannot be converted to a Data object.
    static func decode(_ value: String) throws -> Data {
        var base64 = value
        base64 = base64.replacingOccurrences(of: "-", with: "+")
        base64 = base64.replacingOccurrences(of: "_", with: "/")

        // Properly pad the string.
        switch base64.count % 4 {
        case 0: break
        case 2: base64 += "=="
        case 3: base64 += "="
        default: throw Base64URLError.invalidBase64
        }

        guard let data = Data(base64Encoded: base64) else {
            throw Base64URLError.unableToCreateDataFromBase64String(base64)
        }

        return data
    }

    /// Encodes a Data object to a base64Url encoded string.
    ///
    /// - Parameter value: The Data object to be encoded.
    static func encode(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}

/// Enum for handling Base64URLErrors.
enum Base64URLError: Error {
    /// The input string is not a valid base64Url encoded string.
    case invalidBase64
    /// The input string cannot be converted to a Data object.
    case unableToCreateDataFromBase64String(String)
}

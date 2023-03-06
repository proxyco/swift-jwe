import Foundation

public extension JWE {
    /// Initializes a new JWE object by parsing the compact serialization string.
    ///
    /// The compact serialization format represents the JWE object as a sequence of five Base64URL-encoded strings separated by period ('.') characters, in the following order:
    /// 1. the Base64URL-encoded protected header
    /// 2. the Base64URL-encoded encrypted key
    /// 3. the Base64URL-encoded initialization vector
    /// 4. the Base64URL-encoded ciphertext
    /// 5. the Base64URL-encoded authentication tag
    ///
    /// - Parameters:
    ///   - compactSerialization: The compact serialization string representing the JWE object.
    /// - Throws:
    ///   `JWEError.invalidNumberOfSegments` if the number of segments in the compact serialization string is not 5, or `Base64URLError` if any of the Base64URL-encoded strings are not valid.
    init(compactSerialization: String) throws {
        let parts = compactSerialization.components(separatedBy: ".")

        guard parts.count == 5 else {
            throw JWEError.invalidNumberOfSegments(parts.count)
        }

        try self.init(
            protectedHeader: parts[0],
            encryptedKey: parts[1],
            initializationVector: parts[2],
            ciphertext: parts[3],
            authenticationTag: parts[4]
        )
    }

    /// The JWE compact serialization string representation of the JWE object.
    ///
    /// The compact serialization format represents the JWE object as a sequence of five Base64URL-encoded strings separated by period ('.') characters, in the following order:
    ///
    /// 1. the Base64URL-encoded protected header
    /// 2. the Base64URL-encoded encrypted key
    /// 3. the Base64URL-encoded initialization vector
    /// 4. the Base64URL-encoded ciphertext
    /// 5. the Base64URL-encoded authentication tag
    var compactSerialization: String {
        var header = ""

        if let encodedProtectedHeader = protectedHeaderBase64URLEncodedString {
            header = encodedProtectedHeader
        } else {
            // Ensure private part of ephemeral key is not present in serialization
            var modifiedProtectedHeader = protectedHeader
            modifiedProtectedHeader.epk = protectedHeader.epk?.publicKey

            header = Base64URL.encode((try? JSONEncoder().encode(modifiedProtectedHeader)) ?? Data())
        }

        let compactSerialization = [
            header,
            encryptedKey ?? "",
            initializationVector ?? "",
            ciphertext ?? "",
            authenticationTag ?? "",
        ].joined(separator: ".")

        return compactSerialization
    }
}

import CryptoKit
import Foundation

/// A JSON Web Encryption as defined by [RFC7516](https://www.rfc-editor.org/rfc/rfc7516)
public struct JWE {
    /// The protected header
    public var protectedHeader: JWEHeader

    /// The Base64URL-encoded protected header
    var protectedHeaderBase64URLEncodedString: String?

    /// The content encryption key (CEK)
    public var contentEncryptionKey: String?

    /// The encrypted content encryption key
    public var encryptedKey: String?

    /// The initialization vector
    public var initializationVector: String?

    /// The ciphertext
    public var ciphertext: String?

    /// The authentication tag
    public var authenticationTag: String?

    /// Initializes a new JWE object with the specified properties.
    ///
    /// - Parameters:
    ///   - protectedHeader: The protected header.
    ///   - contentEncryptionKey: The content encryption key (CEK).
    ///   - encryptedKey: The encrypted content encryption key.
    ///   - initializationVector: The initialization vector.
    ///   - ciphertext: The ciphertext.
    ///   - authenticationTag: The authentication tag.
    public init(
        protectedHeader: JWEHeader,
        contentEncryptionKey: String? = nil,
        encryptedKey: String? = nil,
        initializationVector: String? = nil,
        ciphertext: String? = nil,
        authenticationTag: String? = nil
    ) {
        self.protectedHeader = protectedHeader
        self.contentEncryptionKey = contentEncryptionKey
        self.encryptedKey = encryptedKey
        self.initializationVector = initializationVector
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
    }

    /// Initializes a new JWE object with the specified properties.
    ///
    /// - Parameters:
    ///   - protectedHeader: The Base64URL-encoded string of the protected header.
    ///   - contentEncryptionKey: The content encryption key (CEK).
    ///   - encryptedKey: The encrypted content encryption key.
    ///   - initializationVector: The initialization vector.
    ///   - ciphertext: The ciphertext.
    ///   - authenticationTag: The authentication tag.
    /// - Throws:
    ///   `DecodingError` if the protected header could not be decoded using JSONDecoder, or `Base64URLError` if the protected header is not a valid base64url string.
    public init(
        protectedHeader: String,
        contentEncryptionKey: String? = nil,
        encryptedKey: String? = nil,
        initializationVector: String? = nil,
        ciphertext: String? = nil,
        authenticationTag: String? = nil
    ) throws {
        try self.init(
            protectedHeader: JSONDecoder().decode(
                JWEHeader.self,
                from: Base64URL.decode(protectedHeader)
            ),
            contentEncryptionKey: contentEncryptionKey,
            encryptedKey: encryptedKey,
            initializationVector: initializationVector,
            ciphertext: ciphertext,
            authenticationTag: authenticationTag
        )
        protectedHeaderBase64URLEncodedString = protectedHeader
    }
}

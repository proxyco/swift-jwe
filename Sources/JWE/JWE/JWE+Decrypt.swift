import CryptoKit
import Foundation

extension JWE {
    /// Decrypts the JWE object using the specified recipient key and returns the decrypted plaintext.
    ///
    /// - Parameters:
    ///   - recipientKey: The recipient's private key to use for decryption.
    ///   - senderKey: The sender's public key, if using ECDH-1PU.
    ///
    /// - Throws:
    ///   - `JWEError.unsupported` if the encryption algorithm is not supported or if using ECDH-1PU and the sender's key is not provided.
    ///   - `JWEError.missingEphemeralKey` if the JWE does not contain an ephemeral key.
    ///
    /// - Returns: The decrypted plaintext.
    public func decrypt(
        using recipientKey: JWK,
        from senderKey: JWK? = nil
    ) throws -> Data {
        // This implementation only supports Elliptic Curve Diffie-Hellman Ephemeral-Static
        guard protectedHeader.alg.isECDHES else {
            throw JWEError.unsupported
        }

        guard let ephemeralKey = protectedHeader.epk else {
            throw JWEError.missingEphemeralKey
        }

        var sharedSecret: Data!
        switch protectedHeader.alg {
        case .ecdh1PU:
            guard let senderKey else {
                throw JWEError.unsupported
            }
            let ze = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
            let zs = try recipientKey.sharedSecretFromKeyAgreement(with: senderKey)
            sharedSecret = ze + zs
        case .ecdhES, .ecdhESA128KW, .ecdhESA192KW, .ecdhESA256KW:
            sharedSecret = try recipientKey.sharedSecretFromKeyAgreement(with: ephemeralKey)
        }

        let derivedKey = try deriveKey(from: sharedSecret)

        var plaintext = try decryptContent(derivedKey: derivedKey)
        if protectedHeader.zip == .deflate {
            plaintext = try (plaintext as NSData).decompressed(using: .zlib) as Data
        }

        return plaintext
    }

    /// Decrypts the content of the JWE object using the specified derived key and returns the decrypted plaintext.
    ///
    /// If the `alg` field in the protected header uses AES key wrap, the encryptedKey property is used to decrypt the content encryption key (CEK) using the specified derivedKey. Otherwise, the derivedKey is used directly as the CEK.
    ///
    /// The plaintext is decrypted using the encryption algorithm specified in the `enc` field of the protected header.
    ///
    /// - Parameters:
    ///   - derivedKey: The derived content encryption key (CEK) to use for decryption.
    ///
    /// - Throws:
    ///   - `JWEError.unsupported` if the encryption algorithm is not supported.
    ///
    /// - Returns: The decrypted plaintext.
    func decryptContent(
        derivedKey: SymmetricKey
    ) throws -> Data {
        guard
            protectedHeader.enc == .a128GCM ||
            protectedHeader.enc == .a192GCM ||
            protectedHeader.enc == .a256GCM
        else {
            throw JWEError.unsupported
        }

        var contentEncryptionKey = derivedKey
        if protectedHeader.alg.usesAESKeyWrap {
            contentEncryptionKey = try AES.KeyWrap.unwrap(
                Base64URL.decode(encryptedKey ?? ""),
                using: derivedKey
            )
        }

        let authenticatingData = try getAuthenticatingData()

        let plaintext = try AES.GCM.open(
            .init(
                nonce: .init(data: Base64URL.decode(initializationVector ?? "")),
                ciphertext: Base64URL.decode(ciphertext ?? ""),
                tag: Base64URL.decode(authenticationTag ?? "")
            ),
            using: contentEncryptionKey,
            authenticating: authenticatingData
        )

        return plaintext
    }
}

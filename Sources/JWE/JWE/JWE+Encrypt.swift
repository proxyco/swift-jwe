import CryptoKit
import Foundation

extension JWE {
    /// Mutates the JWE object to encrypt the specified plaintext using the specified recipient key and sender key (optional).
    ///
    /// The plaintext is encrypted using the encryption algorithm specified in the `enc` field of the protected header, and the CEK is encrypted using the key encryption algorithm specified in the `alg` field of the protected header.
    ///
    /// - Parameters:
    ///   - plaintext: The plaintext to be encrypted.
    ///   - recipientKey: The JWK of the recipient.
    ///   - senderKey: The JWK of the sender, if using the ECDH-1PU algorithm.
    ///
    /// - Throws:
    ///   - `JWEError.unsupported` if the key encryption algorithm is not supported.
    ///   - `JWEError.missingSenderKey` if the sender key is missing and the ECDH-1PU algorithm is used.
    ///   - `JWEError.incompatibleKeys` if the recipient key and sender key are incompatible.
    public mutating func encrypt(
        plaintext: Data,
        to recipientKey: JWK,
        from senderKey: JWK? = nil
    ) throws {
        // This implementation only supports Elliptic Curve Diffie-Hellman Ephemeral-Static
        guard protectedHeader.alg.isECDHES else {
            throw JWEError.unsupported
        }

        // Generate ephemeral key, if needed
        if protectedHeader.epk == nil {
            try generateEphemeralJWK(to: recipientKey)
        }

        var sharedSecret: Data!
        switch protectedHeader.alg {
        case .ecdh1PU:
            guard let senderKey else {
                throw JWEError.missingSenderKey
            }
            guard recipientKey.kty == senderKey.kty, recipientKey.crv == senderKey.crv else {
                throw JWEError.incompatibleKeys
            }
            let ze = try protectedHeader.epk!.sharedSecretFromKeyAgreement(with: recipientKey)
            let zs = try senderKey.sharedSecretFromKeyAgreement(with: recipientKey)
            sharedSecret = ze + zs
        case .ecdhES, .ecdhESA128KW, .ecdhESA192KW, .ecdhESA256KW:
            sharedSecret = try protectedHeader.epk!.sharedSecretFromKeyAgreement(with: recipientKey)
        }

        let derivedKey = try deriveKey(from: sharedSecret)

        var plaintextToEncrypt = plaintext
        if protectedHeader.zip == .deflate {
            plaintextToEncrypt = try (plaintextToEncrypt as NSData).compressed(using: .zlib) as Data
        }

        try encryptContent(plaintext: plaintextToEncrypt, derivedKey: derivedKey)
    }

    /// Mutates the JWE object to encrypt the plaintext using the specified encryption algorithm.
    ///
    /// - Parameter plaintext: The plaintext to be encrypted.
    ///
    /// - Throws:
    ///   - `JWEError.unsupported` if the encryption algorithm is not supported.
    mutating func encryptContent(
        plaintext: Data,
        derivedKey: SymmetricKey
    ) throws {
        guard
            protectedHeader.enc == .a128GCM ||
            protectedHeader.enc == .a192GCM ||
            protectedHeader.enc == .a256GCM
        else {
            throw JWEError.unsupported
        }

        // Generate initialization vector, if needed
        if initializationVector == nil {
            generateInitializationVector()
        }

        // Generate content encryption key, if needed
        if contentEncryptionKey == nil {
            if protectedHeader.alg.usesDirectEncryptionKey {
                contentEncryptionKey = Base64URL.encode(derivedKey.data)
            } else {
                generateContentEncryptionKey()
            }
        }

        let authenticatingData = try getAuthenticatingData()

        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: .init(data: Base64URL.decode(contentEncryptionKey ?? "")),
            nonce: .init(data: Base64URL.decode(initializationVector ?? "")),
            authenticating: authenticatingData
        )

        ciphertext = Base64URL.encode(sealedBox.ciphertext)
        authenticationTag = Base64URL.encode(sealedBox.tag)

        try generateEncryptedKey(derivedKey: derivedKey)
    }
}

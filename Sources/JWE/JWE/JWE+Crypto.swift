import CryptoKit
import Foundation
import secp256k1

extension JWE {
    /// Mutates the JWE object to generate an ephemeral JWK representation of the specified key, and set the `epk` field of the protected header to the generated ephemeral JWK.
    ///
    /// - Parameters:
    ///   - to: The JWK object to which the ephemeral JWK is generated.
    ///
    /// - Throws:
    ///   - `JWKError.unsupportedKey` if the key type or curve is not supported.
    mutating func generateEphemeralJWK(to: JWK) throws {
        var ephemeralJWK: JWK!
        switch to.kty {
        case .ec:
            switch to.crv {
            case .p256:
                ephemeralJWK = P256.KeyAgreement.PrivateKey().jwkRepresentation
            case .p384:
                ephemeralJWK = P384.KeyAgreement.PrivateKey().jwkRepresentation
            case .p521:
                ephemeralJWK = P521.KeyAgreement.PrivateKey().jwkRepresentation
            case .secp256k1:
                ephemeralJWK = try secp256k1.KeyAgreement.PrivateKey(format: .uncompressed).jwkRepresentation
            default:
                throw JWKError.unsupportedKey
            }
        case .okp:
            switch to.crv {
            case .x25519:
                ephemeralJWK = Curve25519.KeyAgreement.PrivateKey().jwkRepresentation
            case .x448:
                ephemeralJWK = Curve448.KeyAgreement.PrivateKey().jwkRepresentation
            default:
                throw JWKError.unsupportedKey
            }
        }
        protectedHeader.epk = ephemeralJWK
    }

    /// Mutates the JWE object to generate a random initialization vector (IV) for the JWE.
    ///
    /// The size of the IV is determined by the encryption algorithm specified in the `enc` field of the protected header.
    mutating func generateInitializationVector() {
        let keySize = protectedHeader.enc.keySize
        let symmetricKey = SymmetricKey(size: .init(bitCount: keySize))
        initializationVector = Base64URL.encode(symmetricKey.data)
    }

    /// Mutates the JWE object to generate a random content encryption key (CEK) for the JWE.
    ///
    /// The size of the CEK is determined by the encryption algorithm specified in the `enc` field of the protected header.
    mutating func generateContentEncryptionKey() {
        let keySize = protectedHeader.enc.keySize
        let symmetricKey = SymmetricKey(size: .init(bitCount: keySize))
        contentEncryptionKey = Base64URL.encode(symmetricKey.data)
    }

    /// Derives a symmetric key from the shared secret using Concatenation Key Derivation Function (KDF).
    ///
    /// - Parameters:
    ///    - sharedSecret: The shared secret used to derive the symmetric key.
    /// - Returns: The derived symmetric key.
    /// - Throws: An error of type `JWEError` if an error occurs during key derivation.
    func deriveKey(from sharedSecret: Data) throws -> SymmetricKey {
        let keyDataLen = protectedHeader.enc.keySize
        let algorithmID = protectedHeader.alg.rawValue.data(using: .ascii) ?? Data()
        let algorithmIDData = UInt32(algorithmID.count).bigEndian.dataRepresentation + algorithmID

        let partyUInfo = try Base64URL.decode(protectedHeader.apu ?? "")
        let partyUInfoData = UInt32(partyUInfo.count).bigEndian.dataRepresentation + partyUInfo

        let partyVInfo = try Base64URL.decode(protectedHeader.apv ?? "")
        let partyVInfoData = UInt32(partyVInfo.count).bigEndian.dataRepresentation + partyVInfo

        let suppPubInfoData = UInt32(keyDataLen).bigEndian.dataRepresentation
        let suppPrivInfoData = Data()

        let derivedKey = try ConcatKDF<CryptoKit.SHA256>.deriveKey(
            z: sharedSecret,
            keyDataLen: keyDataLen,
            algorithmID: algorithmIDData,
            partyUInfo: partyUInfoData,
            partyVInfo: partyVInfoData,
            suppPubInfo: suppPubInfoData,
            suppPrivInfo: suppPrivInfoData
        )

        return derivedKey
    }

    /// Mutates the JWE object to generate the encrypted content encryption key (CEK) for the JWE.
    ///
    /// The encrypted CEK is generated using the specified symmetric key derived from the shared secret, and the CEK is encrypted using the key encryption algorithm specified in the `alg` field of the protected header.
    ///
    /// - Parameters:
    ///    - derivedKey: The symmetric key derived from the shared secret.
    /// - Throws: `JWEError.unsupported` if the key encryption algorithm is not supported.
    mutating func generateEncryptedKey(derivedKey: SymmetricKey) throws {
        if protectedHeader.alg == .ecdh1PU || protectedHeader.alg == .ecdhES {
            // Direct key agreement
            encryptedKey = nil
        } else if protectedHeader.alg.usesAESKeyWrap {
            let wrappedKey = try AES.KeyWrap.wrap(
                .init(data: Base64URL.decode(contentEncryptionKey ?? "")),
                using: derivedKey
            )
            encryptedKey = Base64URL.encode(wrappedKey)
        } else {
            throw JWEError.unsupported
        }
    }

    /// Returns the authenticating data (AAD) for the JWE.
    ///
    /// - Returns: The authenticating data.
    /// - Throws: `DecodingError` if the protected header could not be decoded using JSONDecoder.
    func getAuthenticatingData() throws -> Data {
        if let protectedHeaderBase64URLEncodedString {
            return protectedHeaderBase64URLEncodedString.data(using: .ascii) ?? .init()
        } else {
            // Ensure private part of ephemeral key is not present
            var modifiedProtectedHeader = protectedHeader
            modifiedProtectedHeader.epk = protectedHeader.epk?.publicKey
            let jsonData = try JSONEncoder().encode(modifiedProtectedHeader)
            return Base64URL.encode(jsonData).data(using: .ascii) ?? .init()
        }
    }
}

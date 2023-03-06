/// A set of JSON Web Keys (JWKs). This is a JSON object that contains an array of JWK objects.
public struct JWKSet: Codable {
    /// The array of JWKs.
    public var keys: [JWK]

    /// Initializes a new instance of the JWKSet struct.
    ///
    /// - Parameter keys: The array of JWKs to include in the set.
    public init(keys: [JWK]) {
        self.keys = keys
    }
}

public extension JWKSet {
    /// Returns the key with the given id, if found.
    /// - Parameter id: The id of the key to search for.
    /// - Returns: The JWK with the given id.
    /// - Throws: `JWKError.keyWithIDNotFound` if no key with the given id is found.
    func key(withID id: String) throws -> JWK {
        guard let key = keys.first(where: { $0.kid == id }) else {
            throw JWKError.keyWithIDNotFound(id)
        }
        return key
    }

    /// Returns the JWK with the given use, if found.
    /// - Parameter use: The use of the key to search for.
    /// - Returns: The JWK with the given use.
    /// - Throws: `JWKError.keyNotFound` if no key with the given use is found.
    func key(withUse use: JWK.Use) throws -> JWK {
        guard let key = keys.first(where: { $0.use == use }) else {
            throw JWKError.keyNotFound
        }
        return key
    }

    /// Returns a JWK that is suitable for key agreement with the given JWK.
    /// The returned JWK must have the same `use`, `kty`, and `crv` parameters as the given JWK.
    /// - Parameter key: The JWK to use as a basis for selecting a suitable key for key agreement.
    /// - Returns: A JWK that is suitable for key agreement with the given JWK.
    /// - Throws: `JWKError.keyNotFound` if no suitable key is found.
    func keySuitableForKeyAgreement(with key: JWK) throws -> JWK {
        guard let suitableKey = keys.first(where: { $0.use == key.use && $0.kty == key.kty && $0.crv == key.crv }) else {
            throw JWKError.keyNotFound
        }
        return suitableKey
    }
}

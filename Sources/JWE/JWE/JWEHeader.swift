import Foundation

/// A struct representing the header of a JSON Web Encryption (JWE) object.
///
/// For more information, see [RFC7516 Section 4](https://www.rfc-editor.org/rfc/rfc7516#section-4)
public struct JWEHeader: Codable, Equatable {
    public var alg: JWEKeyManagementAlgorithm
    public var enc: JWEContentEncryptionAlgorithm
    public var zip: CompressionAlgorithm?
    public var jku: String?
    public var jwk: JWK?
    public var kid: String?
    public var x5u: String?
    public var x5c: String?
    public var x5t: String?
    public var x5tS256: String?
    public var typ: String?
    public var cty: String?
    public var crit: String?
    // Header Parameters Used for ECDH Key Agreement
    public var epk: JWK?
    public var apu: String?
    public var apv: String?
    // Header Parameters Used for ECDH-1PU Key Agreement
    public var skid: String?

    public init(
        alg: JWEKeyManagementAlgorithm,
        enc: JWEContentEncryptionAlgorithm,
        zip: CompressionAlgorithm? = nil,
        jku: String? = nil,
        jwk: JWK? = nil,
        kid: String? = nil,
        x5u: String? = nil,
        x5c: String? = nil,
        x5t: String? = nil,
        x5tS256: String? = nil,
        typ: String? = nil,
        cty: String? = nil,
        crit: String? = nil,
        epk: JWK? = nil,
        apu: String? = nil,
        apv: String? = nil,
        skid: String? = nil
    ) {
        self.alg = alg
        self.enc = enc
        self.zip = zip
        self.jku = jku
        self.jwk = jwk
        self.kid = kid
        self.x5u = x5u
        self.x5c = x5c
        self.x5t = x5t
        self.x5tS256 = x5tS256
        self.typ = typ
        self.cty = cty
        self.crit = crit
        self.epk = epk
        self.apu = apu
        self.apv = apv
        self.skid = skid
    }

    enum CodingKeys: String, CodingKey {
        case alg
        case enc
        case zip
        case jku
        case jwk
        case kid
        case x5u
        case x5c
        case x5t
        case x5tS256 = "x5t#S256"
        case typ
        case cty
        case crit
        case epk
        case apu
        case apv
        case skid
    }
}

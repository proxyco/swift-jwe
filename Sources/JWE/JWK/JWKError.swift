/// An error that can be thrown when working with JWKs.
///
/// This enumeration defines the errors that can be thrown when working with JWKs.
public enum JWKError: Error {
    /// The "x" component of an EC or OKP key is missing.
    case missingXComponent

    /// The "y" component of an EC key is missing.
    case missingYComponent

    /// The "d" component of an EC or RSA key is missing.
    case missingDComponent

    /// The key type is not supported.
    case unsupportedKey

    /// The specified key ID was not found in the JWK set.
    case keyWithIDNotFound(String)

    /// The key was not found in the JWK set.
    case keyNotFound

    /// The keys are not compatible for the requested operation.
    case incompatibleKeys
}

import Foundation

/// An enumeration of possible errors that can be thrown when performing JWE operations.
public enum JWEError: Error {
    /// The operation is not supported.
    case unsupported

    /// The number of segments in the JWE is invalid.
    ///
    /// - Parameter numberOfSegments: The number of segments.
    case invalidNumberOfSegments(_: Int)

    /// The ephemeral key is missing.
    case missingEphemeralKey

    /// The sender key is missing.
    case missingSenderKey

    /// The keys used in the JWE are incompatible.
    case incompatibleKeys
}

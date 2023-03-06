/// An enumeration of supported compression algorithms.
///
/// This enumeration provides a list of supported compression algorithms that can be used with JWE. Currently, the only supported algorithm is DEFLATE (also known as ZLIB), as specified in RFC 1951.
///
/// - Note: Additional algorithms may be added in future versions of the library.
///
/// For more information about DEFLATE, see https://www.rfc-editor.org/rfc/rfc1951.
public enum CompressionAlgorithm: String, Codable, Equatable, CaseIterable {
    /// DEFLATE, also known as ZLIB.
    case deflate = "DEF"
}

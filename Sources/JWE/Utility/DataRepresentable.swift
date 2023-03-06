import Foundation

/// A protocol that defines a type that can be converted to and from a little-endian byte buffer.
protocol DataRepresentable {
    /// Initializes an instance of the conforming type from a little-endian byte buffer.
    ///
    /// - Parameter dataRepresentation: A little-endian byte buffer.
    /// - Throws: A `CocoaError` with a `coderInvalidValue` code if the byte buffer has an invalid size.
    init(dataRepresentation: ContiguousBytes) throws

    /// Returns a little-endian byte buffer representation of the conforming type.
    ///
    /// - Returns: A little-endian byte buffer representation of the conforming type.
    var dataRepresentation: Data { get }
}

extension DataRepresentable {
    /// Initializes an instance of the conforming type from a little-endian byte buffer.
    ///
    /// - Parameter dataRepresentation: A little-endian byte buffer.
    /// - Throws: A `CocoaError` with a `coderInvalidValue` code if the byte buffer has an invalid size.
    init(dataRepresentation: ContiguousBytes) throws {
        self = try dataRepresentation.withUnsafeBytes {
            guard
                $0.count == MemoryLayout<Self>.size,
                let baseAddress = $0.baseAddress
            else {
                throw CocoaError(.coderInvalidValue)
            }
            return baseAddress.bindMemory(to: Self.self, capacity: 1).pointee
        }
    }

    /// Returns a little-endian byte buffer representation of the conforming type.
    ///
    /// - Returns: A little-endian byte buffer representation of the conforming type.
    var dataRepresentation: Data {
        var value = self
        return withUnsafeBytes(of: &value) {
            Data($0)
        }
    }
}

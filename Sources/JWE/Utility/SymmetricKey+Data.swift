import CryptoKit
import Foundation

extension SymmetricKey {
    /// Returns the symmetric key as a `Data` object.
    ///
    /// The `SymmetricKey` struct is backed by a contiguous block of memory, which can be accessed as a pointer to `UInt8`. This method creates a `Data` object from the contents of this memory.
    ///
    /// - Returns: A `Data` object containing the symmetric key bytes.
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}

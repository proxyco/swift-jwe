import CryptoKit
import Foundation

extension SharedSecret {
    /// Returns the shared secret as a `Data` object.
    ///
    /// The `SharedSecret` struct is backed by a contiguous block of memory, which can be accessed as a pointer to `UInt8`. This method creates a `Data` object from the contents of this memory.
    ///
    /// - Returns: A `Data` object containing the shared secret bytes.
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}

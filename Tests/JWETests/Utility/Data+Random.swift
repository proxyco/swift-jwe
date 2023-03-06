import Foundation

extension Data {
    /// Generates a `Data` object filled with random bytes of the specified count.
    ///
    /// - Parameter count: The number of random bytes to generate.
    /// - Returns: A `Data` object filled with random bytes of the specified count.
    static func random(count: Int) -> Data {
        var data = Data(count: count)
        _ = data.withUnsafeMutableBytes { mutableBytes in
            SecRandomCopyBytes(kSecRandomDefault, count, mutableBytes.baseAddress!)
        }
        return data
    }
}

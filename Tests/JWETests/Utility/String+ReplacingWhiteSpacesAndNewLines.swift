import Foundation

extension String {
    /// Returns a new string with all whitespace and newline characters removed.
    ///
    /// This method creates a new string with all occurrences of whitespace and newline characters (spaces and line breaks) removed. The original string is not modified.
    ///
    /// - Returns: A new string with all whitespace and newline characters removed.
    func replacingWhiteSpacesAndNewLines() -> String {
        replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
    }
}

@testable import JWE
import XCTest

final class JWKThumbprintTests: XCTestCase {
    // https://www.rfc-editor.org/rfc/rfc8037#appendix-A.3
    func test_Ed25519() {
        let jwk = JWK(
            kty: .okp,
            crv: .ed25519,
            x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        )
        XCTAssertEqual(try jwk.thumbprint(), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
    }

    func test_P256() {
        let jwk = JWK(
            kty: .ec,
            crv: .p256,
            x: "TvQ0_muDyvS4RX9bJm8Rzy9XTpSG7xwo3Ffgu8Oq7OY",
            y: "saNr4hM3qrojSoY4eaO1WGVna5yW_I4EqdFQ4TRl8iQ"
        )
        XCTAssertEqual(try jwk.thumbprint(), "2i6Yjdy_beRJCkTcJbKmHT4L7LtVWdm5gYw9573NMHo")
    }
}

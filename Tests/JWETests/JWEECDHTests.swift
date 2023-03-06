import CryptoKit
@testable import JWE
import secp256k1
import XCTest

final class JWEECDHTests: XCTestCase {
    // https://www.rfc-editor.org/rfc/rfc7520#section-5.4
    func test_ECDH_ES_A128KW_A128GCM_Encrypt() throws {
        // Load public key of the recipient
        let recipientJWK = JWK(
            kty: .ec,
            crv: .p384,
            x: "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2",
            y: "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP",
            kid: "peregrin.took@tuckborough.example",
            use: .encryption
        )

        var jwe = try JWE(
            protectedHeader: "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0",
            contentEncryptionKey: "Nou2ueKlP70ZXDbq9UrRwg",
            initializationVector: "mH-G2zVqgztUtnW_"
        )

        XCTAssertEqual(
            jwe.protectedHeader,
            .init(
                alg: .ecdhESA128KW,
                enc: .a128GCM,
                kid: recipientJWK.kid,
                epk: .init(
                    kty: .ec,
                    crv: .p384,
                    x: "uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3",
                    y: "sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0"
                )
            )
        )

        // Add the private part of the ephemeral key to the protected header for encryption
        jwe.protectedHeader.epk?.d = "D5H4Y_5PSKZvhfVFbcCYJOtcGZygRgfZkpsBr59Icmmhe9sW6nkZ8WfwhinUfWJg"

        try jwe.encrypt(
            plaintext: "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!,
            to: recipientJWK
        )

        XCTAssertEqual(
            jwe.ciphertext,
            "tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ"
        )
        XCTAssertEqual(jwe.authenticationTag, "WuGzxmcreYjpHGJoa17EBg")
        XCTAssertEqual(jwe.encryptedKey, "0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2")
    }

    // https://www.rfc-editor.org/rfc/rfc7520#section-5.4
    func test_ECDH_ES_A128KW_A128GCM_Decrypt() throws {
        let jwe = try JWE(
            compactSerialization: "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0.0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2.mH-G2zVqgztUtnW_.tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ.WuGzxmcreYjpHGJoa17EBg"
        )

        XCTAssertEqual(jwe.protectedHeader.kid, "peregrin.took@tuckborough.example")

        // Load the key identified by protectedHeader.kid from the key store
        let recipientJWK = JWK(
            kty: .ec,
            crv: .p384,
            x: "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2",
            y: "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP",
            d: "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j",
            kid: "peregrin.took@tuckborough.example",
            use: .encryption
        )

        let plaintext = try jwe.decrypt(using: recipientJWK)

        XCTAssertEqual(
            plaintext,
            "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".data(using: .utf8)!
        )
    }

    func test_ECDH_1PU_A256GCM_Encrypt() throws {
        let plaintext = "Hello, World!".data(using: .utf8)!

        // Load the recipient's static key (e.g. by retrieving it from a well-known URL.)
        let recipientStaticJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
                {"kty": "OKP",
                 "crv": "X25519",
                 "kid": "61F56896-F537-43B0-B0FA-573E5C0F66A3",
                 "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw"}
            """.data(using: .utf8)!
        )

        // Load the sender's static key (e.g., by retrieving it from the local key store).
        // Note: It must be of the same type as the recipient's static key.
        let senderStaticJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
                {"kty": "OKP",
                 "crv": "X25519",
                 "kid": "3EA04AE5-FC22-4F99-9250-28EB7492CCF5",
                 "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
                 "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU"}
            """.data(using: .utf8)!
        )

        var jwe = try JWE(
            protectedHeader: .init(
                alg: .ecdh1PU,
                enc: .a256GCM,
                // Use compression for plaintext before encrypting
                zip: .deflate,
                // Notify the recipient which of their private static keys to use to decrypt.
                kid: recipientStaticJWK.kid,
                // Note: APU values are expected to be Base64URL-encoded
                epk: JSONDecoder().decode(
                    JWK.self,
                    from: """
                          {"kty": "OKP",
                           "crv": "X25519",
                           "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
                           "d": "x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8"}
                    """.data(using: .utf8)!
                ),
                // Notify the recipient from where to fetch the sender's static keys.
                apu: Base64URL.encode("https://example.com/sender.jwks".data(using: .ascii) ?? .init()),
                // Notify the recipient which static sender key was used for encrypted authentication.
                skid: senderStaticJWK.kid
            ),
            initializationVector: "FkGX4uU1mkcLCWV9"
        )

        try jwe.encrypt(plaintext: plaintext, to: recipientStaticJWK, from: senderStaticJWK)

        XCTAssertEqual(jwe.compactSerialization, "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC0xUFUiLCJza2lkIjoiM0VBMDRBRTUtRkMyMi00Rjk5LTkyNTAtMjhFQjc0OTJDQ0Y1IiwiemlwIjoiREVGIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn0sImtpZCI6IjYxRjU2ODk2LUY1MzctNDNCMC1CMEZBLTU3M0U1QzBGNjZBMyIsImFwdSI6ImFIUjBjSE02THk5bGVHRnRjR3hsTG1OdmJTOXpaVzVrWlhJdWFuZHJjdyJ9..FkGX4uU1mkcLCWV9.d9lYtkwJ3-hEQWJrpPO8.Jtg6on5gvUjR5AOvsh3HZg")
    }

    func test_ECDH_1PU_A256GCM_Decrypt() throws {
        let jwe = try JWE(compactSerialization: "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC0xUFUiLCJza2lkIjoiM0VBMDRBRTUtRkMyMi00Rjk5LTkyNTAtMjhFQjc0OTJDQ0Y1IiwiemlwIjoiREVGIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFBRnFVQUZhMzlkeUJjIn0sImtpZCI6IjYxRjU2ODk2LUY1MzctNDNCMC1CMEZBLTU3M0U1QzBGNjZBMyIsImFwdSI6ImFIUjBjSE02THk5bGVHRnRjR3hsTG1OdmJTOXpaVzVrWlhJdWFuZHJjdyJ9..FkGX4uU1mkcLCWV9.d9lYtkwJ3-hEQWJrpPO8.Jtg6on5gvUjR5AOvsh3HZg")

        // Load the recipient static key by fetching it from the local key store specified by protectedHeader.kid.
        let recipientStaticJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
                {"kty": "OKP",
                 "crv": "X25519",
                 "kid": "61F56896-F537-43B0-B0FA-573E5C0F66A3",
                 "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
                 "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg"}
            """.data(using: .utf8)!
        )

        XCTAssertEqual(recipientStaticJWK.kid, jwe.protectedHeader.kid)

        // Load the sender static key by retrieving it from the URL specified by protectedHeader.apu.
        guard
            let apu = jwe.protectedHeader.apu,
            let apuURLString = try String(data: Base64URL.decode(apu), encoding: .ascii),
            let _ = URL(string: apuURLString)
        else {
            XCTFail("Unable to retrieve sender static key")
            abort()
        }

        let senderStaticJWK = try JSONDecoder().decode(
            JWK.self,
            from: """
                {"kty": "OKP",
                 "crv": "X25519",
                 "kid": "3EA04AE5-FC22-4F99-9250-28EB7492CCF5",
                 "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4"}
            """.data(using: .utf8)!
        )

        XCTAssertEqual(senderStaticJWK.kid, jwe.protectedHeader.skid)

        let plaintext = try jwe.decrypt(using: recipientStaticJWK, from: senderStaticJWK)

        XCTAssertEqual(plaintext, "Hello, World!".data(using: .utf8)!)
    }

    func testRoundTrip() throws {
        let keys: [(JWK, JWK)] = try [
            (P256.KeyAgreement.PrivateKey().jwkRepresentation, P256.KeyAgreement.PrivateKey().jwkRepresentation),
            (P384.KeyAgreement.PrivateKey().jwkRepresentation, P384.KeyAgreement.PrivateKey().jwkRepresentation),
            (P521.KeyAgreement.PrivateKey().jwkRepresentation, P521.KeyAgreement.PrivateKey().jwkRepresentation),
            (Curve25519.KeyAgreement.PrivateKey().jwkRepresentation, Curve25519.KeyAgreement.PrivateKey().jwkRepresentation),
            (Curve448.KeyAgreement.PrivateKey().jwkRepresentation, Curve448.KeyAgreement.PrivateKey().jwkRepresentation),
            (secp256k1.KeyAgreement.PrivateKey(format: .uncompressed).jwkRepresentation, secp256k1.KeyAgreement.PrivateKey(format: .uncompressed).jwkRepresentation),
        ]
        let plaintextTestVectors: [Data] = [
            .init(),
            Data([UInt8](repeating: 0, count: 1024)),
            "Hello, World!".data(using: .utf8)!,
            Data.random(count: 1024),
        ]
        for (recipientStatic, senderStatic) in keys {
            for plaintext in plaintextTestVectors {
                for algorithm in JWEKeyManagementAlgorithm.allCases {
                    for encryption in JWEContentEncryptionAlgorithm.allCases {
                        for zip in [CompressionAlgorithm.deflate, nil] {
                            let receivedPlaintext = try roundTrip(
                                plaintext: plaintext,
                                recipientStatic: recipientStatic,
                                senderStatic: senderStatic,
                                algorithm: algorithm,
                                encryption: encryption,
                                zip: zip
                            )
                            XCTAssertEqual(plaintext, receivedPlaintext)
                        }
                    }
                }
            }
        }
    }

    private func roundTrip(
        plaintext: Data,
        recipientStatic: JWK,
        senderStatic: JWK,
        algorithm: JWEKeyManagementAlgorithm,
        encryption: JWEContentEncryptionAlgorithm,
        zip: CompressionAlgorithm?
    ) throws -> Data {
        var jwe = JWE(
            protectedHeader: .init(
                alg: algorithm,
                enc: encryption,
                zip: zip
            )
        )
        try jwe.encrypt(
            plaintext: plaintext,
            to: recipientStatic.publicKey,
            from: senderStatic
        )
        let compactSerialization = jwe.compactSerialization
        let receivedJWE = try JWE(compactSerialization: compactSerialization)
        let receivedPlaintext = try receivedJWE.decrypt(
            using: recipientStatic,
            from: senderStatic.publicKey
        )
        return receivedPlaintext
    }
}

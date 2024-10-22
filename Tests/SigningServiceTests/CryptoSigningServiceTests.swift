import Foundation
@testable import SigningService
import Testing

struct CryptoSigningServiceTests {
    let keyStore: MockKeyStore
    let sut: CryptoSigningService

    init() {
        keyStore = MockKeyStore()
        sut = CryptoSigningService(
            keyStore: keyStore
        )
    }

    @Test
    func testPublicKey() throws {
        let didKeyString = try #require(String(data: sut.publicKey, encoding: .utf8))
        #expect(didKeyString == "did:key:zDnaekBpNWyrZZwcaX1ET66oRWiYCcwbVQGKRY3xYaJa9fPxB")
    }

    @Test
    @available(iOS 17, *)
    func signAndVerifyData() throws {
        enum SigningError: Error {
            case invalidSignature
        }

        let dataToSign = try #require("mock_string".data(using: .utf8))
        let signedData = try sut.sign(data: dataToSign)

        var verifyError: Unmanaged<CFError>?
        guard try SecKeyVerifySignature(
            keyStore.publicKey,
            .ecdsaSignatureMessageRFC4754SHA256,
            dataToSign as CFData,
            signedData as CFData,
            &verifyError
        ) else {
            throw SigningError.invalidSignature
        }
    }
}

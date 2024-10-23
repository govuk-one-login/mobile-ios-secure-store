import Foundation
@testable import CryptoService
import Testing

struct CryptoSigningServiceTests {
    let keyStore: MockKeyStore
    let sut: CryptoSigningService

    init() throws {
        keyStore = MockKeyStore()
        sut = try CryptoSigningService(keyStore: keyStore)
    }
    
    @Test
    func testPublicKey() throws {
        let publicKeyString = try sut.publicKey().base64EncodedString()
        #expect(publicKeyString == "BCWJzI4K0QJ60ejmwbYQ7lGg3kKDx6134c0Zn4Q7WvtobY1uIVihxougBV8/Uv417M43z60dcBJP8ojfMEQ/t+E=")
    }

    @Test
    func testDIDKey() throws {
        let didKeyString = try #require(String(data: sut.publicKey(didKey: true), encoding: .utf8))
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

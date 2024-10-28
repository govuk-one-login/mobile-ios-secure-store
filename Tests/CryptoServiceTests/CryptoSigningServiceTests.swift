@testable import CryptoService
import Foundation
import Testing

struct CryptoSigningServiceTests {
    let keyStore: MockKeyStore
    let sut: CryptoSigningService

    init() {
        keyStore = MockKeyStore()
        sut = CryptoSigningService(keyStore: keyStore)
    }
    
    @Test
    func publicKey() throws {
        let publicKeyString = try sut.publicKey().base64EncodedString()
        #expect(publicKeyString == "BCWJzI4K0QJ60ejmwbYQ7lGg3kKDx6134c0Zn4Q7WvtobY1uIVihxougBV8/Uv417M43z60dcBJP8ojfMEQ/t+E=")
    }

    @Test
    func didKey() throws {
        let didKeyString = try #require(String(data: sut.publicKey(didKey: true), encoding: .utf8))
        #expect(didKeyString == "did:key:zDnaekBpNWyrZZwcaX1ET66oRWiYCcwbVQGKRY3xYaJa9fPxB")
    }

    @Test
    @available(iOS 17, *)
    func signData() throws {
        enum SigningError: Error {
            case invalidSignature
        }

        let dataToSign = Data("mock_String".utf8)
        let signedData = try sut.sign(data: dataToSign)

        guard SecKeyVerifySignature(
            keyStore.publicKey,
            .ecdsaSignatureMessageRFC4754SHA256,
            dataToSign as CFData,
            signedData as CFData,
            nil
        ) else {
            throw SigningError.invalidSignature
        }
    }
    
    @Test
    func signDataThrows() throws {
        keyStore.privateKey = keyStore.publicKey
        
        let dataToSign = Data("mock_String".utf8)
        #expect(performing: {
            try sut.sign(data: dataToSign)
        }, throws: { error in
            let error = error as NSError
            return error.domain == NSOSStatusErrorDomain
                && error.code == -50
        })
    }
}

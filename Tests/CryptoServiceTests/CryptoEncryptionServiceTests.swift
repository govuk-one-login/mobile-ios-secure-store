@testable import CryptoService
import Foundation
import Testing

struct CryptoEncryptionServiceTests {
    let keyStore: MockKeyStore
    let sut: CryptoEncryptionService
    
    init() throws {
        keyStore = MockKeyStore()
        sut = try CryptoEncryptionService(keyStore: keyStore)
    }
    
    @Test
    func encryptData() throws {
        let token = """
            eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        """
        let encryptedData = try sut.encryptDataWithPublicKey(dataToEncrypt: token)
        let decryptedData = try sut.decryptDataWithPrivateKey(dataToDecrypt: encryptedData)
        #expect(token == decryptedData)
    }
}

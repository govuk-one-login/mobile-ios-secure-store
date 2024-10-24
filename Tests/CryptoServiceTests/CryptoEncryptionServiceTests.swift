@testable import CryptoService
import Foundation
import Testing

struct CryptoEncryptionServiceTests {
    let keyStore: MockKeyStore
    let sut: CryptoEncryptionService
    
    init() throws {
        keyStore = try MockKeyStore()
        sut = CryptoEncryptionService(keyStore: keyStore)
    }
    
    @Test
    func encryptAndDecryptData() throws {
        let token = """
            eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        """
        let encryptedData = try sut.encryptData(dataToEncrypt: token)
        let decryptedData = try sut.decryptData(dataToDecrypt: encryptedData)
        #expect(token == decryptedData)
    }
}

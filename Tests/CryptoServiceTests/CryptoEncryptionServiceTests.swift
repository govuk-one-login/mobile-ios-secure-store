@testable import CryptoService
import Foundation
import Testing

struct CryptoEncryptionServiceTests {
    let keyStore: MockKeyStore
    let sut: CryptoEncryptionService
    
    init() {
        keyStore = MockKeyStore()
        sut = CryptoEncryptionService(keyStore: keyStore)
    }

    @Test
    func encryptData() throws {
        let token = "data_to_be_encrypted"
        let encryptedString = try #require(
            try sut.encryptData(dataToEncrypt: token)
        )
        let encryptedData = try #require(
            Data(base64Encoded: encryptedString)
        )
        
        let decryptedData = try #require(
            SecKeyCreateDecryptedData(
                keyStore.privateKey,
                .eciesEncryptionStandardX963SHA256AESGCM,
                encryptedData as CFData,
                nil
            )
        )
        
        let decryptedString = String(
            data: decryptedData as Data,
            encoding: .utf8
        )

        #expect(token == decryptedString)
    }
    
    @Test
    func encryptData_throwsError_whenWrongKeyUsed() throws {
        keyStore.publicKey = keyStore.privateKey
        
        let token = "data_to_be_encrypted"
        
        #expect(performing: {
            try sut.encryptData(dataToEncrypt: token)
        }, throws: { error in
            let error = error as NSError
            return error.domain == NSOSStatusErrorDomain
                && error.code == -50
        })
    }

    @Test
    func decryptData() throws {
        let encryptedData = """
        BCZUnwZ6mMwchNbdics4UQve97VjLPaDCk3GHpR+mgPSmNxsR2k1hQXvHd4moMxBc8SM4qfal6J6iO+xa4ku0cjB7nzMRw+K64DLlolIDL3TqzND9SHsOle1byXtXJUrOsd6Rv0=
        """
        let decryptedData = try sut.decryptData(dataToDecrypt: encryptedData)
        #expect(decryptedData == "data_to_be_encrypted")
    }
    
    @Test
    func decryptData_throwsError_whenWrongKeyUsed() throws {
        let token = "data_to_be_encrypted"
        let encryptedString = try #require(
            try sut.encryptData(dataToEncrypt: token)
        )
        
        keyStore.privateKey = keyStore.publicKey
        
        #expect(performing: {
            try sut.decryptData(dataToDecrypt: encryptedString)
        }, throws: { error in
            let error = error as NSError
            return error.domain == NSOSStatusErrorDomain
                && error.code == -50
        })
    }
}

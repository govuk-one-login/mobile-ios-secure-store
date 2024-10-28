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
    
//    @Test
//    func publicKey_JWK() {
//        #expect(throws: SigningServiceError.notYetImplemented) {
//            try sut.publicKey(format: .jwk)
//        }
//    }
    
    @Test("export public key JWK format")
    func publicKey_JWK() throws {
        let keyString = Data("0373b3fe72bcea2cecaf2768cb85fa0bd7eb2bb91ca8918448a2ef9d323b24a188".utf8).base64EncodedString()
        let keyData = Data(base64Encoded: keyString)!
        let jwks = try sut.generateJWK(keyData)
        let jwksString = String(data: jwks, encoding: .utf8)
        #expect(jwksString == """
            { 
              "jwk" : {
                "crv" : "P-256",
                "kty" : EC",
                "use" : "sig",
                "x" : "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
                "y" : "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
              }
            }
        """)
        
//        #expect(throws: SigningServiceError.notYetImplemented) {
//            try sut.publicKey(format: .jwk)
//        }
    }

    @Test
    func publicKey_DID() throws {
        let didKeyString = try #require(String(data: sut.publicKey(format: .decentralisedIdentifier), encoding: .utf8))
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
    func signDataThrows() {
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

import CryptoKit
@testable import CryptoService
import Foundation
import Testing

struct CryptoSigningServiceTests {
    let keyStore: MockKeyStore
    let encoder: JSONEncoder
    let sut: CryptoSigningService

    init() {
        keyStore = MockKeyStore()
        encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        sut = CryptoSigningService(keyStore: keyStore, encoder: encoder)
    }
    
    

    @Test("Export public key in JWKs format")
    @available(iOS 16, macOS 13, *)
    func publicKey_JWKs() throws {
        
        let key = try P256.Signing.PublicKey(pemRepresentation: """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE18wHLeIgW9wVN6VD1Txgpqy2LszY
        kMf6J8njVAibvhP5Xh1LhRosyA//h9jiPyKvtyXVNeUV0CBzHnmjtORxIA==
        -----END PUBLIC KEY-----
        """)

        let keyData = key.x963Representation
        keyStore.publicKey = SecKeyCreateWithData(
            keyData as NSData,
            [
                kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeyClass: kSecAttrKeyClassPublic
            ] as NSDictionary,
            nil
        )!

        let jwk = try String(data: sut.publicKey(format: .jwk), encoding: .utf8)!

        #expect(
            jwk ==
            """
            {
              "jwk" : {
                "crv" : "P-256",
                "kty" : "EC",
                "use" : "sig",
                "x" : "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
                "y" : "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
              }
            }
            """
        )
    }
    
//    @Test("export public key JWK format")
//    func publicKey_JWK() throws {
//        let keyData = Data(base64Encoded: "BDbZJ4xs5t9aF8a/xoR8XaFr74xhiqxLICQFLx9e1LykVtO1ebOWi+nPAQR9j0rkBIjdrywOFLR+qtnhTWcxgHw=")!
//        let jwks = try sut.generateJWK(keyData)
//        let jwksString = String(data: jwks, encoding: .utf8)
//        #expect(jwksString == """
//            { 
//              "jwk" : {
//                "crv" : "P-256",
//                "kty" : EC",
//                "use" : "sig",
//                "x" : "DbZJ4xs5t9aF8a/xoR8XaFr74xhiqxLICQFLx9e1Lyk",
//                "y" : "Ou1LmrOYh2+NTgRNa7ENRB0R9698W1k/pdMgiIqYPHU"
//              }
//            }
//        """)
//        
//        #expect(throws: SigningServiceError.notYetImplemented) {
//            try sut.publicKey(format: .jwk)
//        }
//    }

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

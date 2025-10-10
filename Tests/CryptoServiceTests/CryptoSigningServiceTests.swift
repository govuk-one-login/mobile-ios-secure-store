import CryptoKit
@testable import CryptoService
import Foundation
import Testing

struct CryptoSigningServiceTests {
    let keyStore: MockKeyStore
    let encoder: JSONEncoder

    init() {
        keyStore = MockKeyStore()
        encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    }
    
    @Test
    @available(iOS 14, macOS 13, *)
    func publicKeyJWKs() throws {
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: SecKeyCreateSignature
        )
        
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
    
    @Test
    func publicKeyRepresentationThrows() throws {
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: { key, error in nil },
            createSignatureMethod: SecKeyCreateSignature
        )
        
        #expect(throws: SigningServiceError.couldNotCreatePublicKeyAsData) {
            try sut.publicKeyRepresentation
        }
    }
    
    @Test
    func publicKeyRepresentationThrowsUnknownError() throws {
        let pointedError = try #require(
            CFErrorCreate(nil, "domain" as CFString, -1, nil)
        )
        let value = Unmanaged.passRetained(pointedError)
        
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: { key, error in
                error?.pointee = value
                return nil
            },
            createSignatureMethod: SecKeyCreateSignature
        )
        
        #expect(throws: pointedError) {
            try sut.publicKeyRepresentation
        }
    }
    
    @Test
    @available(iOS 14, macOS 13, *)
    func jwkDictionary() throws {
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: SecKeyCreateSignature
        )
        
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
        
        #expect(
            try sut.jwkDictionary ==
            JWK(
                x: "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
                y: "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
            ).dictionary
        )
    }
    
    @Test
    @available(iOS 14, macOS 13, *)
    func generateJWKThrows() throws {
        var mockJSONEncoder = MockJSONEncoder()
        mockJSONEncoder.errorFromEncode = NSError(domain: "test domain", code: 0)
        
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: mockJSONEncoder,
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: SecKeyCreateSignature
        )
        
        let key = try P256.Signing.PublicKey(pemRepresentation: """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE18wHLeIgW9wVN6VD1Txgpqy2LszY
        kMf6J8njVAibvhP5Xh1LhRosyA//h9jiPyKvtyXVNeUV0CBzHnmjtORxIA==
        -----END PUBLIC KEY-----
        """)
        
        #expect(throws: SigningServiceError.couldNotCreateJWKAsData) {
            try sut.generateJWK(key)
        }
    }
    
    @Test
    func publicKey_DID() throws {
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: SecKeyCreateSignature
        )
        
        let didKeyString = try #require(String(data: sut.publicKey(format: .decentralisedIdentifier), encoding: .utf8))
        #expect(didKeyString == "did:key:zDnaekBpNWyrZZwcaX1ET66oRWiYCcwbVQGKRY3xYaJa9fPxB")
    }

    @Test
    @available(iOS 17, *)
    func signData() throws {
        enum SigningError: Error {
            case invalidSignature
        }
        
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: SecKeyCreateSignature
        )

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
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: { key, algorithm, dataToSign, error in nil }
        )
        
        let dataToSign = Data("mock_String".utf8)
        
        #expect(throws: SigningServiceError.unknownCreateSignatureError) {
            try sut.sign(data: dataToSign)
        }
    }
    
    @Test
    func signDataThrowsUnknownError() throws {
        let pointedError = try #require(
            CFErrorCreate(nil, "domain" as CFString, -1, nil)
        )
        let value = Unmanaged.passRetained(pointedError)
        
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: { key, algorithm, dataToSign, error in
                error?.pointee = value
                return nil
            }
        )
        
        let dataToSign = Data("mock_String".utf8)
        
        #expect(throws: pointedError) {
            try sut.sign(data: dataToSign)
        }
    }
    
    @Test
    func deleteKeysSucceeds() {
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: SecKeyCreateSignature
        )
        
        var expectedError: Error?
        do {
            try sut.deleteKeys()
        } catch {
            expectedError = error
        }
        #expect(expectedError == nil)
    }
    
    @Test
    func deleteKeysThrows() {
        let sut = CryptoSigningService(
            keyStore: keyStore,
            encoder: encoder,
            keyCopyMethod: SecKeyCopyExternalRepresentation,
            createSignatureMethod: SecKeyCreateSignature
        )
        
        keyStore.errorToThrow = SigningServiceError.failedToDeleteKeys
        
        #expect(throws: SigningServiceError.failedToDeleteKeys) {
            try sut.deleteKeys()
        }
    }
    
    @Test
    func deleteKeysWithOpen() throws {
        // GIVEN
        let id = UUID().uuidString
        let sut: SigningService.Type = MockSigningService.self
        var errorThrown: Error?
        
        // WHEN deleting the item by id
        do {
            try sut.deleteKeys(for: id)
        } catch {
            errorThrown = error
        }
        
        // THEN no exception should be thrown
        #expect(errorThrown == nil)
    }
    
}

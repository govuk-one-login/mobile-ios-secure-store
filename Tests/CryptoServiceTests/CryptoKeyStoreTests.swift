@testable import CryptoService
import Foundation
import LocalAuthentication
import Testing

struct CryptoKeyStoreTests {
    let localAuthStrings: LocalAuthenticationLocalizedStrings
    let configuration: CryptoServiceConfiguration
    
    let privateKeyRef: SecKey
    let publicKeyRef: SecKey
    
    init() {
        localAuthStrings = LocalAuthenticationLocalizedStrings(
            localizedReason: "test_reason",
            localisedFallbackTitle: "test_fallback",
            localisedCancelTitle: "test_cancel"
        )
        configuration = CryptoServiceConfiguration(
            id: "test_config",
            accessControlLevel: .open,
            localAuthStrings: localAuthStrings
        )
        
        let mockKeyStore = MockKeyStore()
        privateKeyRef = mockKeyStore.privateKey
        publicKeyRef = mockKeyStore.publicKey
    }
    
    @Test
    func setUp() throws {
        let (privateKey, publicKey) = try CryptoKeyStore.setup(
            configuration: configuration
        ) { _, result in
            result?.pointee = privateKeyRef
            return errSecSuccess
        } copyPublicKey: { _ in
            publicKeyRef
        }
        
        #expect(privateKey == privateKeyRef)
        #expect(publicKey == publicKeyRef)
    }
    
    @Test
    func setUpThrows() throws {
        #expect(throws: KeyPairAdministratorError.cantCreatePublicKey) {
            try CryptoKeyStore.setup(
                configuration: configuration
            ) { _, result in
                result?.pointee = privateKeyRef
                return errSecSuccess
            } copyPublicKey: { _ in
                nil
            }
        }
    }
    
    @Test
    func getPrivateKey() throws {
        var cfDictionary: CFDictionary?
        
        let privateKey = try CryptoKeyStore.getPrivateKey(
            configuration: configuration
        ) { query, result in
            cfDictionary = query
            result?.pointee = privateKeyRef
            return errSecSuccess
        }
        
        let dictionary = (cfDictionary as? [String: Any])
        #expect(dictionary?[kSecClass as String] as? String == "keys")
        let applicationTagData = try #require(dictionary?[kSecAttrApplicationTag as String] as? Data)
        #expect(String(data: applicationTagData, encoding: .utf8) == "test_configPrivateKey")
        let laContext = try #require(dictionary?[kSecUseAuthenticationContext as String] as? LAContext)
        #expect(laContext.localizedReason == "test_reason")
        #expect(laContext.localizedCancelTitle == "test_cancel")
        #expect(laContext.localizedFallbackTitle == "test_fallback")
        #expect(dictionary?[kSecAttrKeyType as String] as? String == "73")
        #expect(dictionary?[kSecReturnRef as String] as? Bool == true)
        #expect(privateKey == privateKeyRef)
    }
    
    @Test
    func createPrivateKey() throws {
        var cfDictionary: CFDictionary?
        
        let privateKey = try CryptoKeyStore.createPrivateKey(
            configuration: configuration
        ) { parameters, _ in
            cfDictionary = parameters
            return privateKeyRef
        }
        
        let dictionary = (cfDictionary as? [String: Any])
        #expect(dictionary?[kSecAttrKeyType as String] as? String == "73")
        #expect(dictionary?[kSecAttrKeySizeInBits as String] as? Int == 256)
        #expect(dictionary?[kSecAttrTokenID as String] as? String == "com.apple.setoken")
        let privateKeyAttributes = dictionary?[kSecPrivateKeyAttrs as String] as? [String: Any]
        #expect(privateKeyAttributes?[kSecAttrIsPermanent as String] as? Bool == true)
        let privateKeyTagData = try #require(privateKeyAttributes?[kSecAttrApplicationTag as String] as? Data)
        #expect(String(data: privateKeyTagData, encoding: .utf8) == "test_configPrivateKey")
        #expect(privateKey == privateKeyRef)
    }
    
    @Test
    func createPrivateKeyThrows() {
        #expect(throws: KeyPairAdministratorError.cantCreatePrivateKey) {
            try CryptoKeyStore.createPrivateKey(
                configuration: configuration
            ) { _, _ in
                nil
            }
        }
    }
    
    @Test
    func deleteKeys() throws {
        var cfDictionary: CFDictionary?
        
        let sut = try CryptoKeyStore(configuration: configuration) { _, result in
            result?.pointee = privateKeyRef
            return errSecSuccess
        } copyPublicKey: { _ in
            publicKeyRef
        } deleteMethod: { query in
            cfDictionary = query
            return errSecSuccess
        }
        
        #expect(throws: Never.self) {
            try sut.deleteKeys()
        }
        let dictionary = (cfDictionary as? [String: Any])
        #expect(dictionary?[kSecClass as String] as? String == "keys")
        let queryData = try #require(dictionary?[kSecAttrApplicationTag as String] as? Data)
        #expect(String(data: queryData, encoding: .utf8) == "test_configPrivateKey")
    }
    
    @Test
    func deleteKeysThrows() throws {
        let sut = try CryptoKeyStore(configuration: configuration) { _, result in
            result?.pointee = privateKeyRef
            return errSecSuccess
        } copyPublicKey: { _ in
            publicKeyRef
        } deleteMethod: { _ in
            return errSecDeviceError
        }
        
        #expect(throws: KeyPairAdministratorError.cantDeleteKeys) {
            try sut.deleteKeys()
        }
    }
}

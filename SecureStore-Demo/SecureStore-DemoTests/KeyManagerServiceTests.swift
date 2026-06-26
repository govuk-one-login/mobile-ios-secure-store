import Foundation
@testable import SecureStore
import Testing

@Suite
struct KeyManagerServiceTests: ~Copyable {
    private let testRunID = UUID()
    private let sut: KeyManagerService

    private var keyTag: Data {
        Data("\(testRunID)PrivateKey".utf8)
    }

    init() {
        sut = KeyManagerService(configuration: .init(
            id: testRunID.uuidString,
            accessControlLevel: .open
        ))
    }

    deinit {
        try? sut.deleteKeys()
    }

    @Test("When initialised, KeyManagerService creates private key and stores this in keychain")
    func createsKeyOnInitialisation() async throws {

        let query = NSDictionary(dictionary: [
            kSecClass: kSecClassKey,
            kSecAttrApplicationTag: keyTag,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef: true
        ])

        var privateKeyRef: CFTypeRef?
        let privateStatus = SecItemCopyMatching(query as CFDictionary, &privateKeyRef)

        #expect(privateStatus == errSecSuccess)
    }

    @Test("When retrieving keys, KeyManagerService generates this from the stored private key")
    func generatesPublicKeyOnDemand() async throws {
        // Override stored key
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrApplicationTag: keyTag
            ]
        ]
        let privateKey = try #require(SecKeyCreateRandomKey(addQuery, nil))

        // Ensure that the public key matches the new stored key
        let keys = try sut.retrieveKeys()
        #expect(keys.privateKey == privateKey)

        let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
        #expect(keys.publicKey == publicKey)
    }
    
    @Test("""
            GIVEN stored key is not available (e.g. deleted)
            WHEN retrieveKeys 
            THEN throws SecureStoreError with an original OSStatus error (e.g. OSStatus == errSecItemNotFound)
    """)
    func retrieveKeysSecureStoreErrorWithOriginalOSStatusError() async throws {
        // Delete stored key
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let error = #expect(throws: SecureStoreError.self) {
            try sut.retrieveKeys()
        }
        
        #expect(error?.kind == .cantRetrieveKey)
        
        let originalError = try #require(error?.originalError as? OSStatusError)
        
        #expect(originalError.status == errSecItemNotFound)
    }
    
    @Test("""
            GIVEN `originalError` IS a SecureStoreError (e.g. SecureStoreError(.cantStoreKey))
            AND **its** `originalError` IS an `OSStatus` error (e.g. errSecInteractionNotAllowed)
            AND stored key is not available (e.g. not present), 
            WHEN retrieveKeys is called with the `originalError`
            THEN throws SecureStoreError with an original `OSStatus` error (e.g. OSStatus == errSecItemNotFound)
            AND the `underlyingError` is the expected `originalError`
            AND **its** `originalError` is the expected `OSStatusError` 
    """)
    func retrieveKeysSecureStoreErrorWithOriginalOSStatusError2() async throws {
        // Delete stored key
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let originalErrorStatus: OSStatus = errSecItemNotFound
        let initError = SecureStoreError(.cantStoreKey, originalError: OSStatusError.make(status: originalErrorStatus))
        
        let error = #expect(throws: SecureStoreError.self) {
            try sut.retrieveKeys(initError: initError)
        }
        
        #expect(error?.kind == .cantRetrieveKey)
        
        let originalError = try #require(error?.originalError as? OSStatusError)
        #expect(originalError.status == errSecItemNotFound)
        
        let underlyingError = try #require(originalError.errorUserInfo[NSUnderlyingErrorKey] as? SecureStoreError)
        #expect(underlyingError.kind == initError.kind)

        let actual = try #require(underlyingError.originalError as? OSStatusError)
        #expect(actual.status == originalErrorStatus)
    }

}

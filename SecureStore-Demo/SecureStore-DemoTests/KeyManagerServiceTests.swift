import Foundation
import LocalAuthentication
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
    
    ///    This is a test that demonstrates that a new instance of the `KeyManagerService`,
    ///    creates a new set of keys:
    ///
    ///    1. One under `id` tag
    ///    2. Another under the `idPrivateKey` tag
    ///
    ///    For a set of keys K where each key has an identifier, every time a new instance of the
    ///    `KeyManagerService` is created assume the following set:
    ///
    ///        K = { K(id), K(idPrivateKey) }
    ///
    ///     Given that both keys reference the **same key** that is tied to the Secure Enclave
    ///     (i.e. `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave`) we end up with
    ///
    ///     K = { K1(id), K1(idPrivateKey) }
    ///
    ///     Alternatively,
    ///
    ///        tag             | keys
    ///        id              | K1
    ///        idPrivateKey    | K1
    ///
    ///     The `deleteKeys()` function only deletes the `idPrivateKey`, leaving the `id` one behind.
    ///     e.g.
    ///
    ///        tag             | keys
    ///        id              | K1
    ///        idPrivateKey    |
    ///
    ///     Given that for a given `tag`, multiple keys can be stored,
    ///     the next time a **second** second of `KeyManagerService` is created we end up with:
    ///
    ///        tag             | keys
    ///        id              | K1, K2
    ///        idPrivateKey    | K2
    ///
    ///    The **third** time:
    ///
    ///        tag             | keys
    ///        id              | K1, K2, K3
    ///        idPrivateKey    | K3
    ///
    ///    And so on and so forth. Effectively, over time the number of keys under the `id` tag  accumulate
    ///    by the number of `KeyManagerService` instances created.
    @Test("""
            GIVEN a new `KeyManagerService` over time
            AND a call to `KeyManagerService.deleteKeys()`
            WHEN querying for the number of keys under the `id` tag
            THEN the number of keys found is equal to the number of `KeyManagerService` created in that time. 
    """)
    func deleteKeysAccumulatesKeysOverTime() async throws {
        
        let count = 10

        let configuration = SecureStorageConfiguration(
            id: testRunID.uuidString,
            accessControlLevel: .open
        )
        let id = Data(configuration.id.utf8)

        for _ in 1...count {
            let sut = KeyManagerService(configuration: configuration)
            try sut.deleteKeys()
        }

        defer {
            try? sut.deleteKeys()
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: id,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        let keys = try #require(result as? [SecKey])

        #expect(status == errSecSuccess)
        #expect(keys.count == count)
    }

    /// This is a case where a as part of instantiating a `KeyManagerService`, a new set of keys is created
    /// that is tied to the Secure Enclave (i.e. `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave`).
    ///
    /// The keys are explicitly deleted by calling `deleteKeys()` in the  `KeyManagerService`
    ///
    /// When attempting to **decrypt** the data, an `errSecParam` (aka -50) will be thrown
    @Test("""
            GIVEN a new `KeyManagerService` with a set of keys
            AND a data is encrypted
            AND the keys are explicitly deleted
            AND a new `KeyManagerService` is created with the same (i.e. same `id`) configuration
            WHEN attempting to decrypt the data
            THEN throws `SecureStoreError.cantDecryptData`
            AND the `originalError` is `errSecParam` (i.e. -50 OSStatus)
    """)
    func decryptKeyWithWrongPrivateKey() async throws {

        let anyString = "any"
        let encrypted = try sut.encryptDataWithPublicKey(dataToEncrypt: anyString)
                
        try sut.deleteKeys()

        let sut = KeyManagerService(configuration: .init(
            id: testRunID.uuidString,
            accessControlLevel: .open
        ))

        let error = #expect(throws: SecureStoreError.self) {
            try sut.decryptDataWithPrivateKey(dataToDecrypt: encrypted)
        }
        
        #expect(error?.kind == .cantDecryptData)
        
        let originalError = try #require(error?.originalError as? NSError)
        #expect(originalError.code == errSecParam)
        #expect(originalError.code == -50)
    }
    
    /// This is a case where a as part of instantiating a `KeyManagerService`, a new set of keys is created
    /// that is tied to the Secure Enclave (i.e. `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave`).
    ///
    /// A SE key pair provides strong guarantees so that:
    /// * It is never exported to a backup
    /// * The key pair is deleted as soon as the device is erased
    ///
    /// In this case:
    /// 1. a backup from an existing device, with previously encrypted data, was taken
    /// 2. a restore on the device is performed
    /// 3. the data is restored
    /// 4. the key is not restored
    ///
    /// When attempting to **decrypt** the data, an `errSecParam` (aka -50) will be thrown
    @Test("""
            GIVEN a new `KeyManagerService` with a set of keys
            AND a data is encrypted
            AND the key is deleted due (e.g. due to a device erase)
            AND a new `KeyManagerService` is created with the same (i.e. same `id`) configuration as part of a new app installation
            WHEN attempting to decrypt the existing, previously backed-up, data
            THEN throws `SecureStoreError.cantDecryptData`
            AND the `originalError` is `errSecParam` (i.e. -50 OSStatus)
    """)
    func decryptKeyWithWrongPrivateKeyDueToOriginalKeyGoneMising() async throws {

        let anyString = "any"
        let encrypted = try sut.encryptDataWithPublicKey(dataToEncrypt: anyString)
        
        // Device Erased
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        // New app installation
        let sut = KeyManagerService(configuration: .init(
            id: testRunID.uuidString,
            accessControlLevel: .open
        ))

        let error = #expect(throws: SecureStoreError.self) {
            try sut.decryptDataWithPrivateKey(dataToDecrypt: encrypted)
        }
        
        #expect(error?.kind == .cantDecryptData)
        
        let originalError = try #require(error?.originalError as? NSError)
        #expect(originalError.code == errSecParam)
        #expect(originalError.code == -50)
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
    func retrieveKeysSecureStoreErrorWithOriginalOSStatusErrorAndUnderlyingError() async throws {
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

    @Test("""
            GIVEN KeyManagerService did create keys
            WHEN storePrivateKey with the same tag
            THEN throws SecureStoreError(.cantStoreKey) with an original OSStatus error (e.g. OSStatus == errSecDuplicateItem)
    """)
    func attemptStorePrivateKeyThrowsCantStoreKeyWitherrSecDuplicateItem() async throws {
        let tag = "\(testRunID)"
        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag
            ]
        ]

        let anyKey = try #require(SecKeyCreateRandomKey(attributes, nil))

        let error = #expect(throws: SecureStoreError.self) {
            try sut.storePrivateKey(keyToStore: anyKey, name: tag)
        }

        #expect(error?.kind == .cantStoreKey)

        let originalError = try #require(error?.originalError as? OSStatusError)

        #expect(originalError.status == errSecDuplicateItem)
    }
}
